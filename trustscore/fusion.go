package trustscore

import (
	"fmt"
	"math"
	"sort"
	"sync"
)

type ModuleWeights struct {
	Recon        float64
	Bruteforce   float64
	Ddos         float64
	Session      float64
	Scraping     float64
	Evasion      float64
	VulnProbe    float64
	AccountAbuse float64
	Rasp         float64
}

var (
	moduleWeightsMu sync.RWMutex
	liveWeights     = ModuleWeights{
		Recon:        0.20,
		Bruteforce:   0.18,
		Ddos:         0.15,
		Session:      0.12,
		Scraping:     0.10,
		Evasion:      0.10,
		VulnProbe:    0.10,
		AccountAbuse: 0.05,
		// Rasp is additive (not part of the unit-sum of the eight behavioural
		// modules): it is 0 for normal traffic, so the calibrated weights above
		// are unchanged, and dominant when a runtime effect is confirmed. HIGH/
		// CRITICAL effects additionally trigger a hard override (see below), so
		// the weight only governs MEDIUM/LOW influence.
		Rasp: 0.40,
	}
)

func GetModuleWeights() ModuleWeights {
	moduleWeightsMu.RLock()
	defer moduleWeightsMu.RUnlock()
	return liveWeights
}

func SetModuleWeights(w ModuleWeights) {
	moduleWeightsMu.Lock()
	defer moduleWeightsMu.Unlock()
	liveWeights = w
}

func ComputeTrustScore(profile *IPProfile, event *RequestEvent) *TrustScoreResult {
	cfg := GetConfig()

	// ── Phase 1: RLock — score, capture signals ────────────────────────────
	profile.mu.RLock()

	subScoresMap := make(map[string]float64)
	reasonsMap := make(map[string][]string)

	reconPenalty, reconReasons, reconSignals := ScoreRecon(profile, event.Path, event.Timestamp, cfg)
	subScoresMap["recon"] = reconPenalty
	reasonsMap["recon"] = reconReasons

	bfPenalty, bfReasons := ScoreBruteForce(profile, event, cfg)
	subScoresMap["bruteforce"] = bfPenalty
	reasonsMap["bruteforce"] = bfReasons

	ddosPenalty, ddosReasons := ScoreDDoS(profile, event, cfg)
	subScoresMap["ddos"] = ddosPenalty
	reasonsMap["ddos"] = ddosReasons

	sessionPenalty, sessionReasons, sessionSignals := ScoreSession(profile, event, cfg)
	subScoresMap["session"] = sessionPenalty
	reasonsMap["session"] = sessionReasons

	scrapePenalty, scrapeReasons, scrapeSignals := ScoreScraping(profile, event, cfg)
	subScoresMap["scraping"] = scrapePenalty
	reasonsMap["scraping"] = scrapeReasons

	evasionPenalty, evasionReasons := ScoreEvasion(profile, event, cfg)
	subScoresMap["evasion"] = evasionPenalty
	reasonsMap["evasion"] = evasionReasons

	vulnPenalty, vulnReasons, vulnSignals := ScoreVulnProbe(profile, event, cfg)
	subScoresMap["vuln_probe"] = vulnPenalty
	reasonsMap["vuln_probe"] = vulnReasons

	abusePenalty, abuseReasons := ScoreAccountAbuse(profile, event, cfg)
	subScoresMap["account_abuse"] = abusePenalty
	reasonsMap["account_abuse"] = abuseReasons

	raspPenalty, raspReasons, raspSignals := ScoreRASP(profile, event, cfg)
	subScoresMap["rasp"] = raspPenalty
	reasonsMap["rasp"] = raspReasons

	boost, boostReasons, boostSignals := ComputeTrustBoost(profile, event, cfg)

	challengeSolvedRecently := profile.ChallengeSolvedRecently
	tier1Adj := profile.EWMAScore // [0,1], 0.5 = neutral; written by Tier 1 feedback

	signals := DetectionSignals{
		Recon:    reconSignals,
		Session:  sessionSignals,
		Scraping: scrapeSignals,
		VulnProbe: vulnSignals,
		Boost:    boostSignals,
		RASP:     raspSignals,
	}

	profile.mu.RUnlock()
	// ── End Phase 1 ──────────────────────────────────────────────────────

	// ── Phase 2: Pure math — no profile access ───────────────────────────
	override := checkHardOverrides(profile, subScoresMap)

	var score float64
	if override != nil {
		score = *override
	} else {
		weights := GetModuleWeights()
		risk := 0.0
		risk += weights.Recon * subScoresMap["recon"]
		risk += weights.Bruteforce * subScoresMap["bruteforce"]
		risk += weights.Ddos * subScoresMap["ddos"]
		risk += weights.Session * subScoresMap["session"]
		risk += weights.Scraping * subScoresMap["scraping"]
		risk += weights.Evasion * subScoresMap["evasion"]
		risk += weights.VulnProbe * subScoresMap["vuln_probe"]
		risk += weights.AccountAbuse * subScoresMap["account_abuse"]
		risk += weights.Rasp * subScoresMap["rasp"] // additive ground-truth term

		risk = math.Max(0.0, risk-(boost*0.3))
		score = 10.0 * (1.0 - risk)
	}

	score = math.Max(0.0, math.Min(10.0, score))

	// Challenge-solved boost
	if challengeSolvedRecently {
		score = math.Min(10.0, score+0.15)
		boostReasons = append(boostReasons, "challenge_solved")
	}

	// Tier 1 (RoBERTa) feedback correction. EWMAScore is neutral-centred on 0.5;
	// map it to a bounded signed delta (±Tier1ScoreGain) so a confident deep-tier
	// verdict can nudge the score across a decision threshold without letting a
	// single mispredict dominate. Hard overrides stay authoritative, so the delta
	// is skipped when one fired.
	if override == nil {
		tier1Delta := (tier1Adj - 0.5) * 2.0 * cfg.Tier1ScoreGain
		if math.Abs(tier1Delta) >= 0.01 {
			score = math.Max(0.0, math.Min(10.0, score+tier1Delta))
			reasonsMap["tier1"] = append(reasonsMap["tier1"],
				fmt.Sprintf("tier1_correction:%+.2f", tier1Delta))
		}
	}

	score = math.Round(score*100) / 100

	decision := makeDecision(score)

	// Policy layer: even if the numeric score says "allow", certain high-risk
	// signal combinations must be escalated regardless of history. This is a
	// first-touch guardrail — we don't need history to know that a VPN+datacenter
	// IP probing a sensitive path is suspicious.
	decision = applyPolicyOverrides(profile, subScoresMap, score, decision)

	wasBlocked := decision == "block" || decision == "ban"
	wasChallenged := decision == "challenge"

	outcome := RequestOutcome{
		FinalScore:    score,
		Decision:      decision,
		WasBlocked:    wasBlocked,
		WasChallenged: wasChallenged,
	}
	// ── End Phase 2 ──────────────────────────────────────────────────────

	// ── Phase 3: Lock — Update profile ───────────────────────────────────
	profile.Update(event, signals, outcome)

	var allReasons []ReasonItem
	for module, reasons := range reasonsMap {
		for _, reason := range reasons {
			allReasons = append(allReasons, ReasonItem{
				Module:   module,
				Reason:   reason,
				SubScore: math.Round(subScoresMap[module]*1000) / 1000,
			})
		}
	}

	sort.Slice(allReasons, func(i, j int) bool {
		return allReasons[i].SubScore > allReasons[j].SubScore
	})

	profileAge := event.Timestamp - profile.FirstSeen
	if profileAge < 0 {
		profileAge = 0
	}

	return &TrustScoreResult{
		IP:            event.IP,
		Score:         score,
		Decision:      decision,
		SubScores: SubScores{
			Recon:        math.Round(subScoresMap["recon"]*1000) / 1000,
			BruteForce:   math.Round(subScoresMap["bruteforce"]*1000) / 1000,
			DDoS:         math.Round(subScoresMap["ddos"]*1000) / 1000,
			Session:      math.Round(subScoresMap["session"]*1000) / 1000,
			Scraping:     math.Round(subScoresMap["scraping"]*1000) / 1000,
			Evasion:      math.Round(subScoresMap["evasion"]*1000) / 1000,
			VulnProbe:    math.Round(subScoresMap["vuln_probe"]*1000) / 1000,
			AccountAbuse: math.Round(subScoresMap["account_abuse"]*1000) / 1000,
		},
		Boost:         math.Round(boost*1000) / 1000,
		Reasons:       allReasons,
		BoostReasons:  boostReasons,
		ProfileAgeSec: math.Round(profileAge*10) / 10,
		Timestamp:     event.Timestamp,
	}
}

func checkHardOverrides(profile *IPProfile, subScores map[string]float64) *float64 {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	// RASP ground truth bypasses the weighted average. A confirmed CRITICAL
	// runtime effect is evidence, not a probability → collapse to 0.0 ("ban").
	// A HIGH effect alone forces a "block".
	if profile.ConfirmedExploit {
		override := 0.0 // makeDecision(0.0) → "ban"
		return &override
	}
	if raspMaxSeverity(profile) == sevHigh {
		override := 2.0 // makeDecision(2.0) → "block" (block range is 1.0–2.9)
		return &override
	}

	// NOTE on band values (see makeDecision): >=3 challenge, >=1 block, <1 ban.
	// Overrides must use a value INSIDE the band they intend — e.g. 0.5 is a BAN,
	// not a block. The graded thresholds below let an entity settle in the
	// challenge / block / ban bands rather than jumping straight from allow to ban.

	// Anonymised origin (Tor) plus any suspicion → challenge (prove you're human).
	if profile.IsTor {
		for _, v := range subScores {
			if v > 0.5 {
				override := 4.0 // → "challenge"
				return &override
			}
		}
	}

	// Brute force, graded by cumulative failed logins.
	if profile.LoginAttempts >= 40 {
		override := 0.0 // relentless credential stuffing → "ban"
		return &override
	}
	if profile.LoginAttempts >= 8 {
		override := 2.0 // sustained failed logins → "block"
		return &override
	}

	// Reconnaissance: probing sensitive endpoints, graded by breadth. This is a
	// persistent counter (not a time window), so the band is stable regardless of
	// how fast or slow the probes arrive — the reliable way to land in CHALLENGE.
	if len(profile.SensitivePathHits) >= 8 {
		override := 0.0 // aggressive sweep → "ban"
		return &override
	}
	if len(profile.SensitivePathHits) >= 3 {
		override := 2.0 // recon → "block"
		return &override
	}
	if len(profile.SensitivePathHits) >= 1 {
		override := 4.0 // a sensitive-path touch → "challenge" (prove you're human)
		return &override
	}

	if len(profile.SeenCountryCodes) > 2 {
		override := 2.0 // impossible-travel / many geos → "block"
		return &override
	}

	// Volumetric, graded: a sustained flood is a confirmed DoS → ban; a moderate
	// burst is suspicious-but-unproven → challenge (serve a proof-of-work).
	if nb := len(profile.BurstTimestamps); nb > 50 {
		override := 0.0 // → "ban"
		return &override
	} else if nb > 15 {
		override := 4.0 // → "challenge"
		return &override
	}

	return nil
}

func makeDecision(score float64) string {
	if score >= 8.0 {
		return "allow"
	}
	if score >= 5.0 {
		return "allow+stricter"
	}
	if score >= 3.0 {
		return "challenge"
	}
	if score >= 1.0 {
		return "block"
	}
	return "ban"
}

// applyPolicyOverrides escalates the decision when high-risk signal combinations
// are present, regardless of the numeric score. These are first-touch guardrails:
// combinations that are suspicious enough to warrant a stricter action even before
// behavioral history has accumulated.
func applyPolicyOverrides(profile *IPProfile, subScores map[string]float64, score float64, decision string) string {
	profile.mu.RLock()
	defer profile.mu.RUnlock()

	// VPN or datacenter IP + any sensitive path hit → at minimum "allow+stricter".
	// The numeric score may say "allow" on the first request because there is no
	// history yet, but we should never silently pass traffic that combines
	// infrastructure evasion with credential/config probing.
	if (profile.IsVPN || profile.IsDatacenter) && len(profile.SensitivePathHits) > 0 {
		if decision == "allow" {
			return "allow+stricter"
		}
	}

	// Tor + any suspicious sub-score → at minimum "challenge".
	if profile.IsTor && subScores["recon"] > 0 {
		if decision == "allow" || decision == "allow+stricter" {
			return "challenge"
		}
	}

	return decision
}
