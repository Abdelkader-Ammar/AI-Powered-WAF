package trustscore

import (
	"math"
	"sort"
	"sync"
	"time"
)

// UserWeights controls how much the IP-layer risk and the user-behavior penalty
// each contribute to the raw event score before EWMA blending.
//
//	raw_event_score = 10 × (1 − combined_risk)
//	combined_risk   = IPWeight × ip_risk + UserWeight × user_penalty − BoostWeight × boost
//
// The weights intentionally give more influence to user-specific signals (0.60)
// than to the IP layer (0.40) because we have actual identity here.
var (
	userWeightsMu sync.RWMutex
	UserWeights   = struct {
		IP    float64 // contribution of IP-layer risk
		User  float64 // contribution of user-behavior penalty
		Boost float64 // how much a full boost (1.0) can reduce combined risk
	}{
		IP:    0.40,
		User:  0.60,
		Boost: 0.30,
	}
)

func SetUserWeights(ip, user, boost float64) {
	userWeightsMu.Lock()
	defer userWeightsMu.Unlock()
	UserWeights.IP = ip
	UserWeights.User = user
	UserWeights.Boost = boost
}

func GetUserWeights() (ip, user, boost float64) {
	userWeightsMu.RLock()
	defer userWeightsMu.RUnlock()
	return UserWeights.IP, UserWeights.User, UserWeights.Boost
}

// sessionStore tracks the start timestamp of each active user session so
// ScoreUserBehavior can compute session duration. Keyed on session_id.
// In production this would live in Redis with a TTL.
var (
	sessionStore   = make(map[string]float64) // sessionID → start timestamp
	sessionStoreMu sync.Mutex
)

func init() {
	// Simple cleanup to prevent OOM
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			now := float64(time.Now().Unix())
			sessionStoreMu.Lock()
			for k, v := range sessionStore {
				if now-v > 1800 { // 30 minutes
					delete(sessionStore, k)
				}
			}
			sessionStoreMu.Unlock()
		}
	}()
}

// ComputeUserTrustScore is the main entry point for the user-layer scoring.
//
// Flow:
//  1. Run the IP-layer scoring (ComputeTrustScore) — unchanged.
//  2. Load the UserTrustProfile from the store.
//  3. Build UserBehaviorSignals from the event + IP result.
//  4. Run ScoreUserBehavior to get user-specific penalty + boost.
//  5. Merge IP risk and user penalty into a single raw event score.
//  6. EWMA-blend the raw score into the stored long-term score.
//  7. Apply user-level hard overrides.
//  8. Make a decision, write back flags, persist the profile.
//  9. Return UserTrustScoreResult.
func ComputeUserTrustScore(
	ctx *IdentityContext,
	event *RequestEvent,
	store UserStore,
) *UserTrustScoreResult {

	userID := ctx.UserID

	// ── 1. IP-layer score (always run, even for authenticated users) ───────
	ipProfile := GetOrCreateProfile(event.IP)
	ipResult := ComputeTrustScore(ipProfile, event)

	// ── 2. Load user profile ──────────────────────────────────────────────
	userProfile := store.Load(userID, event.Timestamp)

	// Refresh identity fields from the IdentityContext on every request to avoid staleness
	if ctx.AccountCreatedAt > 0 {
		userProfile.AccountCreatedAt = ctx.AccountCreatedAt
	}
	userProfile.EmailVerified = ctx.EmailVerified
	userProfile.MFAEnabled = ctx.MFAEnabled

	previousScore := userProfile.Score

	// Track session start
	sessionStoreMu.Lock()
	if _, exists := sessionStore[event.SessionID]; !exists {
		sessionStore[event.SessionID] = event.Timestamp
	}
	sessionStart := sessionStore[event.SessionID]
	sessionStoreMu.Unlock()

	// ── 3. Build behavior signals ─────────────────────────────────────────
	signals := buildUserBehaviorSignals(userProfile, event, ipResult, sessionStart)

	// Update login counters BEFORE scoring so the penalty logic sees the
	// correct cumulative failed-login count.
	_, isLoginPath := BruteForceEndpoints[event.Path]
	isLoginEvent := isLoginPath && event.Method == "POST"
	if isLoginEvent {
		userProfile.RecordLogin(event, event.StatusCode == 200)
	} else {
		userProfile.TotalRequests++
		userProfile.LastSeenTimestamp = event.Timestamp
		userProfile.UpdatedAt = event.Timestamp
	}

	// ── 4. User-behavior penalty + boost ─────────────────────────────────
	userPenalty, userBoost, penaltyReasons, boostReasons := ScoreUserBehavior(
		userProfile, event, signals,
	)

	// ── 5. Merge IP risk + user penalty → raw event score ─────────────────
	// ip_risk is [0,1]: 0 = perfectly safe IP, 1 = maximum threat.
	ipRisk := math.Max(0.0, math.Min(1.0, (10.0-ipResult.Score)/10.0))

	wIP, wUser, wBoost := GetUserWeights()

	combinedRisk := wIP*ipRisk + wUser*userPenalty
	combinedRisk = math.Max(0.0, combinedRisk-wBoost*userBoost)
	combinedRisk = math.Max(0.0, math.Min(1.0, combinedRisk))

	rawEventScore := 10.0 * (1.0 - combinedRisk)
	rawEventScore = math.Max(0.0, math.Min(10.0, rawEventScore))

	// Challenge-solved boost
	if userProfile.ChallengeSolvedRecently && event.Timestamp-userProfile.ChallengeSolvedAt > 600 {
		userProfile.ChallengeSolvedRecently = false
	}
	if ipProfile.ChallengeSolvedRecently || userProfile.ChallengeSolvedRecently {
		rawEventScore = math.Min(10.0, rawEventScore+0.15)
		boostReasons = append(boostReasons, "challenge_solved")
	}

	// Tier 1 (RoBERTa) feedback correction for the user layer. Mirrors the IP
	// layer: userProfile.EWMAScore is neutral-centred on 0.5, mapped to a bounded
	// ±Tier1ScoreGain point delta applied before the EWMA blend.
	tier1Delta := (userProfile.EWMAScore - 0.5) * 2.0 * GetConfig().Tier1ScoreGain
	if math.Abs(tier1Delta) >= 0.01 {
		rawEventScore = math.Max(0.0, math.Min(10.0, rawEventScore+tier1Delta))
	}

	// ── 6. Apply user hard overrides BEFORE EWMA blend ───────────────────
	// Hard overrides bypass EWMA — they set the final EWMA score directly.
	hardOverride := checkUserHardOverrides(userProfile, signals, ipResult)
	if hardOverride != nil {
		rawEventScore = *hardOverride
	}

	// ── 7. EWMA blend raw event score into stored long-term score ─────────
	// Hard overrides also set the stored score directly (bypass EWMA inertia)
	// so a critical condition takes immediate effect rather than washing out.
	if hardOverride != nil {
		userProfile.Score = *hardOverride
		userProfile.Score = math.Max(0.0, math.Min(10.0, userProfile.Score))
		userProfile.Score = math.Round(userProfile.Score*100) / 100
		userProfile.ScoreHistory = append(userProfile.ScoreHistory, userProfile.Score)
		if len(userProfile.ScoreHistory) > 30 {
			userProfile.ScoreHistory = userProfile.ScoreHistory[1:]
		}
	} else {
		userProfile.UpdateEWMA(rawEventScore)
	}
	finalScore := userProfile.Score
	scoreDelta := math.Round((finalScore-previousScore)*100) / 100

	// ── 8. Decision + flag writeback ─────────────────────────────────────
	decision := makeDecision(finalScore)
	decision = applyUserPolicyOverrides(userProfile, signals, ipResult, decision)

	switch decision {
	case "block", "ban":
		userProfile.EverBlocked = true
	case "challenge":
		userProfile.EverChallenged = true
	}

	// Record IP risk at login so future sessions can reference it.
	if signals.IsLoginEvent && signals.LoginSucceeded {
		userProfile.IPRiskAtLogin = ipResult.Score
		userProfile.TotalSessions++
	}

	// Flag event if it contributed a meaningful penalty.
	if userPenalty >= 0.20 {
		userProfile.TotalFlaggedEvents++
	}

	// ── 9. Persist ────────────────────────────────────────────────────────
	store.Save(userProfile)

	// ── 10. Build result ─────────────────────────────────────────────────
	// Merge IP reasons and user-behavior reasons into one sorted slice.
	allSignals := make([]ReasonItem, 0, len(ipResult.Reasons)+len(penaltyReasons))
	for _, r := range ipResult.Reasons {
		allSignals = append(allSignals, r)
	}
	allSignals = append(allSignals, penaltyReasons...)
	sort.Slice(allSignals, func(i, j int) bool {
		return allSignals[i].SubScore > allSignals[j].SubScore
	})

	allBoostSignals := make([]string, 0, len(ipResult.BoostReasons)+len(boostReasons))
	allBoostSignals = append(allBoostSignals, ipResult.BoostReasons...)
	allBoostSignals = append(allBoostSignals, boostReasons...)

	return &UserTrustScoreResult{
		UserID:        userID,
		Score:         finalScore,
		ScoreDelta:    scoreDelta,
		PreviousScore: previousScore,
		Decision:      decision,
		IPScore:       ipResult.Score,
		Signals:       allSignals,
		BoostSignals:  allBoostSignals,
		RawEventScore: math.Round(rawEventScore*100) / 100,
		AccountAgeSec: math.Round(userProfile.AccountAgeSec(event.Timestamp)*10) / 10,
		Timestamp:     event.Timestamp,
	}
}

// checkUserHardOverrides returns a score override that bypasses EWMA for
// critical conditions. Returns nil if no override applies.
func checkUserHardOverrides(
	profile *UserTrustProfile,
	signals UserBehaviorSignals,
	ipResult *TrustScoreResult,
) *float64 {

	// A confirmed RASP exploitation attributed to this account is ground truth.
	if profile.ConfirmedExploit {
		v := 0.0
		return &v
	}

	// Too many failed logins total → force immediate block score.
	if profile.TotalFailedLogins >= 20 {
		v := 0.5
		return &v
	}

	// IP layer decided to ban AND this event is a login attempt →
	// the account may be under active credential stuffing.
	if ipResult.Decision == "ban" && signals.IsLoginEvent {
		v := 0.0
		return &v
	}

	// User was previously blocked AND is now logging in from a brand-new
	// country + new device simultaneously → very high ATO risk.
	if profile.EverBlocked && signals.IsNewCountry && signals.IsNewJA4 {
		v := 0.5
		return &v
	}

	return nil
}

// applyUserPolicyOverrides escalates the decision for high-risk user-specific
// signal combinations that the numeric EWMA score alone might not catch
// immediately (especially on the first event for a new user).
func applyUserPolicyOverrides(
	profile *UserTrustProfile,
	signals UserBehaviorSignals,
	ipResult *TrustScoreResult,
	decision string,
) string {

	// New country login → at minimum challenge (force step-up auth).
	if signals.IsLoginEvent && signals.IsNewCountry && len(profile.KnownCountries) > 0 {
		if decision == "allow" {
			return "allow+stricter"
		}
	}

	// Previously blocked user + new device → at minimum challenge.
	if profile.EverBlocked && signals.IsNewJA4 {
		if decision == "allow" || decision == "allow+stricter" {
			return "challenge"
		}
	}

	// IP layer says block/ban → user layer cannot allow, at minimum challenge.
	if ipResult.Decision == "block" || ipResult.Decision == "ban" {
		if decision == "allow" || decision == "allow+stricter" {
			return "challenge"
		}
	}

	return decision
}
