package trustscore

import (
	"fmt"
	"math"
)

func ComputeTrustBoost(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string, BoostSignals) {
	boost := 0.0
	var reasons []string
	var signals BoostSignals

	sessionAge := event.Timestamp - profile.FirstSeen
	if sessionAge > 300 {
		if len(profile.RecentTimestamps) >= 5 {
			cv := coefficientOfVariation(profile.RecentTimestamps)
			if cv > cfg.BoostHumanCVMin {
				boost += 0.3
				reasons = append(reasons, fmt.Sprintf("human_timing:session_age=%.0fs,CV=%.2f", sessionAge, cv))
			}
		}
	}

	// Consistent identity boost only after enough requests to rule out a single-shot scanner.
	// A fresh scanner also has exactly 1 UA and 1 JA4 — we need history to distinguish.
	if len(profile.SeenUserAgents) == 1 && len(profile.SeenJA4) == 1 &&
		profile.TotalRequests >= 10 && sessionAge >= 60 {
		boost += 0.2
		reasons = append(reasons, "consistent_identity:single_UA_and_JA4")
	}

	total := profile.AssetRequestCount + profile.NonAssetRequestCount
	if total >= 10 {
		assetRatio := float64(profile.AssetRequestCount) / float64(total)
		if assetRatio > cfg.BoostAssetRatioMin {
			boost += 0.25
			reasons = append(reasons, fmt.Sprintf("normal_browser_behavior:asset_ratio=%.0f%%", assetRatio*100))
		}
	}

	if profile.HasValidReferer {
		boost += 0.15
		reasons = append(reasons, "valid_referer_chain")
	}

	if !profile.IsDatacenter && !profile.IsTor && !profile.IsVPN && len(profile.SeenCountryCodes) == 1 {
		boost += 0.2
		reasons = append(reasons, "residential_ip:consistent_geo")
	}

	if profile.TotalRequests >= 20 {
		errorRate := 0.0
		if profile.TotalRequests > 0 {
			errorRate = float64(profile.Total404+profile.Total403+profile.Total500) / float64(profile.TotalRequests)
		}
		if errorRate < 0.05 {
			boost += 0.15
			reasons = append(reasons, fmt.Sprintf("low_error_rate:%.1f%%", errorRate*100))
		}
	}

	if len(profile.PreviousScores) >= 3 && !profile.WasBlocked && !profile.WasChallenged {
		sum := 0.0
		take := len(profile.PreviousScores)
		if take > 5 {
			take = 5
		}
		for i := len(profile.PreviousScores) - take; i < len(profile.PreviousScores); i++ {
			sum += profile.PreviousScores[i]
		}
		avgPrev := sum / float64(take)
		if avgPrev >= 7.0 {
			boost += 0.25
			reasons = append(reasons, fmt.Sprintf("returning_clean_visitor:avg_prev_score=%.1f", avgPrev))
		}
	}

	if profile.HadHomepage && profile.HadLoginFlow {
		boost += 0.15
		reasons = append(reasons, "proper_session_warmup")
	}

	if event.ChallengePassed {
		boost += 5.0
		reasons = append(reasons, "passed JS Proof-of-Work challenge")
		signals.PassedChallenge = true

		return boost, reasons, signals // Do not cap the boost, drastically restore trust
	}

	return math.Min(boost, 1.0), reasons, signals
}
