package trustscore

import (
	"fmt"
	"math"
)

func ScoreEvasion(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string) {
	penalty := 0.0
	var reasons []string

	uaCount := len(profile.SeenUserAgents)
	if uaCount >= cfg.EvasionUARotationHigh {
		penalty += 0.65
		reasons = append(reasons, fmt.Sprintf("ua_rotation:%d_distinct_UAs", uaCount))
	} else if uaCount >= cfg.EvasionUARotationMedium {
		penalty += 0.3
		reasons = append(reasons, fmt.Sprintf("ua_change:%d_UAs", uaCount))
	}

	ja4Count := len(profile.SeenJA4)
	if ja4Count >= cfg.EvasionJA4Rotation {
		penalty += 0.5
		reasons = append(reasons, fmt.Sprintf("ja4_rotation:%d_distinct_fingerprints", ja4Count))
	}

	if len(profile.RecentTimestamps) >= 6 {
		cv := coefficientOfVariation(profile.RecentTimestamps)
		if cv < cfg.EvasionPeriodicCV {
			penalty += 0.4
			reasons = append(reasons, fmt.Sprintf("periodic_bot:CV=%.4f", cv))
		}
	}

	if profile.RateLimitPauses >= cfg.EvasionPauseResumeCount {
		penalty += 0.55
		reasons = append(reasons, fmt.Sprintf("rate_limit_evasion:paused_and_resumed_%dx", profile.RateLimitPauses))
	}

	if profile.IsTor {
		penalty += 0.7
		reasons = append(reasons, "tor_exit_node")
	}
	if profile.IsVPN {
		penalty += 0.35
		reasons = append(reasons, "vpn_detected")
	}
	if profile.IsDatacenter {
		penalty += 0.2
		reasons = append(reasons, "datacenter_asn")
	}

	return math.Min(penalty, 1.0), reasons
}
