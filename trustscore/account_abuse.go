package trustscore

import (
	"fmt"
	"math"
)

func ScoreAccountAbuse(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string) {
	penalty := 0.0
	var reasons []string

	regRecent := 0
	regRecent += slidingWindowCount(profile.EndpointTimestamps["/register"], 300, event.Timestamp)
	regRecent += slidingWindowCount(profile.EndpointTimestamps["/signup"], 300, event.Timestamp)

	if regRecent > cfg.AbuseRegisterHigh {
		penalty += 0.7
		reasons = append(reasons, fmt.Sprintf("mass_registration:%d/5min", regRecent))
	} else if regRecent > cfg.AbuseRegisterMedium {
		penalty += 0.4
		reasons = append(reasons, fmt.Sprintf("elevated_registration:%d/5min", regRecent))
	}

	resetRecent := 0
	resetRecent += slidingWindowCount(profile.EndpointTimestamps["/forgot-password"], 300, event.Timestamp)
	resetRecent += slidingWindowCount(profile.EndpointTimestamps["/reset-password"], 300, event.Timestamp)

	if resetRecent > cfg.AbuseResetHigh {
		penalty += 0.6
		reasons = append(reasons, fmt.Sprintf("password_reset_flood:%d/5min", resetRecent))
	}

	totalAccountOps := profile.LoginAttempts + profile.RegistrationAttempts + profile.PasswordResetAttempts

	if totalAccountOps > cfg.AbuseCumulativeHigh {
		penalty += 0.5
		reasons = append(reasons, fmt.Sprintf("high_account_ops_total:%d", totalAccountOps))
	}

	return math.Min(penalty, 1.0), reasons
}
