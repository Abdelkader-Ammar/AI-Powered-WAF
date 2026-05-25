package trustscore

import (
	"fmt"
	"math"
)

type BruteForceDetector struct {
	config Config
}

var BruteForceEndpoints = map[string]string{
	"/login":               "login",
	"/api/login":           "login",
	"/auth/login":          "login",
	"/signin":              "login",
	"/api/token":           "login",
	"/forgot-password":     "password_reset",
	"/reset-password":      "password_reset",
	"/api/password/reset":  "password_reset",
	"/register":            "registration",
	"/signup":              "registration",
	"/api/register":        "registration",
}

func ScoreBruteForce(profile *IPProfile, event *RequestEvent, cfg Config) (float64, []string) {
	penalty := 0.0
	var reasons []string

	endpointType, exists := BruteForceEndpoints[event.Path]
	if event.Method != "POST" || !exists {
		return penalty, reasons
	}

	recent := 0
	if timestamps, ok := profile.EndpointTimestamps[event.Path]; ok {
		recent = slidingWindowCount(timestamps, 60, event.Timestamp)
	}

	switch endpointType {
	case "login":
		profile.LoginAttempts++
		if recent > cfg.BruteLoginHigh {
			penalty += 0.85
			reasons = append(reasons, fmt.Sprintf("login_brute_force:%d/60s", recent))
		} else if recent > cfg.BruteLoginMedium {
			penalty += 0.5
			reasons = append(reasons, fmt.Sprintf("login_high_rate:%d/60s", recent))
		}

	case "password_reset":
		profile.PasswordResetAttempts++
		if recent > cfg.BruteResetHigh {
			penalty += 0.7
			reasons = append(reasons, fmt.Sprintf("password_reset_flood:%d/60s", recent))
		}

	case "registration":
		profile.RegistrationAttempts++
		if recent > cfg.BruteRegisterHigh {
			penalty += 0.6
			reasons = append(reasons, fmt.Sprintf("registration_flood:%d/60s", recent))
		}
	}

	if epTimestamps, ok := profile.EndpointTimestamps[event.Path]; ok && len(epTimestamps) >= 8 {
		cv := coefficientOfVariation(epTimestamps)
		if cv < cfg.BruteCVBotThreshold {
			penalty += 0.4
			reasons = append(reasons, fmt.Sprintf("bot_timing_cv:%.3f", cv))
		}
	}

	if profile.LoginAttempts > cfg.BruteCumulativeLogin {
		penalty += 0.5
		reasons = append(reasons, fmt.Sprintf("cumulative_login_attempts:%d", profile.LoginAttempts))
	}

	return math.Min(penalty, 1.0), reasons
}
