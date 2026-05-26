package trustscore

import (
	"fmt"
	"math"
)

// UserBehaviorSignals carries the raw observed inputs for a single scoring
// event. It is built by ComputeUserTrustScore before calling ScoreUserBehavior
// so that the behavior module stays pure and testable.
type UserBehaviorSignals struct {
	// Login context
	IsLoginEvent    bool   // true when this event is a POST to a login endpoint
	LoginSucceeded  bool   // true when status 200 on a login path
	LoginFailed     bool   // true when status 401/403 on a login path
	IsNewIP         bool   // IP not in profile.KnownIPs
	IsNewCountry    bool   // country not in profile.KnownCountries
	IsNewJA4        bool   // TLS fingerprint not in profile.KnownJA4s

	// Account context
	AccountAgeSec   float64 // seconds since account creation (0 = unknown)
	MFAEnabled      bool
	EmailVerified   bool

	// Session context
	SessionDurationSec  float64 // how long this session has lasted so far
	AvgSessionDurationSec float64 // historical average for this user

	// Endpoint context
	IsProtectedEndpoint bool // accessing /admin, /dashboard, etc.

	// IP-layer context (carried in from the IP score result)
	IPScore         float64
	IPWasBlocked    bool // the IP layer decided block or ban for this event
}

// ScoreUserBehavior computes a risk penalty [0.0–1.0] and a trust boost
// [0.0–1.0] from user-specific behavioral signals that the IP layer cannot see.
//
// Returns (penalty, boost, penaltyReasons, boostReasons).
func ScoreUserBehavior(
	profile *UserTrustProfile,
	event *RequestEvent,
	signals UserBehaviorSignals,
) (float64, float64, []ReasonItem, []string) {

	penalty := 0.0
	boost := 0.0
	var penaltyReasons []ReasonItem
	var boostReasons []string

	add := func(module string, amount float64, reason string) {
		penalty += amount
		penaltyReasons = append(penaltyReasons, ReasonItem{
			Module:   module,
			Reason:   reason,
			SubScore: math.Round(amount*1000) / 1000,
		})
	}

	// ── PENALTIES ──────────────────────────────────────────────────────────

	// 1. Consecutive failed logins (this session)
	// A human who misremembers their password tries once or twice then resets.
	// Many rapid failures = credential stuffing or brute force.
	if profile.TotalFailedLogins > 0 {
		switch {
		case profile.TotalFailedLogins >= 10:
			add("user_auth", 0.70, fmt.Sprintf("repeated_failed_logins:%d_total", profile.TotalFailedLogins))
		case profile.TotalFailedLogins >= 5:
			add("user_auth", 0.45, fmt.Sprintf("elevated_failed_logins:%d_total", profile.TotalFailedLogins))
		case profile.TotalFailedLogins >= 3:
			add("user_auth", 0.20, fmt.Sprintf("multiple_failed_logins:%d_total", profile.TotalFailedLogins))
		}
	}

	// 2. Login from a brand-new IP address
	// Not inherently malicious, but combined with other signals it matters.
	if signals.IsLoginEvent && signals.IsNewIP && profile.TotalSuccessLogins > 0 {
		add("user_geo", 0.15, fmt.Sprintf("new_ip_login:%s", event.IP))
	}

	// 3. Login from a new country — significantly more suspicious than new IP.
	// A user who always logs in from TN suddenly appearing from RU is notable.
	if signals.IsLoginEvent && signals.IsNewCountry && len(profile.KnownCountries) > 0 {
		add("user_geo", 0.30, fmt.Sprintf("new_country_login:%s (known:%v)", event.CountryCode, profile.KnownCountries))
	}

	// 4. New TLS fingerprint (new device / TLS library)
	// Weaker signal than new country, but still worth noting.
	if signals.IsLoginEvent && signals.IsNewJA4 && len(profile.KnownJA4s) > 0 {
		add("user_device", 0.15, fmt.Sprintf("new_ja4_fingerprint:%s", event.JA4Fingerprint))
	}

	// 5. Previously blocked IP logging into a user account
	// This is a hard escalation signal: the IP that was blocked at the WAF
	// layer somehow reached a login event (e.g. via a different IP cluster).
	if signals.IPWasBlocked {
		add("user_ip", 0.55, fmt.Sprintf("login_from_blocked_ip:%s", event.IP))
	}

	// 6. Very new account + high request volume
	// Brand-new accounts making lots of requests immediately is a bot-creation
	// pattern (account farms, fake signups).
	if signals.AccountAgeSec > 0 && signals.AccountAgeSec < 86400 { // < 24 hours old
		if profile.TotalRequests > 50 {
			add("user_account", 0.40, fmt.Sprintf("new_account_high_activity:age=%.0fs,reqs=%d",
				signals.AccountAgeSec, profile.TotalRequests))
		} else if profile.TotalRequests > 20 {
			add("user_account", 0.20, fmt.Sprintf("new_account_elevated_activity:age=%.0fs,reqs=%d",
				signals.AccountAgeSec, profile.TotalRequests))
		}
	}

	// 7. Session duration collapse
	// A user who normally spends 15+ minutes per session now disconnects in
	// under 30 seconds. Possible account takeover probe-and-exit pattern.
	if signals.AvgSessionDurationSec > 60 && signals.SessionDurationSec > 0 &&
		signals.SessionDurationSec < 30 && signals.AvgSessionDurationSec > 300 {
		add("user_session", 0.20, fmt.Sprintf("session_duration_collapse:avg=%.0fs,current=%.0fs",
			signals.AvgSessionDurationSec, signals.SessionDurationSec))
	}

	// 8. Accessing protected endpoints with a new device
	// Logging in with a new JA4 and immediately hitting /admin or /settings
	// without any navigation warmup is suspicious (account takeover pattern).
	if signals.IsProtectedEndpoint && signals.IsNewJA4 && len(profile.KnownJA4s) > 1 {
		add("user_device", 0.35, fmt.Sprintf("new_device_protected_access:%s", event.Path))
	}

	// 9. IP layer flagged this request as high risk
	// If the IP score is very low but the user somehow passed auth, apply a
	// proportional penalty. This bridges the gap between the two layers.
	if signals.IPScore < 3.0 {
		ipPenalty := math.Min((3.0-signals.IPScore)/3.0*0.50, 0.50)
		add("user_ip", ipPenalty, fmt.Sprintf("high_risk_ip:ip_score=%.2f", signals.IPScore))
	}

	// ── TRUST BOOSTERS ─────────────────────────────────────────────────────

	// 1. Long-standing account with clean history
	if signals.AccountAgeSec > 30*86400 { // account older than 30 days
		boost += 0.20
		boostReasons = append(boostReasons, fmt.Sprintf("established_account:age=%.0fd", signals.AccountAgeSec/86400))
	}

	// 2. Consistent login country across all sessions
	if len(profile.KnownCountries) == 1 && profile.TotalSuccessLogins >= 3 {
		boost += 0.15
		boostReasons = append(boostReasons, fmt.Sprintf("consistent_login_country:%s", profile.KnownCountries[0]))
	}

	// 3. Strong historical average trust score
	if len(profile.ScoreHistory) >= 5 {
		avg := profile.AverageRecentScore(10)
		if avg >= 8.0 {
			boost += 0.25
			boostReasons = append(boostReasons, fmt.Sprintf("high_historical_trust:avg=%.2f", avg))
		} else if avg >= 6.5 {
			boost += 0.10
			boostReasons = append(boostReasons, fmt.Sprintf("good_historical_trust:avg=%.2f", avg))
		}
	}

	// 4. MFA enabled — user has opted into stronger identity verification
	if signals.MFAEnabled {
		boost += 0.30
		boostReasons = append(boostReasons, "mfa_enabled")
	}

	// 5. Verified email address
	if signals.EmailVerified {
		boost += 0.10
		boostReasons = append(boostReasons, "email_verified")
	}

	// 6. Healthy IP score — the IP layer sees nothing suspicious
	if signals.IPScore >= 8.0 {
		boost += 0.15
		boostReasons = append(boostReasons, fmt.Sprintf("clean_ip:ip_score=%.2f", signals.IPScore))
	}

	return math.Min(penalty, 1.0), math.Min(boost, 1.0), penaltyReasons, boostReasons
}

// buildUserBehaviorSignals derives a UserBehaviorSignals struct from the
// current event and profile. Called by ComputeUserTrustScore before scoring.
func buildUserBehaviorSignals(
	profile *UserTrustProfile,
	event *RequestEvent,
	ipResult *TrustScoreResult,
	sessionStartTs float64,
) UserBehaviorSignals {
	_, isLoginPath := BruteForceEndpoints[event.Path]
	isLoginEvent := isLoginPath && event.Method == "POST"
	loginSucceeded := isLoginEvent && event.StatusCode == 200
	loginFailed := isLoginEvent && (event.StatusCode == 401 || event.StatusCode == 403)

	sessionDur := 0.0
	if sessionStartTs > 0 {
		sessionDur = event.Timestamp - sessionStartTs
	}

	ipWasBlocked := ipResult != nil &&
		(ipResult.Decision == "block" || ipResult.Decision == "ban")

	ipScore := 10.0
	if ipResult != nil {
		ipScore = ipResult.Score
	}

	return UserBehaviorSignals{
		IsLoginEvent:          isLoginEvent,
		LoginSucceeded:        loginSucceeded,
		LoginFailed:           loginFailed,
		IsNewIP:               !profile.IsKnownIP(event.IP),
		IsNewCountry:          !profile.IsKnownCountry(event.CountryCode),
		IsNewJA4:              !profile.IsKnownJA4(event.JA4Fingerprint),
		AccountAgeSec:         profile.AccountAgeSec(event.Timestamp),
		MFAEnabled:            profile.MFAEnabled,
		EmailVerified:         profile.EmailVerified,
		SessionDurationSec:    sessionDur,
		AvgSessionDurationSec: profile.AverageSessionDurationSec,
		IsProtectedEndpoint:   ProtectedEndpoints[event.Path],
		IPScore:               ipScore,
		IPWasBlocked:          ipWasBlocked,
	}
}
