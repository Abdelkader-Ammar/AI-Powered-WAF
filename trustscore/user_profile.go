package trustscore

import (
	"math"
	"sync"
)

// UserTrustProfile is the long-term behavioral reputation record for a single
// authenticated user. It is keyed on user ID (not IP) and persists across
// sessions. The score is EWMA-smoothed so recent events matter more while
// historical trust decays slowly rather than resetting on each session.
//
// In production, persist this struct to a database (SQL or document store).
// The UserStore interface (user_store.go) is the seam for that integration.
type UserTrustProfile struct {
	mu     sync.RWMutex
	UserID string

	// EWMA trust score [0.0–10.0].
	// 10 = fully trusted, 0 = extremely high risk.
	Score float64

	// Alpha controls EWMA sensitivity.
	// 0.15 = slow adaptation (recent event weighs 15%, history 85%).
	// Raise to 0.30+ for systems that need to react faster to bad events.
	Alpha float64

	// Long-term counters (lifetime totals across all sessions)
	TotalSessions        int
	TotalRequests        int
	TotalFailedLogins    int
	TotalSuccessLogins   int
	TotalFlaggedEvents   int
	SessionFailedLogins  int // resets on successful login

	// IP/device reputation linkage
	// These are populated at login and used to detect anomalous access patterns.
	KnownIPs       []string // IPs this user has previously logged in from
	KnownCountries []string // Countries seen across all sessions
	KnownJA4s      []string // TLS fingerprints seen for this user

	// Session behavior
	AverageSessionDurationSec float64 // rolling average across all sessions
	LastSeenTimestamp         float64 // unix timestamp of most recent event

	// Account metadata (populated from the auth system at login)
	AccountCreatedAt float64 // unix timestamp; 0 if unknown
	MFAEnabled       bool
	EmailVerified    bool

	// Risk flags — these are sticky and do NOT reset automatically
	EverBlocked      bool
	EverChallenged   bool
	IPRiskAtLogin    float64 // IP-layer score at the moment of last login (0–10)

	// Score history — last 30 EWMA scores (one per session/key event)
	ScoreHistory []float64

	// Challenge solved state
	ChallengeSolvedRecently bool
	ChallengeSolvedAt       float64

	// Tier 1 correction state (separate from main Score which is 0-10)
	EWMAScore        float64            // correction score [0-1]
	Tier1Corrections []Tier1Correction

	// Tier 2 (RASP) ground-truth state
	RASPHits         []RASPHit
	ConfirmedExploit bool // sticky: set on a CRITICAL RASP hit attributed to this user

	// Timestamp of first and last profile write
	CreatedAt float64
	UpdatedAt float64
}

// NewUserProfile creates a fresh UserTrustProfile for a user we have never seen
// before. The starting score is 7.5 (cautious trust for new accounts) rather
// than 10.0, because we have no evidence either way yet.
func NewUserProfile(userID string, now float64) *UserTrustProfile {
	return &UserTrustProfile{
		UserID:       userID,
		Score:        7.5,
		Alpha:        0.15,
		ScoreHistory: []float64{},
		KnownIPs:     []string{},
		KnownCountries: []string{},
		KnownJA4s:    []string{},
		EWMAScore:        0.5,
		Tier1Corrections: []Tier1Correction{},
		CreatedAt:        now,
		UpdatedAt:        now,
	}
}

// UpdateEWMA blends a new observed score into the stored EWMA score.
// newObservedScore is the score produced by ComputeUserTrustScore for this
// event. The stored Score moves toward newObservedScore at rate Alpha.
//
//	Score = Alpha × newObservedScore + (1 − Alpha) × Score
//
// This means:
//   - A single bad event doesn't destroy a long-trusted user instantly.
//   - A consistent pattern of bad events compounds and pulls the score down.
//   - Good behavior slowly restores a damaged score over time.
func (u *UserTrustProfile) UpdateEWMA(newObservedScore float64) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.Score = u.Alpha*newObservedScore + (1-u.Alpha)*u.Score
	u.Score = math.Max(0.0, math.Min(10.0, u.Score))
	u.Score = math.Round(u.Score*100) / 100

	u.ScoreHistory = append(u.ScoreHistory, u.Score)
	if len(u.ScoreHistory) > 30 {
		u.ScoreHistory = u.ScoreHistory[1:]
	}
}

// AddScoreHistory appends to the history, shifting out old scores.
func (u *UserTrustProfile) AddScoreHistory(score float64) {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.ScoreHistory = append(u.ScoreHistory, score)
	if len(u.ScoreHistory) > 30 {
		u.ScoreHistory = u.ScoreHistory[1:]
	}
}

// AverageRecentScore returns the mean of the last N stored scores.
// Used by the trust booster "high historical average".
func (u *UserTrustProfile) AverageRecentScore(n int) float64 {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if len(u.ScoreHistory) == 0 {
		return u.Score
	}
	take := n
	if take > len(u.ScoreHistory) {
		take = len(u.ScoreHistory)
	}
	sum := 0.0
	for i := len(u.ScoreHistory) - take; i < len(u.ScoreHistory); i++ {
		sum += u.ScoreHistory[i]
	}
	return sum / float64(take)
}

// AccountAgeSec returns how many seconds old the account is.
// Returns 0 if AccountCreatedAt is unknown.
func (u *UserTrustProfile) AccountAgeSec(now float64) float64 {
	u.mu.RLock()
	defer u.mu.RUnlock()

	if u.AccountCreatedAt == 0 {
		return 0
	}
	age := now - u.AccountCreatedAt
	if age < 0 {
		return 0
	}
	return age
}

// IsKnownIP returns true if this IP has been seen for this user before.
func (u *UserTrustProfile) IsKnownIP(ip string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.isKnownIPUnsafe(ip)
}

func (u *UserTrustProfile) isKnownIPUnsafe(ip string) bool {
	for _, known := range u.KnownIPs {
		if known == ip {
			return true
		}
	}
	return false
}

// IsKnownCountry returns true if this country code has been seen before.
func (u *UserTrustProfile) IsKnownCountry(cc string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	return u.isKnownCountryUnsafe(cc)
}

func (u *UserTrustProfile) isKnownCountryUnsafe(cc string) bool {
	for _, known := range u.KnownCountries {
		if known == cc {
			return true
		}
	}
	return false
}

func (u *UserTrustProfile) isKnownJA4Unsafe(ja4 string) bool {
	for _, known := range u.KnownJA4s {
		if known == ja4 {
			return true
		}
	}
	return false
}

// IsKnownJA4 returns true if this TLS fingerprint has been seen before.
func (u *UserTrustProfile) IsKnownJA4(ja4 string) bool {
	u.mu.RLock()
	defer u.mu.RUnlock()

	for _, known := range u.KnownJA4s {
		if known == ja4 {
			return true
		}
	}
	return false
}

// RecordLogin updates the profile with identity signals from the current login
// event. Call this once per successful or failed login, before scoring.
func (u *UserTrustProfile) RecordLogin(event *RequestEvent, success bool) {
	u.mu.Lock()
	defer u.mu.Unlock()

	if success {
		u.TotalSuccessLogins++
		u.SessionFailedLogins = 0

		if !u.isKnownIPUnsafe(event.IP) {
			u.KnownIPs = append(u.KnownIPs, event.IP)
		}
		if !u.isKnownCountryUnsafe(event.CountryCode) {
			u.KnownCountries = append(u.KnownCountries, event.CountryCode)
		}
		if event.JA4Fingerprint != "" && !u.isKnownJA4Unsafe(event.JA4Fingerprint) {
			u.KnownJA4s = append(u.KnownJA4s, event.JA4Fingerprint)
		}
	} else {
		u.TotalFailedLogins++
		u.SessionFailedLogins++
	}

	u.TotalRequests++
	u.LastSeenTimestamp = event.Timestamp
	u.UpdatedAt = event.Timestamp
}

// UserTrustScoreResult is returned by ComputeUserTrustScore.
// It is the user-layer equivalent of TrustScoreResult (IP layer).
type UserTrustScoreResult struct {
	UserID          string       `json:"user_id"`
	Score           float64      `json:"score"`           // EWMA score after this event
	ScoreDelta      float64      `json:"score_delta"`     // how much the score changed
	PreviousScore   float64      `json:"previous_score"`  // score before this event
	Decision        string       `json:"decision"`        // allow / allow+stricter / challenge / block
	IPScore         float64      `json:"ip_score"`        // IP-layer score for this request
	Signals         []ReasonItem `json:"signals"`         // user-specific triggered signals
	BoostSignals    []string     `json:"boost_signals"`   // positive signals
	RawEventScore   float64      `json:"raw_event_score"` // computed before EWMA blend
	AccountAgeSec   float64      `json:"account_age_s"`
	Timestamp       float64      `json:"timestamp"`
}
