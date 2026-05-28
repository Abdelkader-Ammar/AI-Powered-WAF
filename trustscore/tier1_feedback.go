package trustscore

import (
	"fmt"
	"time"
)

const (
	maxCorrections = 100
)

// FeedbackEngine applies trustscore corrections based on Tier 1 results.
type FeedbackEngine struct {
	correctionDelta     float64
	confidenceThreshold float64
	audit               AuditBackend
}

// NewFeedbackEngine creates a new feedback engine.
// delta is the correction magnitude (e.g. 0.20).
// confidenceThreshold is the minimum Tier 1 confidence to auto-correct.
func NewFeedbackEngine(delta, confidenceThreshold float64, audit AuditBackend) *FeedbackEngine {
	return &FeedbackEngine{
		correctionDelta:     delta,
		confidenceThreshold: confidenceThreshold,
		audit:               audit,
	}
}

// Apply evaluates the Tier 1 result against the Tier 0 decision and applies a correction.
// Returns (applied bool, delta float64, reason string, error).
func (f *FeedbackEngine) Apply(job Tier1Job, result PredictResponse) (bool, float64, string, error) {
	if result.Confidence < f.confidenceThreshold {
		return false, 0, "", nil
	}

	isTier0Malicious := job.Tier0Decision == "challenge" ||
		job.Tier0Decision == "block" ||
		job.Tier0Decision == "ban"

	isTier0Benign := job.Tier0Decision == "allow+stricter" ||
		job.Tier0Decision == "allow"

	var delta float64
	var reason string

	if isTier0Malicious && result.Label == "benign" {
		delta = f.correctionDelta
		reason = "tier1_false_positive"
	} else if isTier0Benign && result.Label == "malicious" {
		delta = -f.correctionDelta
		reason = "tier1_false_negative"
	} else {
		return false, 0, "", nil
	}

	ipProfile := GetOrCreateProfile(job.ClientIP)
	ipProfile.mu.Lock()
	ipProfile.EWMAScore += delta
	if ipProfile.EWMAScore > 1.0 {
		ipProfile.EWMAScore = 1.0
	}
	if ipProfile.EWMAScore < 0.0 {
		ipProfile.EWMAScore = 0.0
	}

	if len(ipProfile.Tier1Corrections) >= maxCorrections {
		ipProfile.Tier1Corrections = ipProfile.Tier1Corrections[1:]
	}
	ipProfile.Tier1Corrections = append(ipProfile.Tier1Corrections, Tier1Correction{
		Delta:     delta,
		Reason:    reason,
		Timestamp: float64(time.Now().Unix()),
	})
	ipProfile.mu.Unlock()

	if job.UserID != "" {
		userProfile := DefaultUserStore.Load(job.UserID, float64(time.Now().Unix()))
		if userProfile != nil {
			userProfile.mu.Lock()
			userProfile.EWMAScore += delta
			if userProfile.EWMAScore > 1.0 {
				userProfile.EWMAScore = 1.0
			}
			if userProfile.EWMAScore < 0.0 {
				userProfile.EWMAScore = 0.0
			}
			userProfile.mu.Unlock()
		}
	}

	if f.audit != nil {
		if err := f.audit.LogFeedback(job.ID, delta, reason); err != nil {
			return true, delta, reason, fmt.Errorf("audit feedback: %w", err)
		}
	}

	return true, delta, reason, nil
}
