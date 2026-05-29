package trustscore

import (
	"os"
	"testing"
)

func TestFeedbackEngine(t *testing.T) {
	dbPath := "/tmp/test_tier1_feedback.db"
	os.Remove(dbPath)
	audit, err := NewSQLiteAudit(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteAudit failed: %v", err)
	}
	defer audit.Close()
	defer os.Remove(dbPath)

	engine := NewFeedbackEngine(0.20, 0.85, audit)

	t.Run("FalsePositive", func(t *testing.T) {
		job := Tier1Job{
			ID:            "fp-test",
			Tier0Decision: "block",
			ClientIP:      "192.168.1.1",
			UserID:        "",
		}
		result := PredictResponse{
			Label:      "benign",
			Confidence: 0.91,
		}

		applied, delta, reason, err := engine.Apply(job, result)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !applied {
			t.Fatal("expected feedback to be applied")
		}
		if delta != 0.20 {
			t.Errorf("expected delta +0.20, got %f", delta)
		}
		if reason != "tier1_false_positive" {
			t.Errorf("expected reason tier1_false_positive, got %s", reason)
		}

		profile := GetOrCreateProfile("192.168.1.1")
		profile.mu.RLock()
		score := profile.EWMAScore
		corrections := len(profile.Tier1Corrections)
		profile.mu.RUnlock()

		if score != 0.70 {
			t.Errorf("expected score 0.70 (0.5+0.2), got %f", score)
		}
		if corrections != 1 {
			t.Errorf("expected 1 correction, got %d", corrections)
		}
	})

	t.Run("FalseNegative", func(t *testing.T) {
		job := Tier1Job{
			ID:            "fn-test",
			Tier0Decision: "allow",
			ClientIP:      "192.168.1.2",
			UserID:        "",
		}
		result := PredictResponse{
			Label:      "malicious",
			Confidence: 0.91,
		}

		applied, delta, reason, err := engine.Apply(job, result)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if !applied {
			t.Fatal("expected feedback to be applied")
		}
		if delta != -0.20 {
			t.Errorf("expected delta -0.20, got %f", delta)
		}
		if reason != "tier1_false_negative" {
			t.Errorf("expected reason tier1_false_negative, got %s", reason)
		}

		profile := GetOrCreateProfile("192.168.1.2")
		profile.mu.RLock()
		score := profile.EWMAScore
		profile.mu.RUnlock()

		if score != 0.30 {
			t.Errorf("expected score 0.30 (0.5-0.2), got %f", score)
		}
	})

	t.Run("AgreementNoFeedback", func(t *testing.T) {
		job := Tier1Job{
			ID:            "agree-test",
			Tier0Decision: "block",
			ClientIP:      "192.168.1.3",
			UserID:        "",
		}
		result := PredictResponse{
			Label:      "malicious",
			Confidence: 0.91,
		}

		applied, delta, reason, err := engine.Apply(job, result)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if applied {
			t.Fatal("expected no feedback for agreement")
		}
		if delta != 0 {
			t.Errorf("expected delta 0, got %f", delta)
		}
		if reason != "" {
			t.Errorf("expected empty reason, got %s", reason)
		}
	})

	t.Run("LowConfidenceNoFeedback", func(t *testing.T) {
		job := Tier1Job{
			ID:            "lowconf-test",
			Tier0Decision: "block",
			ClientIP:      "192.168.1.4",
			UserID:        "",
		}
		result := PredictResponse{
			Label:      "benign",
			Confidence: 0.50,
		}

		applied, delta, _, err := engine.Apply(job, result)
		if err != nil {
			t.Fatalf("Apply failed: %v", err)
		}
		if applied {
			t.Fatal("expected no feedback for low confidence")
		}
		if delta != 0 {
			t.Errorf("expected delta 0, got %f", delta)
		}
	})

	t.Run("CorrectionCappedAt100", func(t *testing.T) {
		ip := "192.168.1.5"
		for i := 0; i < 105; i++ {
			job := Tier1Job{
				ID:            "cap-test",
				Tier0Decision: "block",
				ClientIP:      ip,
				UserID:        "",
			}
			result := PredictResponse{
				Label:      "benign",
				Confidence: 0.91,
			}
			engine.Apply(job, result)
		}

		profile := GetOrCreateProfile(ip)
		profile.mu.RLock()
		corrections := len(profile.Tier1Corrections)
		profile.mu.RUnlock()

		if corrections != maxCorrections {
			t.Errorf("expected %d corrections (capped), got %d", maxCorrections, corrections)
		}
	})

	t.Run("ScoreClamped", func(t *testing.T) {
		ip := "192.168.1.6"
		job := Tier1Job{
			ID:            "clamp-test",
			Tier0Decision: "block",
			ClientIP:      ip,
			UserID:        "",
		}
		result := PredictResponse{
			Label:      "benign",
			Confidence: 0.91,
		}

		profile := GetOrCreateProfile(ip)
		profile.mu.Lock()
		profile.EWMAScore = 0.95
		profile.mu.Unlock()

		engine.Apply(job, result)

		profile.mu.RLock()
		score := profile.EWMAScore
		profile.mu.RUnlock()

		if score != 1.0 {
			t.Errorf("expected score clamped to 1.0, got %f", score)
		}
	})

	t.Run("UserProfileUpdate", func(t *testing.T) {
		t.Skip("Requires DefaultUserStore initialization — verify manually in integration test")
	})
}
