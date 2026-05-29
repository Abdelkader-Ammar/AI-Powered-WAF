package trustscore

import (
	"fmt"
	"os"
	"testing"
)

func TestSQLiteAudit(t *testing.T) {
	dbPath := "/tmp/test_tier1_audit.db"
	os.Remove(dbPath)

	audit, err := NewSQLiteAudit(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteAudit failed: %v", err)
	}
	defer audit.Close()
	defer os.Remove(dbPath)

	job := Tier1Job{
		ID:            "test-job-1",
		Event:         RequestEvent{Method: "POST", Path: "/api/login", UserAgent: "test"},
		LGBMProb:      0.45,
		Tier0Decision: "challenge",
		ClientIP:      "192.168.1.100",
		UserID:        "user_123",
		GreyZone:      Tier1GreyZone{Center: 0.65, Width: 0.15},
		EnqueuedAt:    1717102800,
		Retries:       0,
	}

	t.Run("LogEnqueue", func(t *testing.T) {
		if err := audit.LogEnqueue(job); err != nil {
			t.Fatalf("LogEnqueue failed: %v", err)
		}
	})

	t.Run("LogResultSuccess", func(t *testing.T) {
		result := Tier1Result{
			Label:         "benign",
			Confidence:    0.91,
			BenignProb:    0.91,
			MaliciousProb: 0.09,
			ProcessedAt:   1717102805,
			WorkerID:      "worker-0",
		}
		if err := audit.LogResult(job.ID, "worker-0", result, ""); err != nil {
			t.Fatalf("LogResult failed: %v", err)
		}
	})

	t.Run("LogResultFailure", func(t *testing.T) {
		if err := audit.LogResult("nonexistent-job", "worker-0", Tier1Result{}, "connection timeout"); err != nil {
			t.Fatalf("LogResult for nonexistent job failed: %v", err)
		}
	})

	t.Run("LogFeedback", func(t *testing.T) {
		if err := audit.LogFeedback(job.ID, 0.20, "tier1_false_positive"); err != nil {
			t.Fatalf("LogFeedback failed: %v", err)
		}
	})

	t.Run("ConcurrentWrites", func(t *testing.T) {
		done := make(chan bool, 10)
		for i := 0; i < 10; i++ {
			go func(idx int) {
				j := Tier1Job{
					ID:            fmt.Sprintf("concurrent-job-%d", idx),
					Event:         RequestEvent{Method: "GET", Path: "/"},
					LGBMProb:      0.30,
					Tier0Decision: "allow+stricter",
					ClientIP:      "10.0.0.1",
					EnqueuedAt:    1717102800,
				}
				if err := audit.LogEnqueue(j); err != nil {
					t.Errorf("concurrent LogEnqueue failed: %v", err)
				}
				done <- true
			}(i)
		}
		for i := 0; i < 10; i++ {
			<-done
		}
	})
}
