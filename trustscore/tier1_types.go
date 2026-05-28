package trustscore

import (
	"context"
	"fmt"
	"time"
)

// Tier1Job represents a single request queued for RoBERTa analysis.
type Tier1Job struct {
	ID            string        `json:"id"`
	Event         RequestEvent  `json:"event"`
	LGBMProb      float64       `json:"lgbm_prob"`
	Tier0Decision string        `json:"tier0_decision"`
	ClientIP      string        `json:"client_ip"`
	UserID        string        `json:"user_id"`
	BodySnippet   string        `json:"body_snippet"`
	GreyZone      Tier1GreyZone `json:"grey_zone"`
	EnqueuedAt    float64       `json:"enqueued_at"`
	Retries       int           `json:"retries"`
}

// Tier1Result holds the RoBERTa inference output.
type Tier1Result struct {
	Label         string  `json:"label"`
	Confidence    float64 `json:"confidence"`
	BenignProb    float64 `json:"benign_prob"`
	MaliciousProb float64 `json:"malicious_prob"`
	ProcessedAt   int64   `json:"processed_at"`
	WorkerID      string  `json:"worker_id"`
}

// Tier1GreyZone defines the probability range that triggers Tier 1 for a tier.
type Tier1GreyZone struct {
	Center float64 `json:"center"`
	Width  float64 `json:"width"`
}

// Contains reports whether prob falls inside [center-width, center+width].
func (z Tier1GreyZone) Contains(prob float64) bool {
	return prob >= (z.Center-z.Width) && prob <= (z.Center+z.Width)
}

func (z Tier1GreyZone) String() string {
	min := z.Center - z.Width
	max := z.Center + z.Width
	return fmt.Sprintf("[%.2f, %.2f]", min, max)
}

// Tier1Config holds all Tier 1 settings.
type Tier1Config struct {
	Enabled             bool                     `json:"tier1_enabled"`
	ModelURL            string                   `json:"tier1_model_url"`
	ModelAPIKey         string                   `json:"tier1_model_api_key"`
	ConfidenceThreshold float64                  `json:"tier1_confidence_threshold"`
	WorkerCount         int                      `json:"tier1_worker_count"`
	MaxRetries          int                      `json:"tier1_max_retries"`
	CorrectionDelta     float64                  `json:"tier1_correction_delta"`
	GreyZones           map[string]Tier1GreyZone `json:"tier1_grey_zones"`
	RedisQueueKey       string                   `json:"tier1_redis_queue_key"`
	RedisFailedKey      string                   `json:"tier1_redis_failed_key"`
	RedisResultPrefix   string                   `json:"tier1_redis_result_prefix"`
	AuditDBPath         string                   `json:"tier1_audit_db_path"`
}

// Tier1Correction records a single trustscore adjustment.
type Tier1Correction struct {
	Delta     float64 `json:"delta"`
	Reason    string  `json:"reason"`
	Timestamp float64 `json:"timestamp"`
}

// QueueBackend abstracts the job queue.
type QueueBackend interface {
	Enqueue(ctx context.Context, job Tier1Job) error
	Dequeue(ctx context.Context, timeout time.Duration) (*Tier1Job, error)
	Requeue(ctx context.Context, job Tier1Job) error
	MoveToFailed(ctx context.Context, job Tier1Job) error
	StoreResult(ctx context.Context, jobID string, result Tier1Result) error
	MarkFeedbackApplied(ctx context.Context, jobID string) error
	SetHeartbeat(ctx context.Context, workerID, jobID string, ttl time.Duration) error
	DeleteHeartbeat(ctx context.Context, workerID string) error
	GetStats(ctx context.Context) (map[string]int64, error)
}

// AuditBackend abstracts the audit log.
type AuditBackend interface {
	LogEnqueue(job Tier1Job) error
	LogResult(jobID, workerID string, result Tier1Result, errMsg string) error
	LogFeedback(jobID string, delta float64, reason string) error
	Close() error
}
