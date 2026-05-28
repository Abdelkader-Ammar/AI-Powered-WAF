package trustscore

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisQueue implements QueueBackend using Redis Lists (FIFO).
type RedisQueue struct {
	client       *redis.Client
	queueKey     string
	failedKey    string
	resultPrefix string
}

// NewRedisQueue creates a new Redis-backed queue.
func NewRedisQueue(client *redis.Client, queueKey, failedKey, resultPrefix string) *RedisQueue {
	return &RedisQueue{
		client:       client,
		queueKey:     queueKey,
		failedKey:    failedKey,
		resultPrefix: resultPrefix,
	}
}

// Enqueue pushes a job to the tail (RPUSH) for FIFO ordering.
func (q *RedisQueue) Enqueue(ctx context.Context, job Tier1Job) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}

	pipe := q.client.Pipeline()
	pipe.RPush(ctx, q.queueKey, payload)
	pipe.Incr(ctx, "tier1:stats:enqueued")
	_, err = pipe.Exec(ctx)

	return err
}

// Dequeue blocks until a job is available (BLPOP pops from head).
func (q *RedisQueue) Dequeue(ctx context.Context, timeout time.Duration) (*Tier1Job, error) {
	result, err := q.client.BLPop(ctx, timeout, q.queueKey).Result()
	if err == redis.Nil {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("blpop: %w", err)
	}

	var job Tier1Job
	if err := json.Unmarshal([]byte(result[1]), &job); err != nil {
		return nil, fmt.Errorf("unmarshal job: %w", err)
	}

	return &job, nil
}

// Requeue puts a job back for retry (RPUSH to maintain FIFO among retries).
func (q *RedisQueue) Requeue(ctx context.Context, job Tier1Job) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job for requeue: %w", err)
	}

	pipe := q.client.Pipeline()
	pipe.RPush(ctx, q.queueKey, payload)
	pipe.Incr(ctx, "tier1:stats:requeued")
	_, err = pipe.Exec(ctx)

	return err
}

// MoveToFailed moves a permanently failed job to the dead letter queue.
func (q *RedisQueue) MoveToFailed(ctx context.Context, job Tier1Job) error {
	payload, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job for dead letter: %w", err)
	}

	pipe := q.client.Pipeline()
	pipe.LPush(ctx, q.failedKey, payload)
	pipe.Incr(ctx, "tier1:stats:failed")
	_, err = pipe.Exec(ctx)

	return err
}

// StoreResult saves the inference result with TTL.
func (q *RedisQueue) StoreResult(ctx context.Context, jobID string, result Tier1Result) error {
	key := fmt.Sprintf("%s:%s", q.resultPrefix, jobID)

	data := map[string]interface{}{
		"label":            result.Label,
		"confidence":       result.Confidence,
		"benign_prob":      result.BenignProb,
		"malicious_prob":   result.MaliciousProb,
		"processed_at":     result.ProcessedAt,
		"worker_id":        result.WorkerID,
		"feedback_applied": 0,
	}

	pipe := q.client.Pipeline()
	pipe.HSet(ctx, key, data)
	pipe.Expire(ctx, key, 24*time.Hour)
	pipe.Incr(ctx, "tier1:stats:completed")
	_, err := pipe.Exec(ctx)

	return err
}

// MarkFeedbackApplied sets feedback_applied = 1.
func (q *RedisQueue) MarkFeedbackApplied(ctx context.Context, jobID string) error {
	key := fmt.Sprintf("%s:%s", q.resultPrefix, jobID)
	return q.client.HSet(ctx, key, "feedback_applied", 1).Err()
}

// SetHeartbeat records that a worker is processing a job.
func (q *RedisQueue) SetHeartbeat(ctx context.Context, workerID, jobID string, ttl time.Duration) error {
	key := fmt.Sprintf("tier1:processing:%s", workerID)
	return q.client.Set(ctx, key, jobID, ttl).Err()
}

// DeleteHeartbeat removes the worker's processing indicator.
func (q *RedisQueue) DeleteHeartbeat(ctx context.Context, workerID string) error {
	key := fmt.Sprintf("tier1:processing:%s", workerID)
	return q.client.Del(ctx, key).Err()
}

// GetStats returns queue depth and counters.
func (q *RedisQueue) GetStats(ctx context.Context) (map[string]int64, error) {
	pipe := q.client.Pipeline()
	queueLen := pipe.LLen(ctx, q.queueKey)
	failedLen := pipe.LLen(ctx, q.failedKey)
	enqueued := pipe.Get(ctx, "tier1:stats:enqueued")
	completed := pipe.Get(ctx, "tier1:stats:completed")
	failed := pipe.Get(ctx, "tier1:stats:failed")
	requeued := pipe.Get(ctx, "tier1:stats:requeued")

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		return nil, err
	}

	return map[string]int64{
		"queue_depth":  queueLen.Val(),
		"failed_depth": failedLen.Val(),
		"enqueued":     parseIntSafe(enqueued.Val()),
		"completed":    parseIntSafe(completed.Val()),
		"failed":       parseIntSafe(failed.Val()),
		"requeued":     parseIntSafe(requeued.Val()),
	}, nil
}

// parseIntSafe converts a string to int64, returning 0 on empty/error.
func parseIntSafe(s string) int64 {
	if s == "" {
		return 0
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return v
}
