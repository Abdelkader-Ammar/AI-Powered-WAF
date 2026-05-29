package trustscore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func TestTier1PipelineLifecycle(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available — skipping integration test")
	}

	redisClient.Del(context.Background(), "tier1:test:queue", "tier1:test:failed")
	redisClient.Del(context.Background(), "tier1:stats:enqueued", "tier1:stats:completed", "tier1:stats:failed")

	dbPath := "/tmp/test_tier1_pipeline.db"
	os.Remove(dbPath)

	config := Tier1Config{
		Enabled:             true,
		ModelURL:            "http://localhost:5001",
		ModelAPIKey:         "",
		ConfidenceThreshold: 0.85,
		WorkerCount:         1,
		MaxRetries:          2,
		CorrectionDelta:     0.20,
		RedisQueueKey:       "tier1:test:queue",
		RedisFailedKey:      "tier1:test:failed",
		RedisResultPrefix:   "tier1:test:result",
		AuditDBPath:         dbPath,
	}

	t.Run("CreateAndStartStop", func(t *testing.T) {
		pipeline, err := NewTier1Pipeline(config, redisClient)
		if err != nil {
			t.Fatalf("NewTier1Pipeline failed: %v", err)
		}

		pipeline.Start()
		time.Sleep(100 * time.Millisecond)

		pipeline.Stop()

		if err := pipeline.audit.LogEnqueue(Tier1Job{ID: "after-stop"}); err == nil {
			t.Error("expected error logging after stop, got nil")
		}
	})

	t.Run("EnqueueAndStats", func(t *testing.T) {
		pipeline, err := NewTier1Pipeline(config, redisClient)
		if err != nil {
			t.Fatalf("NewTier1Pipeline failed: %v", err)
		}

		job := Tier1Job{
			ID:            "test-enqueue-1",
			Event:         RequestEvent{Method: "GET", Path: "/"},
			LGBMProb:      0.45,
			Tier0Decision: "challenge",
			ClientIP:      "10.0.0.1",
			EnqueuedAt:    float64(time.Now().Unix()),
			Retries:       0,
		}

		if err := pipeline.Enqueue(job); err != nil {
			t.Fatalf("Enqueue failed: %v", err)
		}

		stats, err := pipeline.queue.GetStats(context.Background())
		if err != nil {
			t.Fatalf("GetStats failed: %v", err)
		}
		if stats["enqueued"] < 1 {
			t.Errorf("expected enqueued >= 1, got %d", stats["enqueued"])
		}

		pipeline.Stop()
	})

	t.Run("DisabledPipeline", func(t *testing.T) {
		redisClient.Del(context.Background(), "tier1:stats:enqueued", "tier1:stats:completed", "tier1:stats:failed")
		disabledConfig := config
		disabledConfig.Enabled = false

		pipeline, err := NewTier1Pipeline(disabledConfig, redisClient)
		if err != nil {
			t.Fatalf("NewTier1Pipeline failed: %v", err)
		}

		job := Tier1Job{ID: "disabled-test"}
		if err := pipeline.Enqueue(job); err != nil {
			t.Fatalf("Enqueue on disabled pipeline should not error: %v", err)
		}

		stats, _ := pipeline.queue.GetStats(context.Background())
		if stats["enqueued"] > 0 {
			t.Error("disabled pipeline should not enqueue")
		}

		pipeline.Stop()
	})

	os.Remove(dbPath)
	redisClient.Del(context.Background(), "tier1:test:queue", "tier1:test:failed")
	redisClient.Del(context.Background(), "tier1:stats:enqueued", "tier1:stats:completed", "tier1:stats:failed")
}
