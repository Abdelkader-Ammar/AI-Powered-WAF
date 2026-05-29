package trustscore

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// TestTier1EndToEnd verifies the full pipeline:
// Enqueue → Dequeue → HTTP to mock RoBERTa → Store Result → Apply Feedback → Audit
func TestTier1EndToEnd(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available — skipping end-to-end test")
	}

	prefix := "tier1:e2e"
	redisClient.Del(context.Background(), prefix+":queue", prefix+":failed")
	redisClient.Del(context.Background(), "tier1:stats:enqueued", "tier1:stats:completed", "tier1:stats:failed")

	mockRoberta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/predict" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		var req PredictRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		resp := PredictResponse{
			Label:         "benign",
			Confidence:    0.91,
			BenignProb:    0.91,
			MaliciousProb: 0.09,
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockRoberta.Close()

	dbPath := "/tmp/test_tier1_e2e.db"
	os.Remove(dbPath)

	config := Tier1Config{
		Enabled:             true,
		ModelURL:            mockRoberta.URL,
		ModelAPIKey:         "",
		ConfidenceThreshold: 0.85,
		WorkerCount:         1,
		MaxRetries:          2,
		CorrectionDelta:     0.20,
		RedisQueueKey:       prefix + ":queue",
		RedisFailedKey:      prefix + ":failed",
		RedisResultPrefix:   prefix + ":result",
		AuditDBPath:         dbPath,
	}

	pipeline, err := NewTier1Pipeline(config, redisClient)
	if err != nil {
		t.Fatalf("NewTier1Pipeline failed: %v", err)
	}
	pipeline.Start()

	job := Tier1Job{
		ID:            "e2e-test-job",
		Event:         RequestEvent{Method: "POST", Path: "/api/login", UserAgent: "test"},
		LGBMProb:      0.45,
		Tier0Decision: "block",
		ClientIP:      "192.168.100.1",
		UserID:        "",
		GreyZone:      Tier1GreyZone{Center: 0.40, Width: 0.15},
		EnqueuedAt:    float64(time.Now().Unix()),
		Retries:       0,
	}

	if err := pipeline.Enqueue(job); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	time.Sleep(3 * time.Second)

	pipeline.Stop()

	resultKey := prefix + ":result:" + job.ID
	result, err := redisClient.HGetAll(context.Background(), resultKey).Result()
	if err != nil {
		t.Fatalf("Failed to get result from Redis: %v", err)
	}

	if result["label"] != "benign" {
		t.Errorf("expected label benign, got %s", result["label"])
	}
	if result["confidence"] != "0.91" {
		t.Errorf("expected confidence 0.91, got %s", result["confidence"])
	}

	profile := GetOrCreateProfile("192.168.100.1")
	profile.mu.RLock()
	score := profile.EWMAScore
	corrections := len(profile.Tier1Corrections)
	profile.mu.RUnlock()

	if score != 0.70 {
		t.Errorf("expected score 0.70 after false positive correction, got %f", score)
	}
	if corrections != 1 {
		t.Errorf("expected 1 correction, got %d", corrections)
	}

	os.Remove(dbPath)
	redisClient.Del(context.Background(), prefix+":queue", prefix+":failed")
	redisClient.Del(context.Background(), prefix+":result:"+job.ID)
	redisClient.Del(context.Background(), "tier1:stats:enqueued", "tier1:stats:completed", "tier1:stats:failed")
}

// TestTier1RetryAndDeadLetter verifies retry exhaustion → dead letter
func TestTier1RetryAndDeadLetter(t *testing.T) {
	redisClient := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		t.Skip("Redis not available — skipping test")
	}

	prefix := "tier1:retry"
	redisClient.Del(context.Background(), prefix+":queue", prefix+":failed")

	mockRoberta := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("GPU OOM"))
	}))
	defer mockRoberta.Close()

	dbPath := "/tmp/test_tier1_retry.db"
	os.Remove(dbPath)

	config := Tier1Config{
		Enabled:             true,
		ModelURL:            mockRoberta.URL,
		ConfidenceThreshold: 0.85,
		WorkerCount:         1,
		MaxRetries:          2,
		CorrectionDelta:     0.20,
		RedisQueueKey:       prefix + ":queue",
		RedisFailedKey:      prefix + ":failed",
		RedisResultPrefix:   prefix + ":result",
		AuditDBPath:         dbPath,
	}

	pipeline, err := NewTier1Pipeline(config, redisClient)
	if err != nil {
		t.Fatalf("NewTier1Pipeline failed: %v", err)
	}
	pipeline.Start()

	job := Tier1Job{
		ID:            "retry-test-job",
		Event:         RequestEvent{Method: "GET", Path: "/"},
		LGBMProb:      0.45,
		Tier0Decision: "challenge",
		ClientIP:      "192.168.200.1",
		EnqueuedAt:    float64(time.Now().Unix()),
		Retries:       0,
	}

	if err := pipeline.Enqueue(job); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	time.Sleep(10 * time.Second)

	pipeline.Stop()

	failedLen, err := redisClient.LLen(context.Background(), prefix+":failed").Result()
	if err != nil {
		t.Fatalf("Failed to check dead letter queue: %v", err)
	}
	if failedLen != 1 {
		t.Errorf("expected 1 job in dead letter queue, got %d", failedLen)
	}

	os.Remove(dbPath)
	redisClient.Del(context.Background(), prefix+":queue", prefix+":failed")
}
