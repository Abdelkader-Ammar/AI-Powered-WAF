package trustscore

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisClient *redis.Client
)

// ResetAllData clears all runtime trust state: the in-memory IP and user profile
// stores (so banned entities are forgiven) and the Redis data the WAF publishes
// (scores, the recent-decisions feed, the RASP feed, Tier 1 queues). It does NOT
// touch admin accounts or configuration. Intended for the dashboard's
// "Reset All Data" action / a fresh demo run.
func ResetAllData() {
	DefaultIPStore = NewMemoryIPStore()
	DefaultUserStore = NewMemoryUserStore()
	if redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := redisClient.FlushDB(ctx).Err(); err != nil {
			log.Printf("[WARN] ResetAllData: FlushDB failed: %v", err)
		}
	}
}

// InitRedis initializes the Redis client for score exporting.
// It is intended to only store a simple Key-Value pair: ID -> TrustScore.
func InitRedis(addr, password string, db int) {
	redisClient = redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	})

	pingCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := redisClient.Ping(pingCtx).Result()
	if err != nil {
		log.Printf("Warning: Failed to connect to Redis at %s: %v", addr, err)
	} else {
		log.Printf("Successfully connected to Redis at %s", addr)
	}
}

// ExportScore pushes ONLY the ID and Score to Redis.
// This fulfills the requirement of keeping the external DB minimal (two columns: ID, Score),
// while the full profile remains in the local application state/logs.
func ExportScore(id string, score float64) error {
	if redisClient == nil {
		// Silently skip if Redis isn't initialized
		return nil
	}

	// Format score to 2 decimal places
	scoreStr := fmt.Sprintf("%.2f", score)

	// Set in Redis (no expiration, or could be configured)
	redisCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := redisClient.Set(redisCtx, id, scoreStr, 0).Err()
	if err != nil {
		log.Printf("Error exporting score for %s to Redis: %v", id, err)
		return err
	}

	return nil
}
