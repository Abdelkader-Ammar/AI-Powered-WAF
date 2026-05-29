package main

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRateLimiter implements RateLimiterBackend with a Redis-backed
// fixed-window counter. The window rotates every 60 seconds based on
// Unix timestamp division, ensuring active clients get a clean window.
//
// NOTE: Unlike the in-memory token bucket, burst is not enforced — a
// client can use the full window quota in the first second.
// TODO: implement Redis token bucket via Lua script if burst enforcement
// is required in multi-instance deployments.
type RedisRateLimiter struct {
	redis *redis.Client
}

// NewRedisRateLimiter creates a rate limiter backed by Redis.
func NewRedisRateLimiter(redisClient *redis.Client) *RedisRateLimiter {
	return &RedisRateLimiter{redis: redisClient}
}

// AllowIP checks the per-IP rate limit. Returns (allowed, backendOK).
// On Redis error, backendOK is false so the caller can fall back.
func (rl *RedisRateLimiter) AllowIP(ip string, rate, burst float64) (bool, bool) {
	if rl == nil || rl.redis == nil {
		return true, false
	}
	return rl.allow("ip", ip, rate, burst)
}

// AllowUser checks the per-user rate limit. Returns (allowed, backendOK).
// On Redis error, backendOK is false so the caller can fall back.
func (rl *RedisRateLimiter) AllowUser(userID string, rate, burst float64) (bool, bool) {
	if rl == nil || rl.redis == nil {
		return true, false
	}
	return rl.allow("user", userID, rate, burst)
}

func (rl *RedisRateLimiter) allow(kind, key string, rate, burst float64) (bool, bool) {
	window := int64(60)
	windowID := time.Now().Unix() / window
	redisKey := fmt.Sprintf("ratelimit:%s:%s:%d", kind, key, windowID)
	limit := int64(rate * float64(window))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pipe := rl.redis.Pipeline()
	incr := pipe.Incr(ctx, redisKey)
	pipe.Expire(ctx, redisKey, time.Duration(window*2)*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return true, false
	}

	return incr.Val() <= limit, true
}
