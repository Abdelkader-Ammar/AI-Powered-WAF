package main

import (
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter.
// Rate and burst are updated dynamically from config on each Allow() call.
type TokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	lastFill time.Time
	rate     float64 // tokens per second
	burst    float64 // maximum tokens
}

// NewTokenBucket creates a bucket with the given rate and burst.
func NewTokenBucket(rate, burst float64) *TokenBucket {
	return &TokenBucket{
		tokens:   burst,
		lastFill: time.Now(),
		rate:     rate,
		burst:    burst,
	}
}

// Allow checks if a request is allowed and consumes one token.
// Rate and burst are updated dynamically from the caller so config changes apply immediately.
func (tb *TokenBucket) Allow(rate, burst float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// Update rate/burst dynamically from config
	tb.rate = rate
	tb.burst = burst

	now := time.Now()
	elapsed := now.Sub(tb.lastFill).Seconds()

	// Add tokens based on elapsed time, cap at burst
	newTokens := tb.tokens + elapsed*tb.rate
	if newTokens > tb.burst {
		newTokens = tb.burst
	}
	tb.tokens = newTokens
	tb.lastFill = now

	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// IdleTime returns time since last use (for eviction).
func (tb *TokenBucket) IdleTime() time.Duration {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	return time.Since(tb.lastFill)
}

// RateLimiterBackend is the interface for rate-limit backends.
// AllowIP/AllowUser return (allowed bool, backendOK bool).
// backendOK=false signals a backend error — the caller should fall back to
// the in-memory RateLimiter. For the in-memory backend, backendOK is always true.
type RateLimiterBackend interface {
	AllowIP(ip string, rate, burst float64) (bool, bool)
	AllowUser(userID string, rate, burst float64) (bool, bool)
}

// RateLimiter manages token buckets per IP and per user.
type RateLimiter struct {
	mu          sync.RWMutex
	ipBuckets   map[string]*TokenBucket
	userBuckets map[string]*TokenBucket
	ticker      *time.Ticker // stored for potential Stop()
}

// NewRateLimiter creates a rate limiter and starts the eviction goroutine.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		ipBuckets:   make(map[string]*TokenBucket),
		userBuckets: make(map[string]*TokenBucket),
	}
	// Evict idle buckets every 5 minutes, remove if idle > 10 minutes
	rl.startEviction(5*time.Minute, 10*time.Minute)
	return rl
}

// AllowIP checks the IP bucket. Uses double-check pattern with RWMutex.
// Implements RateLimiterBackend.
func (rl *RateLimiter) AllowIP(ip string, rate, burst float64) (bool, bool) {
	// Fast path: read lock
	rl.mu.RLock()
	bucket, ok := rl.ipBuckets[ip]
	rl.mu.RUnlock()

	if !ok {
		// Slow path: create bucket under write lock
		rl.mu.Lock()
		// Re-check in case another goroutine created it
		if bucket, ok = rl.ipBuckets[ip]; !ok {
			bucket = NewTokenBucket(rate, burst)
			rl.ipBuckets[ip] = bucket
		}
		rl.mu.Unlock()
	}

	return bucket.Allow(rate, burst), true
}

// AllowUser checks the user bucket. Uses double-check pattern with RWMutex.
// Implements RateLimiterBackend.
func (rl *RateLimiter) AllowUser(userID string, rate, burst float64) (bool, bool) {
	rl.mu.RLock()
	bucket, ok := rl.userBuckets[userID]
	rl.mu.RUnlock()

	if !ok {
		rl.mu.Lock()
		if bucket, ok = rl.userBuckets[userID]; !ok {
			bucket = NewTokenBucket(rate, burst)
			rl.userBuckets[userID] = bucket
		}
		rl.mu.Unlock()
	}

	return bucket.Allow(rate, burst), true
}

// startEviction runs a background goroutine that removes idle buckets.
func (rl *RateLimiter) startEviction(interval, maxIdle time.Duration) {
	rl.ticker = time.NewTicker(interval)
	go func() {
		for range rl.ticker.C {
			rl.mu.Lock()
			for ip, b := range rl.ipBuckets {
				if b.IdleTime() > maxIdle {
					delete(rl.ipBuckets, ip)
				}
			}
			for user, b := range rl.userBuckets {
				if b.IdleTime() > maxIdle {
					delete(rl.userBuckets, user)
				}
			}
			rl.mu.Unlock()
		}
	}()
}
