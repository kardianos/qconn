package qconn

import (
	"context"
	"sync"
	"time"
)

// rateLimiter provides atomic rate limiting by key.
// It prevents the race condition where concurrent requests
// could both pass the check before either stores the new time.
type rateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	times    map[string]time.Time
}

func newRateLimiter(ctx context.Context, interval time.Duration) *rateLimiter {
	r := &rateLimiter{
		interval: interval,
		times:    make(map[string]time.Time),
	}
	// Start background cleanup to prevent memory growth.
	go r.cleanupLoop(ctx)
	return r
}

// cleanupLoop periodically removes expired entries.
func (r *rateLimiter) cleanupLoop(ctx context.Context) {
	// Clean up at twice the interval rate to ensure timely removal.
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.cleanup()
		}
	}
}

// allow checks if a request for the given key is allowed.
// If allowed, it atomically records the current time and returns true.
// If rate limited, it returns false and the remaining wait time.
// The check and update are atomic, preventing race conditions.
func (r *rateLimiter) allow(key string) (allowed bool, remaining time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if lastTime, ok := r.times[key]; ok {
		elapsed := now.Sub(lastTime)
		if elapsed < r.interval {
			return false, (r.interval - elapsed).Round(time.Second)
		}
	}
	r.times[key] = now
	return true, 0
}

// record updates the time for a key without checking.
// Use this when you want to record a successful operation
// that should reset the rate limit window.
func (r *rateLimiter) record(key string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.times[key] = time.Now()
}

// cleanup removes entries older than the interval.
// Call periodically to prevent memory growth.
func (r *rateLimiter) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.interval)
	for key, t := range r.times {
		if t.Before(cutoff) {
			delete(r.times, key)
		}
	}
}
