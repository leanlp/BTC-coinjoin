package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ──────────────────────────────────────────────────────────────────────
// Per-IP Token Bucket Rate Limiter
//
// Uses stdlib only — no external dependency.
//
// Each IP gets its own bucket with a configurable capacity and refill rate.
// When the bucket is empty the request receives HTTP 429 with a Retry-After
// header indicating when to try again.
//
// A background goroutine cleans up buckets that have been idle for more than
// cleanupIdleDuration to prevent unbounded memory growth from transient IPs.
// ──────────────────────────────────────────────────────────────────────

const cleanupIdleDuration = 10 * time.Minute

type ipBucket struct {
	tokens   float64
	lastSeen time.Time
	mu       sync.Mutex
}

// RateLimiter holds per-IP state.
type RateLimiter struct {
	rate     float64 // tokens added per second
	burst    float64 // max bucket capacity
	mu       sync.Mutex
	buckets  map[string]*ipBucket
}

// NewRateLimiter creates a rate limiter allowing `ratePerMin` requests per
// minute per IP, with a burst capacity of `burst` requests.
func NewRateLimiter(ratePerMin, burst int) *RateLimiter {
	rl := &RateLimiter{
		rate:    float64(ratePerMin) / 60.0,
		burst:   float64(burst),
		buckets: make(map[string]*ipBucket),
	}
	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) allow(ip string) (bool, time.Duration) {
	rl.mu.Lock()
	bucket, ok := rl.buckets[ip]
	if !ok {
		bucket = &ipBucket{tokens: rl.burst}
		rl.buckets[ip] = bucket
	}
	rl.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()
	// Refill tokens based on elapsed time since last request.
	elapsed := now.Sub(bucket.lastSeen).Seconds()
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > rl.burst {
		bucket.tokens = rl.burst
	}
	bucket.lastSeen = now

	if bucket.tokens >= 1.0 {
		bucket.tokens--
		return true, 0
	}

	// Calculate how long until a token is available.
	retryAfter := time.Duration((1.0-bucket.tokens)/rl.rate*1000) * time.Millisecond
	return false, retryAfter
}

// Middleware returns a Gin handler that enforces the rate limit.
func (rl *RateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		allowed, retryAfter := rl.allow(ip)
		if !allowed {
			c.Header("Retry-After", retryAfter.String())
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"retryAfter":  retryAfter.String(),
				"limit":       "30 requests/minute per IP",
			})
			c.Abort()
			return
		}
		c.Next()
	}
}

// cleanupLoop removes stale IP buckets every cleanupIdleDuration.
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(cleanupIdleDuration)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-cleanupIdleDuration)
		rl.mu.Lock()
		for ip, b := range rl.buckets {
			b.mu.Lock()
			idle := b.lastSeen.Before(cutoff)
			b.mu.Unlock()
			if idle {
				delete(rl.buckets, ip)
			}
		}
		rl.mu.Unlock()
	}
}
