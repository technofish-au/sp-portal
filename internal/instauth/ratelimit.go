package instauth

import (
	"sync"
	"time"
)

// rateLimiter is a per-instance token bucket. Buckets are created on first
// use and reaped when idle long enough that they would be full anyway, so
// the map stays small without a background sweeper.
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	maxKeys int
	now     func() time.Time
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newRateLimiter(perMinute int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*bucket),
		rate:    float64(perMinute) / 60,
		burst:   float64(perMinute),
		maxKeys: 100_000,
		now:     now,
	}
}

// Allow consumes one token for key, reporting whether the request may
// proceed.
func (l *rateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= l.maxKeys {
			l.reap(now)
		}
		b = &bucket{tokens: l.burst, at: now}
		l.buckets[key] = b
	}
	b.tokens += now.Sub(b.at).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.at = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// reap drops buckets idle so long they would have refilled completely —
// their state is equivalent to a fresh bucket.
func (l *rateLimiter) reap(now time.Time) {
	fullAfter := time.Duration(l.burst/l.rate) * time.Second
	for k, b := range l.buckets {
		if now.Sub(b.at) > fullAfter {
			delete(l.buckets, k)
		}
	}
}
