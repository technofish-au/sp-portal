package instauth

import (
	"sync"
	"time"
)

// replayCache is a bounded in-memory set of recently seen request
// signature digests. Entries live for ttl (the timestamp acceptance
// window plus slack): a signature still inside the window is a replay and
// rejected; outside the window it fails the freshness check anyway, so
// older entries may be dropped. A per-request nonce keeps legitimate
// retries distinct — see docs/fakeportal.md.
//
// In-memory is deliberate: a restart accepts at most one replay per
// signature inside a 10-minute window, and the jobs table is not for this.
type replayCache struct {
	mu   sync.Mutex
	seen map[[32]byte]time.Time // digest -> first-seen time
	ttl  time.Duration
	cap  int
}

func newReplayCache(ttl time.Duration, capacity int) *replayCache {
	return &replayCache{seen: make(map[[32]byte]time.Time), ttl: ttl, cap: capacity}
}

// checkAndMark reports whether digest was already presented (a replay);
// otherwise it records it. Expired entries are swept on the way through.
func (c *replayCache) checkAndMark(digest [32]byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sweep(now)
	if _, dup := c.seen[digest]; dup {
		return true
	}
	if len(c.seen) >= c.cap {
		// At capacity with nothing expired: evict the oldest entry. This is
		// a flood safety valve, not the replay guarantee — legitimate
		// traffic is far below the cap.
		var oldest [32]byte
		var oldestAt time.Time
		for d, at := range c.seen {
			if oldestAt.IsZero() || at.Before(oldestAt) {
				oldest, oldestAt = d, at
			}
		}
		delete(c.seen, oldest)
	}
	c.seen[digest] = now
	return false
}

func (c *replayCache) sweep(now time.Time) {
	if len(c.seen) < c.cap/2 {
		return // sweep only once the map is worth scanning
	}
	for d, at := range c.seen {
		if now.Sub(at) > c.ttl {
			delete(c.seen, d)
		}
	}
}
