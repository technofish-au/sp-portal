package jobs

import (
	"testing"
	"time"
)

func TestBackoffGrowsAndCaps(t *testing.T) {
	base, maxDelay := time.Second, 5*time.Minute
	prev := time.Duration(0)
	for attempt := 1; attempt <= 8; attempt++ {
		// Average out jitter over samples: the mean must sit inside
		// [0.75, 1.25] * min(base*2^(a-1), maxDelay).
		var sum time.Duration
		const n = 200
		for range n {
			sum += backoff(base, maxDelay, attempt)
		}
		mean := sum / n
		want := min(base<<(attempt-1), maxDelay)
		if mean < time.Duration(float64(want)*0.7) || mean > time.Duration(float64(want)*1.3) {
			t.Fatalf("attempt %d: mean backoff %s outside jitter band of %s", attempt, mean, want)
		}
		if mean < prev {
			t.Fatalf("attempt %d: mean backoff %s shrank from %s", attempt, mean, prev)
		}
		prev = mean
	}
}

func TestBackoffNeverExceedsCap(t *testing.T) {
	for range 500 {
		if d := backoff(time.Second, 5*time.Second, 20); d > 6250*time.Millisecond {
			t.Fatalf("backoff %s exceeds cap+jitter", d)
		}
	}
}
