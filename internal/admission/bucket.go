package admission

import (
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

// bucket is a no-refund token bucket. Callers must hold their enclosing lock.
type bucket struct {
	tokens float64
	burst  float64
	rate   float64 // tokens per second
	at     time.Time
}

func newBucket(clock timebase.Clock, rate float64, burst int) bucket {
	return bucket{tokens: float64(burst), burst: float64(burst), rate: rate, at: clock.Now()}
}

func (b *bucket) take(now time.Time) bool {
	if elapsed := now.Sub(b.at); elapsed > 0 {
		b.tokens += elapsed.Seconds() * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
		b.at = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
