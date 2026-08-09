package admission

import (
	"testing"
	"time"
)

func TestBucketRefillsAtExactRate(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	b := newBucket(clock, 2, 2)
	if !b.take(clock.Now()) || !b.take(clock.Now()) || b.take(clock.Now()) {
		t.Fatal("burst accounting wrong")
	}
	clock.Advance(500 * time.Millisecond)
	if !b.take(clock.Now()) {
		t.Fatal("one half-second token missing")
	}
	if b.take(clock.Now()) {
		t.Fatal("token refunded")
	}
}
