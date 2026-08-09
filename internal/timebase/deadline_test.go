package timebase

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	now   time.Time
	timer *testTimer
}

func (c *testClock) Now() time.Time { return c.now }

func (c *testClock) NewTimer(duration time.Duration) Timer {
	c.timer = &testTimer{channel: make(chan time.Time, 1), stopped: make(chan struct{}, 1), active: true}
	return c.timer
}

func (c *testClock) NewTicker(time.Duration) Ticker { panic("ticker is not needed") }

type testTimer struct {
	channel chan time.Time
	stopped chan struct{}
	mu      sync.Mutex
	active  bool
	reset   []time.Duration
}

func (t *testTimer) C() <-chan time.Time { return t.channel }
func (t *testTimer) Stop() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.active {
		return false
	}
	t.active = false
	t.stopped <- struct{}{}
	return true
}
func (t *testTimer) Reset(duration time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	wasActive := t.active
	t.active = true
	t.reset = append(t.reset, duration)
	return wasActive
}

func TestSetupDeadlineUsesClockForRemainingTime(t *testing.T) {
	clock := &testClock{now: time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)}
	deadline := NewSetupDeadline(context.Background(), clock, 15*time.Second)

	if got, want := deadline.Remaining(), 15*time.Second; got != want {
		t.Fatalf("remaining = %s, want %s", got, want)
	}

	clock.now = clock.now.Add(4 * time.Second)
	if got, want := deadline.Remaining(), 11*time.Second; got != want {
		t.Fatalf("remaining = %s, want %s", got, want)
	}

	clock.now = clock.now.Add(20 * time.Second)
	if got := deadline.Remaining(); got != 0 {
		t.Fatalf("expired remaining = %s, want 0", got)
	}
}

func TestSetupDeadlineCancelsContextWhenTimerFires(t *testing.T) {
	clock := &testClock{now: time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)}
	deadline := NewSetupDeadline(context.Background(), clock, time.Second)
	clock.timer.channel <- clock.now.Add(time.Second)

	select {
	case <-deadline.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("setup deadline context was not cancelled")
	}
}

func TestSetupDeadlineCancelsAndStopsTimerWhenParentCancels(t *testing.T) {
	clock := &testClock{now: time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)}
	parent, cancel := context.WithCancel(context.Background())
	deadline := NewSetupDeadline(parent, clock, time.Second)
	cancel()

	select {
	case <-deadline.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("setup deadline context was not cancelled")
	}
	select {
	case <-clock.timer.stopped:
	case <-time.After(time.Second):
		t.Fatal("parent cancellation did not stop the timer")
	}
}
