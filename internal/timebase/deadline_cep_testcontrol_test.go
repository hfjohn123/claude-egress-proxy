//go:build cep_testcontrol

package timebase

import (
	"context"
	"slices"
	"testing"
	"time"
)

func TestPausedSetupDeadline(t *testing.T) {
	clock := &testClock{now: time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)}
	deadline := NewSetupDeadline(context.Background(), clock, 15*time.Second)
	resume, err := deadline.PauseForTest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deadline.PauseForTest(); err == nil {
		t.Fatal("nested pause succeeded")
	}

	clock.now = clock.now.Add(time.Hour)
	if got, want := deadline.Remaining(), 15*time.Second; got != want {
		t.Fatalf("paused remaining = %s, want %s", got, want)
	}

	if err := resume(); err != nil {
		t.Fatal(err)
	}
	if got, want := deadline.Remaining(), 15*time.Second; got != want {
		t.Fatalf("resumed remaining = %s, want %s", got, want)
	}
	if got, want := clock.timer.reset, []time.Duration{15 * time.Second}; !slices.Equal(got, want) {
		t.Fatalf("timer reset = %s, want %s", got, want)
	}
	if err := resume(); err == nil {
		t.Fatal("double resume succeeded")
	}
	if got, want := deadline.Remaining(), 15*time.Second; got != want {
		t.Fatalf("double resume remaining = %s, want %s", got, want)
	}
}

func TestPausedSetupDeadlineStillCancelsFromParent(t *testing.T) {
	clock := &testClock{now: time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)}
	parent, cancel := context.WithCancel(context.Background())
	deadline := NewSetupDeadline(parent, clock, 15*time.Second)
	if _, err := deadline.PauseForTest(); err != nil {
		t.Fatal(err)
	}
	cancel()

	select {
	case <-deadline.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("paused deadline did not respect parent cancellation")
	}
}

func TestPausedSetupDeadlineRefusesExpiredBudget(t *testing.T) {
	start := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		budget  time.Duration
		advance time.Duration
	}{
		{name: "zero budget", budget: 0},
		{name: "negative budget", budget: -time.Second},
		{name: "clock past deadline before timer notification", budget: time.Second, advance: 2 * time.Second},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := &testClock{now: start}
			deadline := NewSetupDeadline(context.Background(), clock, test.budget)
			clock.now = clock.now.Add(test.advance)

			if _, err := deadline.PauseForTest(); err == nil {
				t.Fatal("PauseForTest accepted an expired setup deadline")
			}
			if got := deadline.Remaining(); got != 0 {
				t.Fatalf("remaining = %s, want 0", got)
			}
			select {
			case <-deadline.Context().Done():
			case <-time.After(time.Second):
				t.Fatal("expired setup deadline context was not cancelled")
			}
		})
	}
}

type scriptedClock struct {
	now         []time.Time
	index       int
	timer       *testTimer
	timerActive bool
}

func (c *scriptedClock) Now() time.Time {
	value := c.now[c.index]
	if c.index < len(c.now)-1 {
		c.index++
	}
	return value
}

func (c *scriptedClock) NewTimer(time.Duration) Timer {
	c.timer = &testTimer{channel: make(chan time.Time, 1), stopped: make(chan struct{}, 1), active: c.timerActive}
	return c.timer
}

func (c *scriptedClock) NewTicker(time.Duration) Ticker { panic("ticker is not needed") }

func TestPausedSetupDeadlineRejectsExpiryAtPauseBoundary(t *testing.T) {
	start := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	deadlineAt := start.Add(time.Second)
	clock := &scriptedClock{now: []time.Time{start, deadlineAt.Add(-time.Nanosecond), deadlineAt}, timerActive: true}
	deadline := NewSetupDeadline(context.Background(), clock, time.Second)

	if _, err := deadline.PauseForTest(); err == nil {
		t.Fatal("PauseForTest accepted expiry at the pause boundary")
	}
	if got := deadline.Remaining(); got != 0 {
		t.Fatalf("remaining = %s, want 0", got)
	}
	select {
	case <-deadline.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("expired setup deadline context was not cancelled")
	}
}

func TestPausedSetupDeadlineRejectsTimerStopFailure(t *testing.T) {
	start := time.Date(2026, time.August, 2, 0, 0, 0, 0, time.UTC)
	beforeDeadline := start.Add(time.Second - time.Nanosecond)
	clock := &scriptedClock{now: []time.Time{start, beforeDeadline, beforeDeadline}}
	deadline := NewSetupDeadline(context.Background(), clock, time.Second)

	if _, err := deadline.PauseForTest(); err == nil {
		t.Fatal("PauseForTest accepted an already-fired timer")
	}
	select {
	case <-deadline.Context().Done():
	case <-time.After(time.Second):
		t.Fatal("already-fired setup deadline context was not cancelled")
	}
}
