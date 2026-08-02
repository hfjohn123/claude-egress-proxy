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
