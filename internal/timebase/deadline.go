package timebase

import (
	"context"
	"sync"
	"time"
)

// SetupDeadline provides a cancellable setup budget.
type SetupDeadline interface {
	Context() context.Context
	Remaining() time.Duration
}

// Deadline owns one setup budget and its cancellation.
type Deadline struct {
	clock   Clock
	context context.Context
	cancel  context.CancelFunc
	timer   Timer

	mu       sync.Mutex
	deadline time.Time
	done     bool
	paused   bool
	pausedAt time.Time
}

// NewSetupDeadline starts a setup budget using clock.
func NewSetupDeadline(parent context.Context, clock Clock, budget time.Duration) *Deadline {
	ctx, cancel := context.WithCancel(parent)
	d := &Deadline{
		clock:    clock,
		context:  ctx,
		cancel:   cancel,
		timer:    clock.NewTimer(budget),
		deadline: clock.Now().Add(budget),
	}
	go d.wait(parent)
	return d
}

func (d *Deadline) wait(parent context.Context) {
	select {
	case <-parent.Done():
	case <-d.timer.C():
	}
	d.finish()
}

func (d *Deadline) finish() {
	d.mu.Lock()
	if d.done {
		d.mu.Unlock()
		return
	}
	d.done = true
	d.paused = false
	d.timer.Stop()
	d.mu.Unlock()
	d.cancel()
}

// Context is cancelled when the parent is cancelled or the setup budget expires.
func (d *Deadline) Context() context.Context { return d.context }

// Remaining reports the unexpired budget according to the injected clock.
func (d *Deadline) Remaining() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.paused {
		return d.deadline.Sub(d.pausedAt)
	}
	remaining := d.deadline.Sub(d.clock.Now())
	if remaining < 0 {
		return 0
	}
	return remaining
}
