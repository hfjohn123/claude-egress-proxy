//go:build cep_testcontrol

package timebase

import (
	"errors"
	"sync"
)

var (
	errDeadlinePaused = errors.New("setup deadline already paused")
	errDeadlineDone   = errors.New("setup deadline is done")
	errResumeUsed     = errors.New("setup deadline resume already used")
)

// PauseForTest pauses setup budget accounting until its returned resume function is called.
func (d *Deadline) PauseForTest() (resume func() error, err error) {
	d.mu.Lock()
	if d.done {
		d.mu.Unlock()
		return nil, errDeadlineDone
	}
	if d.paused {
		d.mu.Unlock()
		return nil, errDeadlinePaused
	}
	if d.deadline.Sub(d.clock.Now()) <= 0 {
		d.finishLocked()
		d.mu.Unlock()
		d.cancel()
		return nil, errDeadlineDone
	}
	stopped := d.timer.Stop()
	pausedAt := d.clock.Now()
	if !stopped || d.deadline.Sub(pausedAt) <= 0 {
		d.finishLocked()
		d.mu.Unlock()
		d.cancel()
		return nil, errDeadlineDone
	}
	d.paused = true
	d.pausedAt = pausedAt
	d.mu.Unlock()

	var resumeMu sync.Mutex
	used := false
	return func() error {
		resumeMu.Lock()
		defer resumeMu.Unlock()
		if used {
			return errResumeUsed
		}
		used = true
		return d.resumeForTest()
	}, nil
}

func (d *Deadline) resumeForTest() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done {
		return errDeadlineDone
	}
	if !d.paused {
		return errDeadlinePaused
	}
	held := d.clock.Now().Sub(d.pausedAt)
	d.deadline = d.deadline.Add(held)
	d.paused = false
	d.timer.Reset(d.deadline.Sub(d.clock.Now()))
	return nil
}
