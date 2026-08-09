//go:build cep_testcontrol

package securefs

import (
	"context"
	"time"
)

type testFaults struct {
	fn      func(FaultPoint) error
	replace func(func() error) error
	wait    func(context.Context, time.Duration) error
}

func (f testFaults) hit(point FaultPoint) error { return f.fn(point) }

func FaultsForTest(fn func(FaultPoint) error) Faults { return testFaults{fn: fn} }

// FaultsForTestWithReplace is a per-call, build-tagged syscall seam. It is
// intentionally carried by Faults rather than stored in production globals.
func FaultsForTestWithReplace(fn func(FaultPoint) error, replace func(func() error) error) Faults {
	if fn == nil {
		fn = func(FaultPoint) error { return nil }
	}
	return testFaults{fn: fn, replace: replace}
}
func (f testFaults) replaceAttempt(run func() error) error {
	if f.replace != nil {
		return f.replace(run)
	}
	return run()
}
func (f testFaults) waitRetry(ctx context.Context, d time.Duration) error {
	if f.wait != nil {
		return f.wait(ctx, d)
	}
	return nil
}
func (f testFaults) hasRetryWaitOverride() bool { return f.wait != nil }
func FaultsForTestWithRetry(fn func(FaultPoint) error, replace func(func() error) error, wait func(context.Context, time.Duration) error) Faults {
	if fn == nil {
		fn = func(FaultPoint) error { return nil }
	}
	return testFaults{fn: fn, replace: replace, wait: wait}
}
