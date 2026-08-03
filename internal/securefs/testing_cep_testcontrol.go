//go:build cep_testcontrol

package securefs

type testFaults struct {
	fn      func(FaultPoint) error
	replace func(func() error) error
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
