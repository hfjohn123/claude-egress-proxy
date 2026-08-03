//go:build cep_testcontrol

package securefs

type testFaults struct{ fn func(FaultPoint) error }

func (f testFaults) hit(point FaultPoint) error { return f.fn(point) }

func FaultsForTest(fn func(FaultPoint) error) Faults { return testFaults{fn: fn} }
