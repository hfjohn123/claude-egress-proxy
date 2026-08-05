package admission

import (
	"testing"
	"time"
)

func TestAdminCapacityDoesNotConsumeStartToken(t *testing.T) {
	a := NewAdmin(newTestClock(time.Unix(0, 0)))
	leases := make([]*AdminLease, 0, 16)
	for range 16 {
		lease, d := a.Acquire()
		if !d.Allowed() {
			t.Fatal(d)
		}
		leases = append(leases, &lease)
	}
	if _, d := a.Acquire(); d != DecisionCapacity {
		t.Fatalf("17th = %v", d)
	}
	leases[0].Release()
	if _, d := a.Acquire(); !d.Allowed() {
		t.Fatalf("replacement = %v", d)
	}
	if _, d := a.Acquire(); d != DecisionCapacity {
		t.Fatalf("second replacement = %v", d)
	}
}

func TestAdminMetricsWorkHasTwoSlots(t *testing.T) {
	a := NewAdmin(newTestClock(time.Unix(0, 0)))
	a1, d := a.AcquireMetricsWork()
	if !d.Allowed() {
		t.Fatal(d)
	}
	_, d = a.AcquireMetricsWork()
	if !d.Allowed() {
		t.Fatal(d)
	}
	if _, d = a.AcquireMetricsWork(); d != DecisionCapacity {
		t.Fatal(d)
	}
	a1.Release()
	if _, d = a.AcquireMetricsWork(); !d.Allowed() {
		t.Fatal(d)
	}
}

func TestAdminCopiedLeaseReleasesExactlyOnce(t *testing.T) {
	a := NewAdmin(newTestClock(time.Unix(0, 0)))
	lease, d := a.Acquire()
	if !d.Allowed() {
		t.Fatal(d)
	}
	other, d := a.Acquire()
	if !d.Allowed() {
		t.Fatal(d)
	}
	copy := lease
	lease.Release()
	copy.Release()
	if got := a.active; got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}
	other.Release()
}

var _ = time.Second
