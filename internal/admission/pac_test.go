package admission

import (
	"net/netip"
	"testing"
	"time"
)

func TestPACWorkCapacityDoesNotSpendTokens(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	p := NewPAC(clock)
	leases := make([]*WorkLease, 0, 32)
	for i := range 32 {
		clock.Advance(time.Second)
		l, d := p.Acquire(netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 32))
		if !d.Allowed() {
			t.Fatal(d)
		}
		leases = append(leases, &l)
	}
	if _, d := p.Acquire(netip.MustParsePrefix("203.0.113.1/32")); d != PACCapacity {
		t.Fatal(d)
	}
	leases[0].Release()
	if _, d := p.Acquire(netip.MustParsePrefix("203.0.113.1/32")); !d.Allowed() {
		t.Fatal(d)
	}
}

func TestPACRefillsThirtyTokensPerMinute(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	p := NewPAC(clock)
	prefix := netip.MustParsePrefix("198.51.100.32/32")
	for range 10 {
		lease, d := p.Acquire(prefix)
		if !d.Allowed() {
			t.Fatal(d)
		}
		lease.Release()
	}
	clock.Advance(2 * time.Second)
	if lease, d := p.Acquire(prefix); !d.Allowed() {
		t.Fatalf("two-second refill = %v", d)
	} else {
		lease.Release()
	}
}

func TestPACCopiedLeaseReleasesExactlyOnce(t *testing.T) {
	p := NewPAC(newTestClock(time.Unix(0, 0)))
	lease, d := p.Acquire(netip.MustParsePrefix("198.51.100.40/32"))
	if !d.Allowed() {
		t.Fatal(d)
	}
	other, d := p.Acquire(netip.MustParsePrefix("198.51.100.41/32"))
	if !d.Allowed() {
		t.Fatal(d)
	}
	copy := lease
	lease.Release()
	copy.Release()
	if got := p.active; got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}
	other.Release()
}

var _ = time.Second
