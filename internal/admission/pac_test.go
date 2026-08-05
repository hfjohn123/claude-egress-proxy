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

var _ = time.Second
