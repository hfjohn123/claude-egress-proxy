package admission

import (
	"net/netip"
	"testing"
	"time"
)

func TestAuthenticationIPv6AggregatesAt64(t *testing.T) {
	a := NewAuthentication(newTestClock(time.Unix(0, 0)))
	first := Aggregate(netip.MustParseAddr("2001:db8::1"))
	second := Aggregate(netip.MustParseAddr("2001:db8::2"))
	if first != second {
		t.Fatal("IPv6 addresses must aggregate at /64")
	}
	for range 10 {
		if d := a.AdmitInvalid(first); !d.Allowed() {
			t.Fatal(d)
		}
	}
	if d := a.AdmitInvalid(second); d != DecisionThrottled {
		t.Fatalf("shared prefix = %v", d)
	}
}

var _ = time.Second
