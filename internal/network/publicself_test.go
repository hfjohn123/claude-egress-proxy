package network

import (
	"context"
	"net/netip"
	"testing"
)

func TestPublicSelfRefreshPublishesCanonicalUnion(t *testing.T) {
	p := NewPublicSelf([]netip.Addr{netip.MustParseAddr("1.1.1.1")}, LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	}), "self.example")
	s := p.Refresh(context.Background())
	if s.Outcome.String() != "positive" || len(s.Addresses) != 2 || s.Addresses[0] != netip.MustParseAddr("1.1.1.1") || s.Addresses[1] != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("snapshot = %#v", s)
	}
}

func TestPublicSelfOverflowPublishesFailure(t *testing.T) {
	addresses := make([]netip.Addr, 65)
	for i := range addresses {
		addresses[i] = netip.AddrFrom4([4]byte{8, 8, 8, byte(i + 1)})
	}
	p := NewPublicSelf(addresses, nil, "")
	if got := p.Refresh(context.Background()); got.Outcome.String() != "failure" {
		t.Fatalf("outcome = %v, want failure", got.Outcome)
	}
}

func TestPublicSelfLoopbackModeIsSuccessEmpty(t *testing.T) {
	p := NewPublicSelfForMode(PublicSelfLoopback, nil, nil, "")
	if got := p.Refresh(context.Background()); got.Outcome.String() != "success_empty" {
		t.Fatalf("outcome = %v, want success_empty", got.Outcome)
	}
}
