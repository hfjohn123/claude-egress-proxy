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
