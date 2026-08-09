package network

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
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

func TestPublicSelfRefreshSingleflightsConcurrentCallers(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	p := NewPublicSelf(nil, LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}), "self.example")
	first := make(chan PublicSelfSnapshot, 1)
	second := make(chan PublicSelfSnapshot, 1)
	go func() { first <- p.Refresh(t.Context()) }()
	<-started
	go func() { second <- p.Refresh(t.Context()) }()
	time.Sleep(10 * time.Millisecond) // second caller reaches the in-flight gate
	close(release)
	<-first
	<-second
	if got := calls.Load(); got != 1 {
		t.Fatalf("resolver calls = %d, want one", got)
	}
}

func TestPublicSelfAcquireRefreshesExpiredSnapshot(t *testing.T) {
	now := time.Unix(100, 0)
	var calls atomic.Int32
	p := NewPublicSelf(nil, LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		calls.Add(1)
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}), "self.example")
	p.now = func() time.Time { return now }
	first := p.Acquire(context.Background())
	now = now.Add(6 * time.Second)
	second := p.Acquire(context.Background())
	if second.Generation <= first.Generation || calls.Load() != 2 {
		t.Fatalf("first=%d second=%d resolver calls=%d", first.Generation, second.Generation, calls.Load())
	}
}

func TestPublicSelfRejectsUnsafeConfiguredAddress(t *testing.T) {
	p := NewPublicSelf([]netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil, "")
	if got := p.Refresh(context.Background()); got.Outcome.String() != "failure" {
		t.Fatalf("unsafe configured outcome=%s want failure", got.Outcome)
	}
}

func TestACMEPublicSelfConfiguredAddressDoesNotSatisfyPositiveDNS(t *testing.T) {
	p := NewPublicSelfForMode(PublicSelfACME, []netip.Addr{netip.MustParseAddr("1.1.1.1")}, LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		return nil, nil
	}), "proxy.example.com")
	got := p.Refresh(context.Background())
	if got.Outcome.String() == "positive" || len(got.Addresses) != 1 || got.Addresses[0] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("snapshot=%#v; configured address must remain deny-only", got)
	}
}
