package network

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestClassifyCandidatesRejectsUnsafeSet(t *testing.T) {
	_, err := ClassifyCandidates([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("127.0.0.1"),
	})
	if err == nil {
		t.Fatal("unsafe answer set accepted")
	}
}

func TestClassifyCandidatesRejectsIPv4MappedIPv6(t *testing.T) {
	_, err := ClassifyCandidates([]netip.Addr{netip.MustParseAddr("::ffff:8.8.8.8")})
	if err == nil {
		t.Fatal("IPv4-mapped IPv6 accepted")
	}
}

func TestClassifyCandidatesKeepsFirstSeenPublicIPv4(t *testing.T) {
	got, err := ClassifyCandidates([]netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("4.4.4.4"),
		netip.MustParseAddr("208.67.222.222"),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("4.4.4.4")}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("candidate %d = %v, want %v", i, got[i], want[i])
		}
	}
}

func TestDialCandidatesRejectsSelfAddress(t *testing.T) {
	d := Dialer{}
	_, _, err := d.DialCandidates(context.Background(), "example.com", 443,
		[]netip.Addr{netip.MustParseAddr("8.8.8.8")},
		PublicSelfSnapshot{Addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8")}})
	if err == nil {
		t.Fatal("self address accepted")
	}
}

func TestDialCandidatesRequiresFreshPositiveSelfSnapshot(t *testing.T) {
	d := Dialer{}
	for _, snapshot := range []PublicSelfSnapshot{
		{ObservedAt: time.Now().Add(-6 * time.Second), Outcome: publicSelfOutcome("positive"), Addresses: []netip.Addr{netip.MustParseAddr("9.9.9.9")}},
		{ObservedAt: time.Now(), Outcome: publicSelfOutcome("failure")},
	} {
		if _, _, err := d.DialCandidates(context.Background(), "example.com", 443, []netip.Addr{netip.MustParseAddr("8.8.8.8")}, snapshot); !errors.Is(err, ErrPublicSelfStale) {
			t.Fatalf("error = %v, want %v", err, ErrPublicSelfStale)
		}
	}
}
