package network

import (
	"context"
	"net/netip"
	"testing"
)

func TestLookupFuncResolverPreservesOrderedAAnswers(t *testing.T) {
	r := LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}, nil
	})
	got, err := r.LookupA(context.Background(), "EXAMPLE.COM.")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != netip.MustParseAddr("8.8.8.8") || got[1] != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("answers = %v", got)
	}
}

func TestLookupFuncResolverRejectsNonIPv4AndExcessAnswers(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("2001:4860:4860::8888")},
		func() []netip.Addr {
			a := make([]netip.Addr, 33)
			for i := range a {
				a[i] = netip.MustParseAddr("8.8.8.8")
			}
			return a
		}(),
	} {
		r := LookupFunc(func(context.Context, string) ([]netip.Addr, error) { return answers, nil })
		if _, err := r.LookupA(context.Background(), "example.com"); err == nil {
			t.Fatalf("answers %v accepted", answers)
		}
	}
}
