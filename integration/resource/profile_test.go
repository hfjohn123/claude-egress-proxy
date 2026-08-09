package resource

import (
	"net/netip"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
)

func TestHermeticProfileUsesFixedGlobalCandidate(t *testing.T) {
	candidate := netip.MustParseAddr(SyntheticGlobalIPv4)
	if got := policy.Classify(candidate); got != policy.AddressGlobalIPv4 {
		t.Fatalf("candidate class = %v, want global IPv4", got)
	}
}

func TestHermeticProfileReflectsFixedV1Bounds(t *testing.T) {
	limits := contract.V1()
	profile := DefaultProfile()
	if profile.PreAuth != limits.PreAuthActive || profile.Authenticated != limits.GlobalCapacity {
		t.Fatalf("connection bounds = %+v", profile)
	}
	if profile.MapEntries != limits.PrefixEntries || profile.RetainedBuffers != limits.RelayRetainedBuffers {
		t.Fatalf("resource bounds = %+v", profile)
	}
	if profile.BufferBytes != limits.RelayBufferBytes || profile.BuffersPerTunnel != limits.RelayBuffersPerTunnel {
		t.Fatalf("relay bounds = %+v", profile)
	}
}

func TestFixtureRejectsImpossibleResourceCounts(t *testing.T) {
	for _, fixture := range []Fixture{
		{P: 129},
		{Q: 257},
		{T: 257},
		{Q: 128, T: 129},
		{E0: 2, Et: 1},
	} {
		if err := fixture.Validate(); err == nil {
			t.Fatalf("accepted invalid fixture: %+v", fixture)
		}
	}
}
