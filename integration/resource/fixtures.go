// Package resource keeps the independent, fixed arithmetic used by external
// resource fixtures. It does not configure or inspect the proxy process.
package resource

import (
	"fmt"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

const (
	KiB uint64 = 1 << 10
	MiB        = 1 << 20

	// SyntheticGlobalIPv4 is mapped by the tagged external test harness only.
	// It belongs to test code, never a production binary or configuration.
	SyntheticGlobalIPv4 = "93.184.216.34"
)

// Fixture declares a single, externally observed resource measurement point.
// P, Q, T, E0, and Et retain the names and definitions from the reviewed spec.
type Fixture struct {
	P, Q, T int
	E0, Et  int
}

// IdleFixture is the clean external-process baseline.
func IdleFixture() Fixture { return Fixture{E0: 1, Et: 1} }

// Tunnel64Fixture holds the first fixed tunnel resource point.
func Tunnel64Fixture() Fixture { return Fixture{T: 64, E0: 1, Et: 1} }

// Tunnel256Fixture holds the maximum authenticated tunnel point.
func Tunnel256Fixture() Fixture { return Fixture{T: contract.V1().GlobalCapacity, E0: 1, Et: 1} }

// FullMapFixture holds the independent three-map saturation point.
func FullMapFixture() Fixture { return Fixture{E0: 1, Et: 3 * contract.V1().PrefixEntries} }

// MixedFixture holds P=Q=T=128, whose socket formula is 642.
func MixedFixture() Fixture {
	limits := contract.V1()
	return Fixture{P: limits.PreAuthActive, Q: limits.GlobalCapacity / 2, T: limits.GlobalCapacity / 2, E0: 1, Et: 8}
}

// Validate rejects profiles outside the fixed v1 resource envelope.
func (f Fixture) Validate() error {
	limits := contract.V1()
	if f.P < 0 || f.P > limits.PreAuthActive {
		return fmt.Errorf("P outside [0,%d]", limits.PreAuthActive)
	}
	if f.Q < 0 || f.T < 0 || f.Q+f.T > limits.GlobalCapacity {
		return fmt.Errorf("Q+T outside [0,%d]", limits.GlobalCapacity)
	}
	if f.E0 < 0 || f.Et < f.E0 || f.Et > 3*limits.PrefixEntries {
		return fmt.Errorf("map entries outside [E0,%d]", 3*limits.PrefixEntries)
	}
	return nil
}

// Capacity is the authenticated capacity consumed by pending and established
// connections.
func (f Fixture) Capacity() int { return f.Q + f.T }

// EntryDelta is the post-baseline map allocation count.
func (f Fixture) EntryDelta() int {
	if f.Et <= f.E0 {
		return 0
	}
	return f.Et - f.E0
}

// Sockets implements S = 2 + P + 2*(Q+T).
func (f Fixture) Sockets() int { return 2 + f.P + 2*f.Capacity() }

// HeapGrowth implements M = 128 KiB*(P+C) + 64 KiB*T + 1 KiB*Ed.
func (f Fixture) HeapGrowth() uint64 {
	return 128*KiB*uint64(f.P+f.Capacity()) + 64*KiB*uint64(f.T) + KiB*uint64(f.EntryDelta())
}

// RetainedBuffers implements R = min(2*Tpeak, 512).
func RetainedBuffers(tunnelPeak int) int {
	if tunnelPeak <= 0 {
		return 0
	}
	retained := contract.V1().RelayBuffersPerTunnel * tunnelPeak
	if retained > contract.V1().RelayRetainedBuffers {
		return contract.V1().RelayRetainedBuffers
	}
	return retained
}

// PostCloseHeapAllowance implements 32 KiB*R + 4 MiB.
func PostCloseHeapAllowance(tunnelPeak int) uint64 {
	return 32*KiB*uint64(RetainedBuffers(tunnelPeak)) + 4*MiB
}

// MixedStartAdvance is the fixed (384 - 40) / 20 second schedule in ms.
func MixedStartAdvance() int { return (384 - 40) * 1000 / 20 }

// MixedOldestGateWait is the fixed raw wait of start 129 in ms.
func MixedOldestGateWait() int { return 12750 }
