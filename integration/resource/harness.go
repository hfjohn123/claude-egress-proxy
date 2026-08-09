package resource

import "github.com/hfjohn123/claude-egress-proxy/internal/contract"

// Profile is the immutable external-harness configuration. Runtime fixtures
// derive their limits from these fixed v1 values; they do not accept supplied
// thresholds or calibrate against a proxy implementation.
type Profile struct {
	PreAuth          int
	Authenticated    int
	MapEntries       int
	BufferBytes      int
	BuffersPerTunnel int
	RetainedBuffers  int
}

// DefaultProfile snapshots the product's fixed v1 constants for comparison by
// the independent integration fixtures.
func DefaultProfile() Profile {
	limits := contract.V1()
	return Profile{
		PreAuth:          limits.PreAuthActive,
		Authenticated:    limits.GlobalCapacity,
		MapEntries:       limits.PrefixEntries,
		BufferBytes:      limits.RelayBufferBytes,
		BuffersPerTunnel: limits.RelayBuffersPerTunnel,
		RetainedBuffers:  limits.RelayRetainedBuffers,
	}
}

// LinuxBounds returns the fixed sample ceilings for a resource point.
func (f Fixture) LinuxBounds() Bounds {
	return Bounds{
		Sockets:      f.Sockets(),
		Descriptors:  f.Sockets() + 12,
		Goroutines:   64 + f.P + 3*f.Capacity(),
		HeapGrowth:   f.HeapGrowth(),
		AbsoluteHeap: 24*MiB + f.HeapGrowth(),
	}
}

// WindowsBounds returns the fixed sample ceilings for a resource point.
func (f Fixture) WindowsBounds() Bounds {
	return Bounds{
		Sockets:      f.Sockets(),
		Descriptors:  f.Sockets() + 128,
		Goroutines:   72 + f.P + 3*f.Capacity(),
		HeapGrowth:   f.HeapGrowth(),
		AbsoluteHeap: 32*MiB + f.HeapGrowth(),
	}
}

// Bounds holds external process ceilings. Descriptors means FDs on Linux and
// process handles on Windows.
type Bounds struct {
	Sockets, Descriptors, Goroutines int
	HeapGrowth, AbsoluteHeap         uint64
}
