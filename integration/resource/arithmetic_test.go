package resource

import "testing"

func TestArithmeticFixturesMatchFrozenResourceProfile(t *testing.T) {
	tests := []struct {
		name       string
		fixture    Fixture
		sockets    int
		heapGrowth uint64
	}{
		{name: "idle", fixture: Fixture{E0: 1, Et: 1}, sockets: 2, heapGrowth: 0},
		{name: "64 tunnels", fixture: Fixture{T: 64, E0: 1, Et: 1}, sockets: 130, heapGrowth: 12 * MiB},
		{name: "mixed", fixture: Fixture{P: 128, Q: 128, T: 128, E0: 1, Et: 8}, sockets: 642, heapGrowth: 56*MiB + 7*KiB},
		{name: "256 tunnels", fixture: Fixture{T: 256, E0: 1, Et: 1}, sockets: 514, heapGrowth: 48 * MiB},
		{name: "full maps", fixture: Fixture{E0: 1, Et: 12288}, sockets: 2, heapGrowth: 12287 * KiB},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.fixture.Sockets(); got != test.sockets {
				t.Fatalf("sockets = %d, want %d", got, test.sockets)
			}
			if got := test.fixture.HeapGrowth(); got != test.heapGrowth {
				t.Fatalf("heap growth = %d, want %d", got, test.heapGrowth)
			}
		})
	}
}

func TestPostCloseRetentionUsesTunnelPeakOnly(t *testing.T) {
	if got, want := RetainedBuffers(256), 512; got != want {
		t.Fatalf("retained buffers = %d, want %d", got, want)
	}
	if got, want := PostCloseHeapAllowance(256), uint64(20*MiB); got != want {
		t.Fatalf("post-close allowance = %d, want %d", got, want)
	}
}

func TestMixedStartArithmeticIsIndependentOfImplementation(t *testing.T) {
	if got, want := MixedStartAdvance(), 17200; got != want {
		t.Fatalf("start advance = %dms, want %dms", got, want)
	}
	if got, want := MixedOldestGateWait(), 12750; got != want {
		t.Fatalf("oldest gate wait = %dms, want %dms", got, want)
	}
}

func TestPlatformBoundsUseFixedOverheads(t *testing.T) {
	fixture := Fixture{P: 128, Q: 128, T: 128, E0: 1, Et: 8}
	linux := fixture.LinuxBounds()
	if linux.Sockets != 642 || linux.Descriptors != 654 || linux.Goroutines != 960 {
		t.Fatalf("linux bounds = %+v", linux)
	}
	if linux.AbsoluteHeap != 24*MiB+56*MiB+7*KiB {
		t.Fatalf("linux absolute heap = %d", linux.AbsoluteHeap)
	}
	windows := fixture.WindowsBounds()
	if windows.Sockets != 642 || windows.Descriptors != 770 || windows.Goroutines != 968 {
		t.Fatalf("windows bounds = %+v", windows)
	}
	if windows.AbsoluteHeap != 32*MiB+56*MiB+7*KiB {
		t.Fatalf("windows absolute heap = %d", windows.AbsoluteHeap)
	}
}

func TestNamedFixturesPreserveReviewedResourcePoints(t *testing.T) {
	tests := []struct {
		name string
		got  Fixture
		want Fixture
	}{
		{"idle", IdleFixture(), Fixture{E0: 1, Et: 1}},
		{"64 tunnels", Tunnel64Fixture(), Fixture{T: 64, E0: 1, Et: 1}},
		{"256 tunnels", Tunnel256Fixture(), Fixture{T: 256, E0: 1, Et: 1}},
		{"full maps", FullMapFixture(), Fixture{E0: 1, Et: 3 * 4096}},
		{"mixed", MixedFixture(), Fixture{P: 128, Q: 128, T: 128, E0: 1, Et: 8}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Fatalf("fixture = %+v, want %+v", test.got, test.want)
			}
			if err := test.got.Validate(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
