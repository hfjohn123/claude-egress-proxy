package policy

import (
	"net/netip"
	"testing"
)

func TestClassifyRejectsReservedAndIPv6(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want AddressClass
	}{
		{"8.8.8.8", AddressGlobalIPv4}, {"192.0.0.9", AddressGlobalIPv4},
		{"192.0.0.8", AddressDenied}, {"100.64.0.1", AddressDenied},
		{"203.0.113.1", AddressDenied}, {"::ffff:8.8.8.8", AddressDenied},
		{"2001:4860:4860::8888", AddressDenied}, {"fc00::1", AddressDenied},
	} {
		if got := Classify(netip.MustParseAddr(tc.raw)); got != tc.want {
			t.Fatalf("%s=%v want %v", tc.raw, got, tc.want)
		}
	}
}
