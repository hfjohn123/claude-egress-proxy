package policy

import "net/netip"

type AddressClass uint8

const (
	AddressInvalid AddressClass = iota
	AddressDenied
	AddressGlobalIPv4
)

var deniedPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("240.0.0.0/4")}

func Classify(a netip.Addr) AddressClass {
	if !a.IsValid() {
		return AddressInvalid
	}
	if !a.Is4() || !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsUnspecified() {
		return AddressDenied
	}
	if a == netip.MustParseAddr("192.0.0.9") || a == netip.MustParseAddr("192.0.0.10") {
		return AddressGlobalIPv4
	}
	for _, p := range deniedPrefixes {
		if p.Contains(a) {
			return AddressDenied
		}
	}
	return AddressGlobalIPv4
}
