package proxy

import (
	"net"
	"net/netip"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

func TestAdminListenerReturnsOwnedConnection(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	l := NewAdminListener(base, admission.NewAdmin(timebase.Real{}))
	done := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); done <- c }()
	c, err := net.Dial("tcp", base.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	accepted := <-done
	defer accepted.Close()
	if _, ok := accepted.(wire.OwnedConn); !ok {
		t.Fatalf("%T is not wire.OwnedConn", accepted)
	}
}

func TestCanonicalAdminAddressRequiresExactLoopback(t *testing.T) {
	for _, text := range []string{"127.0.0.1:1", "[::1]:1"} {
		address := netip.MustParseAddrPort(text)
		if !CanonicalAdminAddress(address) {
			t.Fatalf("%s rejected", text)
		}
	}
	for _, text := range []string{"127.0.0.2:1", "[::ffff:127.0.0.1]:1", "127.0.0.1:0"} {
		address := netip.MustParseAddrPort(text)
		if CanonicalAdminAddress(address) {
			t.Fatalf("%s accepted", text)
		}
	}
}
