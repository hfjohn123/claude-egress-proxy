package proxy

import (
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

var ErrNonLoopbackAdmin = errors.New("proxy: admin listener must be loopback")

func CanonicalAdminAddress(address netip.AddrPort) bool {
	if address.Port() == 0 || !address.Addr().IsValid() {
		return false
	}
	return address.Addr() == netip.MustParseAddr("127.0.0.1") || address.Addr() == netip.MustParseAddr("::1")
}

type adminListener struct {
	net.Listener
	admission *admission.Admin
}

// NewAdminListener admits at accept time, before net/http reads any bytes.
func NewAdminListener(listener net.Listener, admissionControl *admission.Admin) net.Listener {
	return &adminListener{Listener: listener, admission: admissionControl}
}
func (l *adminListener) Accept() (net.Conn, error) {
	if l.Listener == nil {
		return nil, net.ErrClosed
	}
	if !canonicalAdminListener(l.Listener) {
		return nil, ErrNonLoopbackAdmin
	}
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.admission == nil {
			_ = conn.Close()
			continue
		}
		lease, decision := l.admission.Acquire()
		if !decision.Allowed() {
			_ = conn.Close()
			continue
		}
		owned := newOwnedConn(conn, lease)
		_ = owned.SetReadDeadline(timebase.Real{}.Now().Add(10 * time.Second))
		_ = owned.SetWriteDeadline(timebase.Real{}.Now().Add(10 * time.Second))
		return owned, nil
	}
}

func canonicalAdminListener(listener net.Listener) bool {
	if listener == nil {
		return false
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || address == nil || address.Zone != "" || address.Port < 1 || address.Port > 65535 {
		return false
	}
	ip, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return false
	}
	return CanonicalAdminAddress(netip.AddrPortFrom(ip, uint16(address.Port)))
}
