package proxy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
)

// NewPublicListener acquires public admission before any TLS or HTTP bytes are read.
func NewPublicListener(listener net.Listener, control *admission.Public) net.Listener {
	return &publicListener{Listener: listener, control: control}
}

type publicListener struct {
	net.Listener
	control *admission.Public
}

func (l *publicListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.control == nil {
			_ = conn.Close()
			continue
		}
		address, ok := remoteAddress(conn.RemoteAddr())
		if !ok {
			_ = conn.Close()
			continue
		}
		lease, decision := l.control.Acquire(admission.Aggregate(address))
		if !decision.Allowed() {
			_ = conn.Close()
			continue
		}
		return &publicConn{Conn: conn, lease: lease}, nil
	}
}

func remoteAddress(addr net.Addr) (netip.Addr, bool) {
	if addr == nil {
		return netip.Addr{}, false
	}
	p, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return p.Addr().Unmap(), true
}

type publicConn struct {
	net.Conn
	lease admission.PublicLease
	once  sync.Once
}

func (c *publicConn) Release() bool {
	did := false
	if c != nil {
		c.once.Do(func() { c.lease.Release(); did = true })
	}
	return did
}
func (c *publicConn) Close() error {
	if c == nil {
		return nil
	}
	err := c.Conn.Close()
	c.Release()
	return err
}
func (c *publicConn) PublicLease() admission.PublicLease { return c.lease }
