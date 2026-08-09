package proxy

import (
	"net"
	"net/netip"
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
)

// NewPublicListener acquires public admission before any TLS or HTTP bytes are read.
func NewPublicListener(listener net.Listener, control *admission.Public) net.Listener {
	return NewInstrumentedPublicListener(listener, control, nil, false)
}

func NewInstrumentedPublicListener(listener net.Listener, control *admission.Public, metrics *telemetry.Metrics, tlsEnabled bool) net.Listener {
	return &publicListener{Listener: listener, control: control, metrics: metrics, tlsEnabled: tlsEnabled}
}

type publicListener struct {
	net.Listener
	control    *admission.Public
	metrics    *telemetry.Metrics
	tlsEnabled bool
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
		l.recordAdmission(decision)
		if !decision.Allowed() {
			_ = conn.Close()
			continue
		}
		return &publicConn{Conn: conn, lease: lease}, nil
	}
}

func (l *publicListener) recordAdmission(decision admission.Decision) {
	if l.metrics == nil {
		return
	}
	limiter, _ := contract.ParseLimiter("tls_handshake")
	eventName := "allowed"
	switch decision {
	case admission.DecisionAllowed:
	case admission.DecisionSaturationOverflow:
		eventName = "saturation_overflow"
	default:
		eventName = "throttled"
	}
	event, _ := contract.ParseLimiterEvent(eventName)
	l.metrics.IncLimiter(limiter, event)
	if l.tlsEnabled && !decision.Allowed() {
		result, _ := contract.ParseTLSResult("rate_limited")
		l.metrics.IncTLS(result)
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
