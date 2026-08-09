package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

var ErrInvalidServerGroup = errors.New("proxy: invalid server group")

type ServerEndpoint struct {
	Server   *http.Server
	Listener net.Listener
}

type tlsOwnedListener struct {
	net.Listener
	config  *tls.Config
	metrics *telemetry.Metrics
}

// NewTLSOwnedListener adds server TLS without losing admission ownership.
func NewTLSOwnedListener(listener net.Listener, config *tls.Config) net.Listener {
	return NewInstrumentedTLSOwnedListener(listener, config, nil)
}

func NewInstrumentedTLSOwnedListener(listener net.Listener, config *tls.Config, metrics *telemetry.Metrics) net.Listener {
	return &tlsOwnedListener{Listener: listener, config: config, metrics: metrics}
}

func (l *tlsOwnedListener) Accept() (net.Conn, error) {
	if l == nil || l.Listener == nil || l.config == nil {
		return nil, ErrInvalidServerGroup
	}
	connection, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	owner, ok := connection.(wire.OwnedConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrInvalidServerGroup
	}
	return &tlsOwnedConn{Conn: tls.Server(connection, l.config), owner: owner, metrics: l.metrics}, nil
}

type tlsOwnedConn struct {
	*tls.Conn
	owner        wire.OwnedConn
	metrics      *telemetry.Metrics
	handshake    sync.Once
	handshakeErr error
}

func (c *tlsOwnedConn) Read(p []byte) (int, error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *tlsOwnedConn) Write(p []byte) (int, error) {
	if err := c.ensureHandshake(); err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *tlsOwnedConn) ensureHandshake() error {
	c.handshake.Do(func() {
		c.handshakeErr = c.Conn.Handshake()
		if c.metrics == nil {
			return
		}
		name := "success"
		if c.handshakeErr != nil {
			name = "tls_error"
			if timeout, ok := c.handshakeErr.(net.Error); ok && timeout.Timeout() {
				name = "timeout"
			}
		}
		result, _ := contract.ParseTLSResult(name)
		c.metrics.IncTLS(result)
	})
	return c.handshakeErr
}

func (c *tlsOwnedConn) Release() bool { return c.owner != nil && c.owner.Release() }
func (c *tlsOwnedConn) PublicLease() admission.PublicLease {
	if leased, ok := c.owner.(interface{ PublicLease() admission.PublicLease }); ok {
		return leased.PublicLease()
	}
	return admission.PublicLease{}
}

// RunServers owns all bound HTTP servers through cancellation and bounded drain.
func RunServers(ctx context.Context, endpoints []ServerEndpoint, coordinator *session.Coordinator, grace time.Duration) error {
	return RunServersWithDrain(ctx, endpoints, coordinator, grace, nil)
}

func RunServersWithDrain(ctx context.Context, endpoints []ServerEndpoint, coordinator *session.Coordinator, grace time.Duration, onDrain func(bool)) error {
	if ctx == nil || coordinator == nil || len(endpoints) == 0 || grace <= 0 {
		return ErrInvalidServerGroup
	}
	for _, endpoint := range endpoints {
		if endpoint.Server == nil || endpoint.Listener == nil {
			return ErrInvalidServerGroup
		}
	}
	errCh := make(chan error, 1)
	var serving sync.WaitGroup
	for _, endpoint := range endpoints {
		endpoint := endpoint
		serving.Add(1)
		go func() {
			defer serving.Done()
			if err := endpoint.Server.Serve(endpoint.Listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				select {
				case errCh <- err:
				default:
				}
			}
		}()
	}
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-errCh:
	}
	wasReady := coordinator.ReadinessReady()
	coordinator.BeginDrain()
	if onDrain != nil {
		onDrain(wasReady)
	}
	drainContext, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	var shutdown sync.WaitGroup
	for _, endpoint := range endpoints {
		endpoint := endpoint
		shutdown.Add(1)
		go func() {
			defer shutdown.Done()
			_ = endpoint.Server.Shutdown(drainContext)
		}()
	}
	if !coordinator.WaitHijacked(drainContext) {
		coordinator.ForceCloseHijacked()
	}
	shutdown.Wait()
	for _, endpoint := range endpoints {
		_ = endpoint.Server.Close()
		_ = endpoint.Listener.Close()
	}
	serving.Wait()
	return runErr
}
