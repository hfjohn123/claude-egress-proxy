package proxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

type oneConnListener struct {
	conn net.Conn
	done bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.done {
		return nil, net.ErrClosed
	}
	l.done = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

type fakePublicOwnedConn struct {
	net.Conn
	released bool
	lease    admission.PublicLease
}

func (c *fakePublicOwnedConn) Release() bool {
	if c.released {
		return false
	}
	c.released = true
	return true
}
func (c *fakePublicOwnedConn) PublicLease() admission.PublicLease { return c.lease }

func TestTLSOwnedListenerPreservesConnectionOwnerAndPublicLease(t *testing.T) {
	left, right := net.Pipe()
	defer right.Close()
	owned := &fakePublicOwnedConn{Conn: left}
	listener := NewTLSOwnedListener(&oneConnListener{conn: owned}, &tls.Config{MinVersion: tls.VersionTLS12})
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := connection.(wire.OwnedConn); !ok {
		t.Fatal("TLS connection lost wire owner")
	}
	if _, ok := connection.(interface{ PublicLease() admission.PublicLease }); !ok {
		t.Fatal("TLS connection lost public lease")
	}
	if !connection.(wire.OwnedConn).Release() || !owned.released {
		t.Fatal("TLS owner did not delegate release")
	}
}

func TestRunServersServesAndDrainsOnCancellation(t *testing.T) {
	raw, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	coordinator := session.NewCoordinator(credential.Verifier{}, admission.NewAuthentication(timebase.Real{}))
	server := wire.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeAdmin(w, r, coordinator, http.StatusOK, "ok\n", "text/plain; charset=utf-8")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- RunServers(ctx, []ServerEndpoint{{Server: server, Listener: NewAdminListener(raw, admission.NewAdmin(timebase.Real{}))}}, coordinator, time.Second)
	}()
	response, err := http.Get("http://" + raw.Addr().String() + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status=%d", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("RunServers did not drain")
	}
}

func TestRunServersRejectsInvalidEndpointBeforeServe(t *testing.T) {
	if err := RunServers(context.Background(), []ServerEndpoint{{}}, nil, time.Second); err == nil {
		t.Fatal("RunServers accepted invalid endpoint")
	}
}
