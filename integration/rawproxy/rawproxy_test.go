// Package rawproxy exercises literal HTTP bytes at the standard-library proxy
// boundary without any external network dependency.
package rawproxy

import (
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

func TestRawCONNECTUsesImmutableTargetAndConsumesAuthorization(t *testing.T) {
	var calls atomic.Int32
	owner := serveOne(t, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: conflicting.example\r\nProxy-Authorization: Basic c2VjcmV0\r\n\r\nGET /second HTTP/1.1\r\nHost: allowed.example\r\n\r\n", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		r.Host, r.URL.Host = "poison.invalid", "poison.invalid"
		request, decision := wire.AdaptRequest(r)
		if decision != wire.DecisionAllow || request.RequestURI != "allowed.example:443" || request.Target != wire.TargetAuthority {
			t.Fatalf("adapted request = %+v, decision=%v", request, decision)
		}
		value, count := wire.TakeAuthorization(r.Header, "Proxy-Authorization")
		if count != 1 || string(value) != "Basic c2VjcmV0" || len(r.Header.Values("Proxy-Authorization")) != 0 {
			t.Fatalf("authorization count=%d value=%q remaining=%v", count, value, r.Header.Values("Proxy-Authorization"))
		}
		w.Header().Set("Connection", "close")
		w.WriteHeader(http.StatusNoContent)
	}))
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want one request per connection", calls.Load())
	}
	if !owner.Released() {
		t.Fatal("owned connection was not released")
	}
}

func TestRawDuplicateHostIsFrameworkRejected(t *testing.T) {
	var calls atomic.Int32
	owner := serveOne(t, "GET / HTTP/1.1\r\nHost: first.example\r\nHost: second.example\r\n\r\n", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls.Add(1)
	}))
	if calls.Load() != 0 {
		t.Fatal("duplicate Host reached application handler")
	}
	if !owner.Released() {
		t.Fatal("framework-rejected owner was not released")
	}
}

type ownedConn struct {
	net.Conn
	once     sync.Once
	released atomic.Bool
}

func (c *ownedConn) Release() bool {
	did := false
	c.once.Do(func() {
		c.released.Store(true)
		did = true
	})
	return did
}

func (c *ownedConn) Released() bool { return c.released.Load() }

func (c *ownedConn) Close() error {
	c.Release()
	return c.Conn.Close()
}

type oneListener struct {
	conn net.Conn
	once sync.Once
}

func (l *oneListener) Accept() (net.Conn, error) {
	accepted := false
	l.once.Do(func() { accepted = true })
	if !accepted {
		return nil, net.ErrClosed
	}
	return l.conn, nil
}
func (l *oneListener) Close() error   { return nil }
func (l *oneListener) Addr() net.Addr { return rawAddr("rawproxy") }

type rawAddr string

func (a rawAddr) Network() string { return string(a) }
func (a rawAddr) String() string  { return string(a) }

func serveOne(t *testing.T, request string, handler http.Handler) *ownedConn {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	owner := &ownedConn{Conn: server}
	listener := &oneListener{conn: owner}
	httpServer := wire.NewServer(handler)
	done := make(chan error, 1)
	go func() { done <- httpServer.Serve(listener) }()
	written := make(chan error, 1)
	go func() { _, err := io.WriteString(client, request); written <- err }()
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(client)
	if err := <-written; err != nil && !strings.Contains(err.Error(), "closed pipe") {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("HTTP server did not stop after one raw connection")
	}
	return owner
}
