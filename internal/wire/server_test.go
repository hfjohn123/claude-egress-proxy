package wire

import (
	"context"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

type ownerConn struct {
	net.Conn
	releases int
}

func (c *ownerConn) Release() bool { c.releases++; return c.releases == 1 }

func TestServerHasBoundedHTTP1OwnerBridge(t *testing.T) {
	s := NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if s.ReadHeaderTimeout != 10*time.Second || s.WriteTimeout != 10*time.Second || s.MaxHeaderBytes != 16<<10 || s.ReadTimeout != 0 || s.IdleTimeout != 0 || !s.DisableGeneralOptionsHandler || s.ErrorLog == nil || !s.Protocols.HTTP1() || s.Protocols.HTTP2() {
		t.Fatalf("unexpected server %#v", s)
	}
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	c := &ownerConn{Conn: a}
	r := (&http.Request{}).WithContext(s.ConnContext(context.Background(), c))
	if got, ok := ConnectionOwner(r); !ok || got != c {
		t.Fatalf("owner=%v ok=%v", got, ok)
	}
	r = (&http.Request{}).WithContext(s.ConnContext(context.Background(), b))
	if _, ok := ConnectionOwner(r); ok {
		t.Fatal("unowned connection admitted")
	}
	_ = io.Discard
}

func TestServerAbortsUnownedConnectionWithoutCallingHandler(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	listener := &oneConnListener{conn: server}
	var calls atomic.Int32
	s := NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	done := make(chan error, 1)
	go func() { done <- s.Serve(listener) }()
	if _, err := io.WriteString(client, "GET / HTTP/1.1\r\nHost: example\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if n, err := client.Read(buf); n != 0 || err != io.EOF {
		t.Fatalf("read %d, %v; want closed without response", n, err)
	}
	if calls.Load() != 0 {
		t.Fatal("unowned connection reached supplied handler")
	}
	if err := <-done; err == nil {
		t.Fatal("Serve unexpectedly returned nil")
	}
}

func TestServerOwnedLiteralParserMatrix(t *testing.T) {
	tests := []struct {
		name, raw string
		reach     bool
		decision  Decision
	}{
		{"http10", "GET / HTTP/1.0\r\n\r\n", true, DecisionHTTPVersionNotSupported},
		{"other minor", "GET / HTTP/1.2\r\nHost: x\r\n\r\n", true, DecisionHTTPVersionNotSupported},
		{"origin", "GET /x HTTP/1.1\r\nHost: x\r\n\r\n", true, DecisionAllow},
		{"authority", "CONNECT x:443 HTTP/1.1\r\nHost: ignored\r\n\r\n", true, DecisionAllow},
		{"absolute", "GET http://x/a HTTP/1.1\r\nHost: x\r\n\r\n", true, DecisionAllow},
		{"asterisk", "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", true, DecisionAllow},
		{"content length", "GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", true, DecisionBadRequest},
		{"expect", "GET / HTTP/1.1\r\nHost: x\r\nExpect: 100-continue\r\n\r\n", true, DecisionBadRequest},
		{"upgrade", "GET / HTTP/1.1\r\nHost: x\r\nConnection: upgrade\r\nUpgrade: x\r\n\r\n", true, DecisionBadRequest},
		{"duplicate host", "GET / HTTP/1.1\r\nHost: x\r\nHost: y\r\n\r\n", false, 0},
		{"malformed host", "GET / HTTP/1.1\r\nHost: x y\r\n\r\n", false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls atomic.Int32
			var got Decision
			var same atomic.Bool
			owner := serveOne(t, tt.raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, got = AdaptRequest(r)
				o, ok := ConnectionOwner(r)
				same.Store(ok && o != nil)
				w.Header().Set("Connection", "close")
			}))
			if (calls.Load() == 1) != tt.reach {
				t.Fatalf("calls=%d reach=%v", calls.Load(), tt.reach)
			}
			if tt.reach && (got != tt.decision || !same.Load()) {
				t.Fatalf("decision=%v same=%v", got, same.Load())
			}
			if owner.releases != 1 {
				t.Fatalf("releases=%d", owner.releases)
			}
		})
	}
}

type trackedOwnedConn struct {
	net.Conn
	releases int
}

func (c *trackedOwnedConn) Release() bool { c.releases++; return c.releases == 1 }
func (c *trackedOwnedConn) Close() error  { c.Release(); return c.Conn.Close() }

func serveOne(t *testing.T, raw string, handler http.Handler) *trackedOwnedConn {
	t.Helper()
	client, server := net.Pipe()
	owner := &trackedOwnedConn{Conn: server}
	listener := &oneConnListener{conn: owner}
	s := NewServer(handler)
	done := make(chan error, 1)
	go func() { done <- s.Serve(listener) }()
	if _, err := io.WriteString(client, raw); err != nil {
		t.Fatal(err)
	}
	_ = client.SetReadDeadline(time.Now().Add(time.Second))
	_, _ = io.ReadAll(client)
	_ = client.Close()
	<-done
	return owner
}

type oneConnListener struct {
	conn net.Conn
	used bool
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	if l.used {
		return nil, net.ErrClosed
	}
	l.used = true
	return l.conn, nil
}
func (l *oneConnListener) Close() error   { return nil }
func (l *oneConnListener) Addr() net.Addr { return dummyAddr("one") }

type dummyAddr string

func (a dummyAddr) Network() string { return string(a) }
func (a dummyAddr) String() string  { return string(a) }
