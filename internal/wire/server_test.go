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
