package wire

import (
	"context"
	"io"
	"net"
	"net/http"
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
