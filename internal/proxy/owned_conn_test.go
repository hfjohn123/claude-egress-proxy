package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestOwnedConnReleasesAdminLeaseOnce(t *testing.T) {
	a := admission.NewAdmin(timebase.Real{})
	lease, decision := a.Acquire()
	if !decision.Allowed() {
		t.Fatal(decision)
	}
	left, right := net.Pipe()
	defer right.Close()
	c := newOwnedConn(left, lease)
	if !c.Release() || c.Release() {
		t.Fatal("release should be once")
	}
	_ = c.Close()
	if _, d := a.Acquire(); !d.Allowed() {
		t.Fatalf("lease retained: %v", d)
	}
}

var _ = time.Second
