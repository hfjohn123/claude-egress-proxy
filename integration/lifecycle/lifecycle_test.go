package lifecycle

import (
	"context"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
)

type lease struct{ released bool }

func (l *lease) Release() bool {
	if l.released {
		return false
	}
	l.released = true
	return true
}

func TestDrainForceClosesOutstandingHijackedOwner(t *testing.T) {
	coordinator := session.NewCoordinator(credential.Verifier{}, nil)
	owner := &lease{}
	if _, ok := coordinator.BeginFixed(owner); !ok {
		t.Fatal("fixed owner was not accepted")
	}
	if got := coordinator.BeginDrain(); got != session.DrainStarted {
		t.Fatalf("first drain = %v, want started", got)
	}
	if got := coordinator.BeginDrain(); got != session.DrainAlready {
		t.Fatalf("second drain = %v, want already", got)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if coordinator.WaitHijacked(canceled) {
		t.Fatal("drain completed while hijacked owner remains")
	}
	coordinator.ForceCloseHijacked()
	if !owner.released {
		t.Fatal("force-close did not release hijacked owner")
	}
	if !coordinator.WaitHijacked(context.Background()) {
		t.Fatal("drain did not complete after force-close")
	}
}
