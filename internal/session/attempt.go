package session

import (
	"net/netip"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
)

type Attempt interface {
	Release(contract.ConnectResult) bool
}
type attempt struct {
	coordinator *Coordinator
	lease       admission.PublicLease
	handle      credential.AuthHandle
	started     interface{}
	prefix      netip.Prefix
	destination string
	live        bool
}

func SetDestination(value Attempt, hostname string) bool {
	a, ok := value.(*attempt)
	if !ok || a == nil || a.coordinator == nil || hostname == "" {
		return false
	}
	a.coordinator.mu.Lock()
	defer a.coordinator.mu.Unlock()
	if !a.live {
		return false
	}
	a.destination = hostname
	return true
}

func SetSetupStarted(value Attempt, started time.Time) bool {
	a, ok := value.(*attempt)
	if !ok || a == nil || a.coordinator == nil || started.IsZero() {
		return false
	}
	a.coordinator.mu.Lock()
	defer a.coordinator.mu.Unlock()
	if !a.live {
		return false
	}
	a.started = started
	return true
}

type publicLease struct {
	lease    *admission.PublicLease
	released bool
}

func (l *publicLease) Release() bool {
	if l == nil || l.lease == nil || l.released {
		return false
	}
	l.released = true
	l.lease.Release()
	return true
}

func (a *attempt) Release(r contract.ConnectResult) bool {
	if a == nil || a.coordinator == nil {
		return false
	}
	a.coordinator.mu.Lock()
	ok := a.releaseLocked(r)
	a.coordinator.mu.Unlock()
	if ok {
		a.coordinator.notify(TerminalEvent{HasConnect: true, ConnectResult: r})
	}
	return ok
}
func (a *attempt) releaseLocked(contract.ConnectResult) bool {
	if !a.live {
		return false
	}
	a.live = false
	a.lease.Release()
	a.coordinator.signalLocked()
	return true
}
