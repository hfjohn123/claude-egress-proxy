package session

import (
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
	live        bool
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
	defer a.coordinator.mu.Unlock()
	return a.releaseLocked(r)
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
