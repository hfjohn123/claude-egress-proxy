package session

import (
	"context"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
)

type Reservation interface {
	Release(contract.ConnectResult) bool
	Context() context.Context
}
type reservation struct {
	coordinator *Coordinator
	handoff     *handoff
	handle      credential.AuthHandle
	released    bool
	result      contract.ConnectResult
}

func (r *reservation) Release(v contract.ConnectResult) bool {
	if r == nil || r.coordinator == nil {
		return false
	}
	r.coordinator.mu.Lock()
	defer r.coordinator.mu.Unlock()
	return r.releaseLocked(v)
}
func (r *reservation) releaseLocked(result contract.ConnectResult) bool {
	if r.released {
		return false
	}
	r.released = true
	r.result = result
	delete(r.coordinator.pending, r)
	r.handoff.releaseLocked()
	r.coordinator.signalLocked()
	return true
}
func (r *reservation) Context() context.Context {
	if r == nil || r.handoff == nil {
		return context.Background()
	}
	return r.handoff.Context()
}
