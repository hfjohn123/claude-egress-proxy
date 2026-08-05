package session

import (
	"context"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"net"
)

type Tunnel interface {
	Release(contract.CloseResult, contract.ByteTotals) bool
	Context() context.Context
}
type tunnel struct {
	coordinator *Coordinator
	handoff     *handoff
	origin      net.Conn
	released    bool
	result      contract.CloseResult
	bytes       contract.ByteTotals
}

func (t *tunnel) Release(v contract.CloseResult, b contract.ByteTotals) bool {
	if t == nil || t.coordinator == nil {
		return false
	}
	t.coordinator.mu.Lock()
	defer t.coordinator.mu.Unlock()
	return t.releaseLocked(v, b)
}
func (t *tunnel) releaseLocked(result contract.CloseResult, bytes contract.ByteTotals) bool {
	if t.released {
		return false
	}
	t.released = true
	t.result, t.bytes = result, bytes
	delete(t.coordinator.tunnels, t)
	if t.origin != nil {
		_ = t.origin.Close()
	}
	t.handoff.releaseLocked()
	t.coordinator.signalLocked()
	return true
}
func (t *tunnel) Context() context.Context {
	if t == nil || t.handoff == nil {
		return context.Background()
	}
	return t.handoff.Context()
}
