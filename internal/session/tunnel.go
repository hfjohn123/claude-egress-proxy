package session

import (
	"context"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"net"
	"time"
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
	ok := t.releaseLocked(v, b)
	t.coordinator.mu.Unlock()
	if ok {
		t.coordinator.notify(tunnelTerminalEvent(t, v, b))
	}
	return ok
}

func tunnelTerminalEvent(t *tunnel, result contract.CloseResult, bytes contract.ByteTotals) TerminalEvent {
	event := TerminalEvent{HasClose: true, CloseResult: result, Bytes: bytes}
	if t == nil || t.handoff == nil || t.handoff.attempt == nil {
		return event
	}
	attempt := t.handoff.attempt
	if started, valid := attempt.started.(time.Time); valid {
		event.Duration = time.Since(started)
		if event.Duration < 0 {
			event.Duration = 0
		}
	}
	event.Sensitive = &telemetry.SensitiveMetadata{DestinationHostname: attempt.destination, DeviceIdentifier: attempt.handle.Device, SourcePrefix: attempt.prefix, DurationMillis: uint64(event.Duration / time.Millisecond), Bytes: bytes}
	return event
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
