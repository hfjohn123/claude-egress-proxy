package session

import (
	"bufio"
	"context"
	"errors"
	"net"
)

type Handoff interface {
	Attach(net.Conn, *bufio.ReadWriter) error
	Release() bool
	Context() context.Context
}
type handoff struct {
	coordinator                     *Coordinator
	lease                           Lease
	attempt                         *attempt
	conn                            net.Conn
	rw                              *bufio.ReadWriter
	attached, transferred, released bool
	ctx                             context.Context
	cancel                          context.CancelFunc
}

func newHandoff(c *Coordinator, l Lease, a *attempt) *handoff {
	ctx, cancel := context.WithCancel(context.Background())
	return &handoff{coordinator: c, lease: l, attempt: a, ctx: ctx, cancel: cancel}
}
func (h *handoff) Attach(conn net.Conn, rw *bufio.ReadWriter) error {
	if h == nil || conn == nil || rw == nil {
		return errors.New("session: invalid handoff")
	}
	h.coordinator.mu.Lock()
	defer h.coordinator.mu.Unlock()
	if h.attached || h.released {
		return errors.New("session: handoff closed")
	}
	h.conn, h.rw, h.attached = conn, rw, true
	h.coordinator.signalLocked()
	return nil
}
func (h *handoff) Release() bool {
	if h == nil || h.coordinator == nil {
		return false
	}
	h.coordinator.mu.Lock()
	defer h.coordinator.mu.Unlock()
	return h.releaseLocked()
}
func (h *handoff) releaseLocked() bool {
	if h.released {
		return false
	}
	h.released = true
	delete(h.coordinator.handoffs, h)
	h.cancel()
	if h.conn != nil {
		_ = h.conn.Close()
	}
	if !h.transferred && h.lease != nil {
		h.lease.Release()
	}
	h.coordinator.signalLocked()
	return true
}
func (h *handoff) Context() context.Context {
	if h == nil {
		return context.Background()
	}
	return h.ctx
}
