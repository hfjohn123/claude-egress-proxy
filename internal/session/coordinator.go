// Package session coordinates credential snapshots and CONNECT ownership.
package session

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
)

type InstallResult uint8

const (
	InstallRejected InstallResult = iota
	InstallInstalled
	InstallRecovered
)

type DrainResult uint8

const (
	DrainAlready DrainResult = iota
	DrainStarted
)

type Lease interface{ Release() bool }
type Coordinator struct {
	mu          sync.Mutex
	verifier    credential.Verifier
	auth        *admission.Authentication
	snapshot    *credential.ValidatedSnapshot
	highWater   uint64
	unavailable bool
	draining    bool
	readiness   map[contract.ReadinessPredicate]bool
	handoffs    map[*handoff]struct{}
	pending     map[*reservation]struct{}
	tunnels     map[*tunnel]struct{}
	changed     chan struct{}
}

func NewCoordinator(verifier credential.Verifier, auth *admission.Authentication) *Coordinator {
	return &Coordinator{verifier: verifier, auth: auth, unavailable: true, readiness: make(map[contract.ReadinessPredicate]bool), handoffs: make(map[*handoff]struct{}), pending: make(map[*reservation]struct{}), tunnels: make(map[*tunnel]struct{}), changed: make(chan struct{})}
}
func connect(value string) contract.ConnectResult {
	r, ok := contract.ParseConnectResult(value)
	if !ok {
		panic("session: contract")
	}
	return r
}
func authResult(value string) contract.AuthenticationResult {
	r, ok := contract.ParseAuthenticationResult(value)
	if !ok {
		panic("session: contract")
	}
	return r
}

func (c *Coordinator) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Coordinator) InstallCredentials(next credential.ValidatedSnapshot) InstallResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if next.Generation() < c.highWater {
		return InstallRejected
	}
	if c.snapshot != nil && next.Generation() == c.snapshot.Generation() && next.Records() == nil {
		return InstallRejected
	}
	recovered := c.unavailable && c.snapshot != nil
	c.snapshot = &next
	c.highWater = next.Generation()
	c.unavailable = false
	c.signalLocked()
	if recovered {
		return InstallRecovered
	}
	return InstallInstalled
}
func (c *Coordinator) SetCredentialUnavailable(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation < c.highWater || c.unavailable {
		return false
	}
	c.unavailable = true
	for r := range c.pending {
		r.releaseLocked(connect("credential_changed"))
	}
	c.signalLocked()
	return true
}
func (c *Coordinator) Authenticate(header []byte, lease admission.PublicLease, started time.Time) (Attempt, contract.AuthenticationResult, contract.ConnectResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		lease.Release()
		return nil, authResult("invalid"), connect("draining")
	}
	if c.unavailable || c.snapshot == nil {
		lease.Release()
		return nil, authResult("invalid"), connect("credential_store_unavailable")
	}
	id, outcome := c.verifier.Verify(*c.snapshot, header)
	handle, ok := c.snapshot.AuthHandle(id)
	if outcome.String() != "valid" || !ok {
		lease.Release()
		return nil, outcome, connect("credential_changed")
	}
	a := &attempt{coordinator: c, lease: lease, handle: handle, started: started, live: true}
	return a, outcome, connect("established")
}
func (c *Coordinator) BeginFixed(lease Lease) (Handoff, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		return nil, false
	}
	h := newHandoff(c, lease, nil)
	c.handoffs[h] = struct{}{}
	c.signalLocked()
	return h, true
}
func (c *Coordinator) BeginSetup(a Attempt) (Handoff, contract.ConnectResult) {
	x, ok := a.(*attempt)
	if !ok || x == nil {
		return nil, connect("internal_error")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		x.releaseLocked(connect("draining"))
		return nil, connect("draining")
	}
	if !x.live || c.unavailable || c.snapshot == nil || x.handle.Generation != c.snapshot.Generation() {
		x.releaseLocked(connect("credential_changed"))
		return nil, connect("credential_changed")
	}
	h := newHandoff(c, &publicLease{lease: &x.lease}, x)
	x.live = false
	c.handoffs[h] = struct{}{}
	c.signalLocked()
	return h, connect("established")
}
func (c *Coordinator) Transfer(h Handoff) (Reservation, contract.ConnectResult) {
	x, ok := h.(*handoff)
	if !ok || x == nil {
		return nil, connect("internal_error")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		x.releaseLocked()
		return nil, connect("draining")
	}
	if x.attempt == nil || !x.attached || x.released {
		return nil, connect("client_disconnected")
	}
	r := &reservation{coordinator: c, handoff: x, handle: x.attempt.handle}
	c.pending[r] = struct{}{}
	x.transferred = true
	x.lease.Release()
	c.signalLocked()
	return r, connect("established")
}
func (c *Coordinator) Commit(v Reservation, origin net.Conn) (Tunnel, contract.ConnectResult) {
	r, ok := v.(*reservation)
	if !ok || r == nil || origin == nil {
		return nil, connect("internal_error")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		r.releaseLocked(connect("draining"))
		return nil, connect("draining")
	}
	if r.released || c.unavailable || c.snapshot == nil || r.handle.Generation != c.snapshot.Generation() {
		r.releaseLocked(connect("credential_changed"))
		return nil, connect("credential_changed")
	}
	t := &tunnel{coordinator: c, handoff: r.handoff, origin: origin}
	delete(c.pending, r)
	r.released = true
	c.tunnels[t] = struct{}{}
	c.signalLocked()
	return t, connect("established")
}
func (c *Coordinator) SetReadiness(p contract.ReadinessPredicate, ready bool) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.readiness[p] == ready {
		return false
	}
	c.readiness[p] = ready
	c.signalLocked()
	return true
}
func (c *Coordinator) Snapshot() telemetry.StateSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := telemetry.StateSnapshot{PendingSetupReservations: uint64(len(c.pending)), ActiveTunnels: uint64(len(c.tunnels))}
	if !c.unavailable && c.snapshot != nil {
		s.CredentialGeneration = c.snapshot.Generation()
	}
	return s
}
func (c *Coordinator) BeginDrain() DrainResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		return DrainAlready
	}
	c.draining = true
	for r := range c.pending {
		r.releaseLocked(connect("draining"))
	}
	c.signalLocked()
	return DrainStarted
}
func (c *Coordinator) WaitHijacked(ctx context.Context) bool {
	for {
		c.mu.Lock()
		empty := len(c.handoffs) == 0 && len(c.tunnels) == 0
		ch := c.changed
		c.mu.Unlock()
		if empty {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ch:
		}
	}
}
func (c *Coordinator) ForceCloseHijacked() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for h := range c.handoffs {
		h.releaseLocked()
	}
	for t := range c.tunnels {
		t.releaseLocked(contract.CloseResult(0), contract.ByteTotals{})
	}
	c.signalLocked()
}

var _ = time.Time{}
