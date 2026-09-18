// Package session coordinates credential snapshots and CONNECT ownership.
package session

import (
	"context"
	"net"
	"reflect"
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
type TerminalEvent struct {
	HasConnect    bool
	HasClose      bool
	ConnectResult contract.ConnectResult
	CloseResult   contract.CloseResult
	Duration      time.Duration
	Bytes         contract.ByteTotals
	Sensitive     *telemetry.SensitiveMetadata
}
type Coordinator struct {
	mu                sync.Mutex
	verifier          credential.Verifier
	auth              *admission.Authentication
	snapshot          *credential.ValidatedSnapshot
	highWater         uint64
	revoked           map[credential.RecordID]struct{}
	unavailable       bool
	draining          bool
	readiness         map[contract.ReadinessPredicate]bool
	handoffs          map[*handoff]struct{}
	pending           map[*reservation]struct{}
	tunnels           map[*tunnel]struct{}
	changed           chan struct{}
	perDeviceCapacity int
	observer          func(TerminalEvent)
}

func NewCoordinator(verifier credential.Verifier, auth *admission.Authentication) *Coordinator {
	return NewCoordinatorWithCapacity(verifier, auth, contract.V1().PerDeviceCapacityDefault)
}
func NewCoordinatorWithCapacity(verifier credential.Verifier, auth *admission.Authentication, perDevice int) *Coordinator {
	if perDevice < contract.V1().PerDeviceCapacityMin || perDevice > contract.V1().PerDeviceCapacityMax {
		perDevice = contract.V1().PerDeviceCapacityDefault
	}
	return &Coordinator{verifier: verifier, auth: auth, perDeviceCapacity: perDevice, unavailable: true, revoked: make(map[credential.RecordID]struct{}), readiness: make(map[contract.ReadinessPredicate]bool), handoffs: make(map[*handoff]struct{}), pending: make(map[*reservation]struct{}), tunnels: make(map[*tunnel]struct{}), changed: make(chan struct{})}
}
func (c *Coordinator) SetTerminalObserver(observer func(TerminalEvent)) {
	c.mu.Lock()
	c.observer = observer
	c.mu.Unlock()
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
func closeResult(value string) contract.CloseResult {
	r, ok := contract.ParseCloseResult(value)
	if !ok {
		panic("session: contract")
	}
	return r
}

func (c *Coordinator) signalLocked() { close(c.changed); c.changed = make(chan struct{}) }
func (c *Coordinator) notify(e TerminalEvent) {
	c.mu.Lock()
	f := c.observer
	c.mu.Unlock()
	if f != nil {
		f(e)
	}
}
func (c *Coordinator) InstallCredentials(next credential.ValidatedSnapshot) InstallResult {
	c.mu.Lock()
	terminal := make([]TerminalEvent, 0)
	defer func() {
		c.mu.Unlock()
		for _, event := range terminal {
			c.notify(event)
		}
	}()
	if next.Generation() < c.highWater {
		return InstallRejected
	}
	if c.snapshot != nil && next.Instance() != c.snapshot.Instance() {
		return InstallRejected
	}
	if c.snapshot != nil && next.Generation() == c.snapshot.Generation() && !reflect.DeepEqual(next, *c.snapshot) {
		return InstallRejected
	}
	for _, record := range next.Records() {
		if _, wasRevoked := c.revoked[record.ID]; wasRevoked && record.State == credential.Active {
			return InstallRejected
		}
		if record.State == credential.Revoked {
			c.revoked[record.ID] = struct{}{}
		}
	}
	invalidated := make(map[credential.RecordID]struct{})
	if c.snapshot != nil {
		for _, record := range c.snapshot.Records() {
			prior, wasActive := c.snapshot.AuthHandle(record.ID)
			if !wasActive {
				continue
			}
			current, stillActive := next.AuthHandle(record.ID)
			if !stillActive || !prior.SameRecord(current) {
				invalidated[record.ID] = struct{}{}
			}
		}
	}
	recovered := c.unavailable && c.snapshot != nil
	c.snapshot = &next
	c.highWater = next.Generation()
	c.unavailable = false
	for h := range c.handoffs {
		if h.attempt != nil && !h.transferred {
			if _, ok := invalidated[h.attempt.handle.RecordID]; ok {
				h.releaseLocked()
			}
		}
	}
	for r := range c.pending {
		if _, ok := invalidated[r.handle.RecordID]; ok {
			r.releaseLocked(connect("credential_changed"))
		}
	}
	for t := range c.tunnels {
		if t.handoff != nil && t.handoff.attempt != nil {
			if _, ok := invalidated[t.handoff.attempt.handle.RecordID]; ok {
				result := closeResult("credential_revoked")
				if t.releaseLocked(result, contract.ByteTotals{}) {
					terminal = append(terminal, tunnelTerminalEvent(t, result, contract.ByteTotals{}))
				}
			}
		}
	}
	c.signalLocked()
	if recovered {
		return InstallRecovered
	}
	return InstallInstalled
}
func (c *Coordinator) SetCredentialUnavailable(generation uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if generation != c.highWater || c.unavailable {
		return false
	}
	c.unavailable = true
	for r := range c.pending {
		r.releaseLocked(connect("credential_changed"))
	}
	c.signalLocked()
	return true
}
func (c *Coordinator) Authenticate(header []byte, present bool, prefix admission.Prefix, lease admission.PublicLease, started time.Time) (Attempt, contract.AuthenticationResult, contract.ConnectResult) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.draining {
		lease.Release()
		return nil, authResult("invalid"), connect("draining")
	}
	if c.unavailable || c.snapshot == nil {
		lease.Release()
		return nil, authResult("store_unavailable"), connect("credential_store_unavailable")
	}
	id, outcome := c.verifier.Verify(*c.snapshot, header)
	if !present {
		lease.Release()
		return nil, authResult("challenge"), connect("credential_changed")
	}
	handle, ok := c.snapshot.AuthHandle(id)
	if outcome.String() != "valid" || !ok {
		if c.auth != nil {
			decision := c.auth.AdmitInvalid(prefix)
			if !decision.Allowed() {
				lease.Release()
				if decision == admission.DecisionMapFull {
					return nil, authResult("map_capacity"), connect("credential_changed")
				}
				return nil, authResult("throttled"), connect("credential_changed")
			}
		}
		lease.Release()
		return nil, outcome, connect("credential_changed")
	}
	a := &attempt{coordinator: c, lease: lease, handle: handle, started: started, prefix: prefix, live: true}
	return a, outcome, connect("established")
}
func (c *Coordinator) BeginFixed(lease Lease) (Handoff, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
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
	if !x.live || !c.handleStillActiveLocked(x.handle) {
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
		return nil, connect("draining")
	}
	if x.attempt != nil && !c.handleStillActiveLocked(x.attempt.handle) {
		return nil, connect("credential_changed")
	}
	if x.attempt == nil || !x.attached || x.released || x.transferred {
		return nil, connect("client_disconnected")
	}
	if len(c.pending)+len(c.tunnels) >= contract.V1().GlobalCapacity {
		return nil, connect("global_capacity")
	}
	owned := 0
	for r := range c.pending {
		if r.handle.Device == x.attempt.handle.Device {
			owned++
		}
	}
	for t := range c.tunnels {
		if t.handoff != nil && t.handoff.attempt != nil && t.handoff.attempt.handle.Device == x.attempt.handle.Device {
			owned++
		}
	}
	if owned >= c.perDeviceCapacity {
		return nil, connect("device_capacity")
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
		return nil, connect("draining")
	}
	if r.released || r.handoff == nil || r.handoff.released || !c.handleStillActiveLocked(r.handle) {
		return nil, connect("credential_changed")
	}
	t := &tunnel{coordinator: c, handoff: r.handoff, origin: origin}
	delete(c.pending, r)
	r.released = true
	c.tunnels[t] = struct{}{}
	c.signalLocked()
	return t, connect("established")
}

func (c *Coordinator) handleStillActiveLocked(handle credential.AuthHandle) bool {
	if c.unavailable || c.snapshot == nil {
		return false
	}
	current, ok := c.snapshot.AuthHandle(handle.RecordID)
	return ok && handle.SameRecord(current)
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
func (c *Coordinator) ReadinessReady() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, value := range contract.AllReadinessPredicates() {
		p, ok := contract.ParseReadinessPredicate(value)
		if !ok || !c.readiness[p] {
			return false
		}
	}
	return true
}
func (c *Coordinator) Snapshot() telemetry.StateSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := telemetry.StateSnapshot{PendingSetupReservations: uint64(len(c.pending)), ActiveTunnels: uint64(len(c.tunnels))}
	if !c.unavailable && c.snapshot != nil {
		s.CredentialGeneration = c.snapshot.Generation()
	}
	s.Ready = true
	for _, value := range contract.AllReadinessPredicates() {
		p, ok := contract.ParseReadinessPredicate(value)
		if !ok || !c.readiness[p] {
			s.Ready = false
			break
		}
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
	if predicate, ok := contract.ParseReadinessPredicate("drain"); ok {
		c.readiness[predicate] = false
	}
	for r := range c.pending {
		r.releaseLocked(connect("draining"))
	}
	c.signalLocked()
	return DrainStarted
}
func (c *Coordinator) WaitHijacked(ctx context.Context) bool {
	for {
		c.mu.Lock()
		empty := len(c.handoffs) == 0 && len(c.pending) == 0 && len(c.tunnels) == 0
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
	for r := range c.pending {
		r.releaseLocked(connect("draining"))
	}
	for h := range c.handoffs {
		h.releaseLocked()
	}
	terminal := make([]TerminalEvent, 0, len(c.tunnels))
	result := closeResult("shutdown_deadline")
	for t := range c.tunnels {
		if t.releaseLocked(result, contract.ByteTotals{}) {
			terminal = append(terminal, tunnelTerminalEvent(t, result, contract.ByteTotals{}))
		}
	}
	c.signalLocked()
	c.mu.Unlock()
	for _, event := range terminal {
		c.notify(event)
	}
}

var _ = time.Time{}
