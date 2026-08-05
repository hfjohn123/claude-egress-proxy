// Package certmgr owns immutable TLS serving and ACME challenge snapshots.
package certmgr

import (
	"context"
	"crypto/tls"
	"sync/atomic"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

// Provider is the public certificate boundary consumed by the public listener.
type Provider interface {
	TLSConfig() *tls.Config
	Ready(time.Time) bool
	Expiry(time.Time) time.Duration
	Start(context.Context) error
	ReloadOnce(context.Context) contract.ReloadResult
}

type snapshot struct {
	serving   *material
	challenge *material
}

type material struct {
	certificate tls.Certificate
	notBefore   time.Time
	notAfter    time.Time
}

// Manager selects current immutable serving and challenge material.
type Manager struct {
	hostname string
	now      func() time.Time
	snapshot atomic.Pointer[snapshot]
}

// New creates an empty manager. Callers install validated material before use.
func New(hostname string, now func() time.Time) *Manager {
	if now == nil {
		now = timebase.Real{}.Now
	}
	return &Manager{hostname: hostname, now: now}
}

// InstallServing atomically publishes serving material after validation.
func (m *Manager) InstallServing(certificate tls.Certificate) error {
	material, err := validateMaterial(certificate, m.hostname, m.now())
	if err != nil {
		return err
	}
	m.replace(func(next *snapshot) { next.serving = material })
	return nil
}

// InstallChallenge atomically publishes an exact-host ACME TLS-ALPN challenge.
func (m *Manager) InstallChallenge(certificate tls.Certificate) error {
	material, err := validateMaterial(certificate, m.hostname, m.now())
	if err != nil {
		return err
	}
	m.replace(func(next *snapshot) { next.challenge = material })
	return nil
}

// ClearChallenge removes an expired or completed challenge without touching serving state.
func (m *Manager) ClearChallenge() { m.replace(func(next *snapshot) { next.challenge = nil }) }

func (m *Manager) replace(change func(*snapshot)) {
	for {
		old := m.snapshot.Load()
		next := &snapshot{}
		if old != nil {
			*next = *old
		}
		change(next)
		if m.snapshot.CompareAndSwap(old, next) {
			return
		}
	}
}

func (m *Manager) Ready(now time.Time) bool {
	s := m.snapshot.Load()
	return s != nil && validAt(s.serving, now)
}

func (m *Manager) Expiry(now time.Time) time.Duration {
	s := m.snapshot.Load()
	if s == nil || s.serving == nil || !s.serving.notAfter.After(now) {
		return 0
	}
	return s.serving.notAfter.Sub(now)
}

func (m *Manager) Start(context.Context) error { return nil }

func (m *Manager) ReloadOnce(context.Context) contract.ReloadResult {
	result, _ := contract.ParseReloadResult("success")
	return result
}
