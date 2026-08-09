package network

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
)

// PublicSelf holds immutable public-self snapshots. Refresh serializes one
// resolver operation so concurrent callers observe a single publication.
type PublicSelf struct {
	configured []netip.Addr
	resolver   Resolver
	host       string
	mode       PublicSelfMode
	now        func() time.Time

	mu          sync.Mutex
	snapshot    PublicSelfSnapshot
	lastRefresh time.Time
	refreshing  bool
	refreshDone chan struct{}
}

type PublicSelfMode uint8

const (
	PublicSelfACME PublicSelfMode = iota
	PublicSelfSupplied
	PublicSelfLoopback
)

func NewPublicSelf(configured []netip.Addr, resolver Resolver, host string) *PublicSelf {
	return NewPublicSelfForMode(PublicSelfSupplied, configured, resolver, host)
}

func NewPublicSelfForMode(mode PublicSelfMode, configured []netip.Addr, resolver Resolver, host string) *PublicSelf {
	return &PublicSelf{configured: append([]netip.Addr(nil), configured...), resolver: resolver, host: host, mode: mode, now: time.Now}
}

func (p *PublicSelf) Snapshot() PublicSelfSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneSnapshot(p.snapshot)
}

func (p *PublicSelf) Refresh(ctx context.Context) PublicSelfSnapshot {
	return p.refresh(ctx, false)
}

// Acquire returns a snapshot fresh enough for one outbound setup, refreshing
// synchronously only when the published snapshot can no longer be trusted.
func (p *PublicSelf) Acquire(ctx context.Context) PublicSelfSnapshot {
	snapshot := p.Snapshot()
	if freshPublicSelfAt(snapshot, p.now()) {
		return snapshot
	}
	return p.Refresh(ctx)
}

func (p *PublicSelf) refresh(ctx context.Context, onlyIfDue bool) PublicSelfSnapshot {
	p.mu.Lock()
	if onlyIfDue && !p.lastRefresh.IsZero() && p.now().Sub(p.lastRefresh) < 30*time.Second {
		s := cloneSnapshot(p.snapshot)
		p.mu.Unlock()
		return s
	}
	if p.refreshing {
		done := p.refreshDone
		p.mu.Unlock()
		select {
		case <-done:
			return p.Snapshot()
		case <-ctx.Done():
			return p.Snapshot()
		}
	}
	p.refreshing = true
	p.refreshDone = make(chan struct{})
	configured := append([]netip.Addr(nil), p.configured...)
	resolver, host, mode := p.resolver, p.host, p.mode
	p.mu.Unlock()

	addresses := configured
	var resolved []netip.Addr
	var err error
	if mode != PublicSelfLoopback && resolver != nil && host != "" {
		resolved, err = resolver.LookupA(ctx, host)
		addresses = append(addresses, resolved...)
	}
	s := PublicSelfSnapshot{ObservedAt: p.now(), Coverage: "configured_and_resolved", Mode: mode}
	if err != nil || len(addresses) > 64 {
		s.Outcome = publicSelfOutcome("failure")
	} else if mode == PublicSelfLoopback {
		s.Outcome = publicSelfOutcome("success_empty")
	} else {
		seen := make(map[netip.Addr]struct{}, len(addresses))
		unsafe := false
		for _, address := range addresses {
			if address.Is4In6() {
				unsafe = true
				break
			}
			address = address.Unmap()
			if !address.Is4() || policy.Classify(address) != policy.AddressGlobalIPv4 {
				unsafe = true
				break
			}
			if _, ok := seen[address]; !ok && len(s.Addresses) < 64 {
				seen[address] = struct{}{}
				s.Addresses = append(s.Addresses, address)
			}
		}
		if unsafe {
			s.Addresses = nil
			s.Outcome = publicSelfOutcome("failure")
		} else if mode == PublicSelfACME && len(resolved) == 0 {
			s.Outcome = publicSelfOutcome("success_empty")
		} else if len(s.Addresses) == 0 {
			s.Outcome = publicSelfOutcome("success_empty")
		} else {
			s.Outcome = publicSelfOutcome("positive")
		}
	}
	p.mu.Lock()
	// A single owner is the only writer, but calculate generation while holding
	// the publication lock so snapshots remain strictly monotonic.
	s.Generation = p.snapshot.Generation + 1
	p.snapshot = s
	p.lastRefresh = s.ObservedAt
	p.refreshing = false
	close(p.refreshDone)
	p.refreshDone = nil
	p.mu.Unlock()
	return cloneSnapshot(s)
}

// RefreshIfDue avoids ambient refresh storms; callers share the one owner.
func (p *PublicSelf) RefreshIfDue(ctx context.Context) PublicSelfSnapshot {
	return p.refresh(ctx, true)
}

func publicSelfOutcome(value string) contract.PublicSelfOutcome {
	outcome, ok := contract.ParsePublicSelfOutcome(value)
	if !ok {
		panic("invalid public self outcome")
	}
	return outcome
}

func cloneSnapshot(s PublicSelfSnapshot) PublicSelfSnapshot {
	s.Addresses = append([]netip.Addr(nil), s.Addresses...)
	return s
}

// PublicSelfSnapshot is one immutable observation of local public addresses.
type PublicSelfSnapshot struct {
	Generation uint64
	ObservedAt time.Time
	Outcome    contract.PublicSelfOutcome
	Addresses  []netip.Addr
	Coverage   string
	Mode       PublicSelfMode
}

func (s PublicSelfSnapshot) addressSet() map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(s.Addresses))
	for _, address := range s.Addresses {
		set[address.Unmap()] = struct{}{}
	}
	return set
}
