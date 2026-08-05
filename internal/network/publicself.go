package network

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

// PublicSelf holds immutable public-self snapshots. Refresh serializes one
// resolver operation so concurrent callers observe a single publication.
type PublicSelf struct {
	configured []netip.Addr
	resolver   Resolver
	host       string
	now        func() time.Time

	mu       sync.Mutex
	snapshot PublicSelfSnapshot
}

func NewPublicSelf(configured []netip.Addr, resolver Resolver, host string) *PublicSelf {
	return &PublicSelf{configured: append([]netip.Addr(nil), configured...), resolver: resolver, host: host, now: time.Now}
}

func (p *PublicSelf) Snapshot() PublicSelfSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	return cloneSnapshot(p.snapshot)
}

func (p *PublicSelf) Refresh(ctx context.Context) PublicSelfSnapshot {
	p.mu.Lock()
	defer p.mu.Unlock()
	addresses := append([]netip.Addr(nil), p.configured...)
	var err error
	if p.resolver != nil && p.host != "" {
		var resolved []netip.Addr
		resolved, err = p.resolver.LookupA(ctx, p.host)
		addresses = append(addresses, resolved...)
	}
	s := PublicSelfSnapshot{Generation: p.snapshot.Generation + 1, ObservedAt: p.now(), Coverage: "configured_and_resolved"}
	if err != nil {
		s.Outcome = publicSelfOutcome("failure")
	} else {
		seen := make(map[netip.Addr]struct{}, len(addresses))
		for _, address := range addresses {
			address = address.Unmap()
			if !address.Is4() {
				continue
			}
			if _, ok := seen[address]; !ok && len(s.Addresses) < 64 {
				seen[address] = struct{}{}
				s.Addresses = append(s.Addresses, address)
			}
		}
		if len(s.Addresses) == 0 {
			s.Outcome = publicSelfOutcome("success_empty")
		} else {
			s.Outcome = publicSelfOutcome("positive")
		}
	}
	p.snapshot = s
	return cloneSnapshot(s)
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
}

func (s PublicSelfSnapshot) addressSet() map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(s.Addresses))
	for _, address := range s.Addresses {
		set[address.Unmap()] = struct{}{}
	}
	return set
}
