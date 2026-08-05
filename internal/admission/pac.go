package admission

import (
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type PACDecision uint8

const (
	PACAllowed PACDecision = iota
	PACPrefixThrottled
	PACGlobalThrottled
	PACMapFull
	PACCapacity
)

func (d PACDecision) Allowed() bool { return d == PACAllowed }

type PAC struct {
	mu       sync.Mutex
	clock    timebase.Clock
	prefixes prefixMap
	global   bucket
	active   int
	limits   contract.Limits
}

func NewPAC(clock timebase.Clock) *PAC {
	l := contract.V1()
	return &PAC{clock: clock, prefixes: newPrefixMap(l.PACEntries, l.PACEntryTTL), global: newBucket(clock, float64(l.PACGlobalRatePerMinute)/60, l.PACGlobalBurst), limits: l}
}

type WorkLease struct {
	owner *PAC
	state *leaseState
}

func (p *PAC) Acquire(prefix Prefix) (WorkLease, PACDecision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix = canonicalPrefix(prefix)
	now := p.clock.Now()
	if p.active == p.limits.PACWorkSlots {
		return WorkLease{}, PACCapacity
	}
	e, state := p.prefixes.entry(prefix, now, func() bucket {
		return newBucket(p.clock, float64(p.limits.PACPrefixRatePerMinute)/60, p.limits.PACPrefixBurst)
	})
	if state == entryFull {
		return WorkLease{}, PACMapFull
	}
	if state == entryExpired {
		return WorkLease{}, PACPrefixThrottled
	}
	prefixBucket, global := e.bucket, p.global
	if !prefixBucket.take(now) {
		if state == entryNew {
			delete(p.prefixes.entries, prefix)
		}
		return WorkLease{}, PACPrefixThrottled
	}
	if !global.take(now) {
		if state == entryNew {
			delete(p.prefixes.entries, prefix)
		}
		return WorkLease{}, PACGlobalThrottled
	}
	e.bucket, p.global = prefixBucket, global
	p.active++
	return WorkLease{owner: p, state: &leaseState{}}, PACAllowed
}
func (l *WorkLease) Release() {
	if l == nil || l.owner == nil || l.state == nil {
		return
	}
	l.state.once.Do(func() {
		l.owner.mu.Lock()
		defer l.owner.mu.Unlock()
		if l.owner.active > 0 {
			l.owner.active--
		}
	})
}
