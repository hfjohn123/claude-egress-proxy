package admission

import (
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type Decision uint8

const (
	DecisionAllowed Decision = iota
	DecisionThrottled
	DecisionMapFull
	DecisionSaturationOverflow
	DecisionCapacity
)

func (d Decision) Allowed() bool { return d == DecisionAllowed || d == DecisionSaturationOverflow }
func (d Decision) String() string {
	return [...]string{"allowed", "throttled", "map_full", "saturation_overflow", "capacity"}[d]
}

type Public struct {
	mu                     sync.Mutex
	clock                  timebase.Clock
	global                 bucket
	mapped                 prefixMap
	overflow               bucket
	active, overflowActive int
	limits                 contract.Limits
}

func NewPublic(clock timebase.Clock) *Public {
	l := contract.V1()
	return &Public{clock: clock, global: newBucket(clock, l.PreAuthRatePerSecond, l.PreAuthBurst), mapped: newPrefixMap(l.PrefixEntries, l.LimiterEntryTTL), overflow: newBucket(clock, l.OverflowRatePerSecond, l.OverflowBurst), limits: l}
}

type PublicLease struct {
	owner      *Public
	prefix     Prefix
	entry      *prefixEntry
	generation uint64
	overflow   bool
	once       sync.Once
}

func (p *Public) Acquire(prefix Prefix) (PublicLease, Decision) {
	p.mu.Lock()
	defer p.mu.Unlock()
	prefix = canonicalPrefix(prefix)
	now := p.clock.Now()
	if p.active == p.limits.PreAuthActive {
		return PublicLease{}, DecisionThrottled
	}
	entry, state := p.mapped.entry(prefix, now, func() bucket {
		return newBucket(p.clock, p.limits.MappedPrefixRatePerSecond, p.limits.MappedPrefixBurst)
	})
	if state == entryExpired {
		return PublicLease{}, DecisionThrottled
	}
	if state == entryFull {
		if p.overflowActive == p.limits.OverflowActive {
			return PublicLease{}, DecisionThrottled
		}
		global, overflow := p.global, p.overflow
		if !overflow.take(now) || !global.take(now) {
			return PublicLease{}, DecisionThrottled
		}
		p.global, p.overflow = global, overflow
		p.active++
		p.overflowActive++
		return PublicLease{owner: p, prefix: prefix, overflow: true}, DecisionSaturationOverflow
	}
	if entry.active == p.limits.MappedPrefixActive {
		return PublicLease{}, DecisionThrottled
	}
	entryBucket, global := entry.bucket, p.global
	if !entryBucket.take(now) || !global.take(now) {
		if state == entryNew {
			delete(p.mapped.entries, prefix)
		}
		return PublicLease{}, DecisionThrottled
	}
	entry.bucket, p.global = entryBucket, global
	p.active++
	entry.active++
	return PublicLease{owner: p, prefix: prefix, entry: entry, generation: entry.generation}, DecisionAllowed
}

func (l *PublicLease) Release() {
	if l == nil || l.owner == nil {
		return
	}
	l.once.Do(func() {
		p := l.owner
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.active > 0 {
			p.active--
		}
		if l.overflow && p.overflowActive > 0 {
			p.overflowActive--
		}
		if !l.overflow && p.mapped.entries[l.prefix] == l.entry && l.entry.generation == l.generation && l.entry.active > 0 {
			l.entry.active--
			if !p.clock.Now().Before(l.entry.expires) && l.entry.active == 0 {
				delete(p.mapped.entries, l.prefix)
			}
		}
	})
}

func (p *Public) Active() int { p.mu.Lock(); defer p.mu.Unlock(); return p.active }
func (p *Public) Entries() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.mapped.cleanup(p.clock.Now())
	return len(p.mapped.entries)
}

var _ = time.Second
