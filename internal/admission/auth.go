package admission

import (
	"sync"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type Authentication struct {
	mu       sync.Mutex
	clock    timebase.Clock
	prefixes prefixMap
	limits   contract.Limits
}

func NewAuthentication(clock timebase.Clock) *Authentication {
	l := contract.V1()
	return &Authentication{clock: clock, prefixes: newPrefixMap(l.InvalidAuthEntries, l.InvalidAuthEntryTTL), limits: l}
}
func (a *Authentication) AdmitInvalid(prefix Prefix) Decision {
	a.mu.Lock()
	defer a.mu.Unlock()
	prefix = canonicalPrefix(prefix)
	now := a.clock.Now()
	e, state := a.prefixes.entry(prefix, now, func() bucket {
		return newBucket(a.clock, float64(a.limits.InvalidAuthRatePerMinute)/60, a.limits.InvalidAuthBurst)
	})
	if state == entryFull {
		return DecisionMapFull
	}
	if state == entryExpired {
		return DecisionThrottled
	}
	if !e.bucket.take(now) {
		return DecisionThrottled
	}
	return DecisionAllowed
}
func (a *Authentication) Entries() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.prefixes.cleanup(a.clock.Now())
	return len(a.prefixes.entries)
}
