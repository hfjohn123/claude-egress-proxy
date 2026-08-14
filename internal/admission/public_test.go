package admission

import (
	"net/netip"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestPublicAcquireUsesNoRefundStartTokens(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	p := NewPublic(clock)
	prefix := netip.MustParsePrefix("198.51.100.1/32")
	for range 10 { // mapped burst
		lease, decision := p.Acquire(prefix)
		if !decision.Allowed() {
			t.Fatalf("Acquire() = %v", decision)
		}
		lease.Release()
	}
	if _, decision := p.Acquire(prefix); decision != DecisionThrottled {
		t.Fatalf("post-burst decision = %v, want throttled", decision)
	}
}

func TestPublicFailedCompositeDoesNotSpendGlobalToken(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	p := NewPublic(clock)
	prefix := netip.MustParsePrefix("198.51.100.2/32")
	for range 10 {
		lease, _ := p.Acquire(prefix)
		lease.Release()
	}
	for i := range 29 {
		other := netip.PrefixFrom(netip.AddrFrom4([4]byte{203, 0, 113, byte(1 + i)}), 32)
		lease, decision := p.Acquire(other)
		if !decision.Allowed() {
			t.Fatalf("setup acquire = %v", decision)
		}
		lease.Release()
	}
	if _, decision := p.Acquire(prefix); decision != DecisionThrottled {
		t.Fatalf("prefix decision = %v", decision)
	}
	if _, decision := p.Acquire(netip.MustParsePrefix("203.0.113.250/32")); !decision.Allowed() {
		t.Fatalf("global token spent by failed composite: %v", decision)
	}
}

func TestPublicLeaseReleaseIsExactlyOnce(t *testing.T) {
	p := NewPublic(newTestClock(time.Unix(0, 0)))
	lease, decision := p.Acquire(netip.MustParsePrefix("198.51.100.9/32"))
	if !decision.Allowed() {
		t.Fatal(decision)
	}
	lease.Release()
	lease.Release()
	if got := p.Active(); got != 0 {
		t.Fatalf("active = %d, want 0", got)
	}
}

func TestPublicCopiedLeaseReleasesExactlyOnce(t *testing.T) {
	p := NewPublic(newTestClock(time.Unix(0, 0)))
	lease, d := p.Acquire(netip.MustParsePrefix("198.51.100.10/32"))
	if !d.Allowed() {
		t.Fatal(d)
	}
	other, d := p.Acquire(netip.MustParsePrefix("198.51.100.11/32"))
	if !d.Allowed() {
		t.Fatal(d)
	}
	copy := lease
	lease.Release()
	copy.Release()
	if got := p.Active(); got != 1 {
		t.Fatalf("active = %d, want 1", got)
	}
	other.Release()
}

func TestPublicExpiredActivePrefixRenewsWithoutReset(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	p := NewPublic(clock)
	p.limits.LimiterEntryTTL = time.Minute
	p.limits.MappedPrefixRatePerSecond = 0
	p.mapped.ttl = time.Minute
	prefix := netip.MustParsePrefix("198.51.100.20/32")
	first, decision := p.Acquire(prefix)
	if !decision.Allowed() {
		t.Fatal(decision)
	}
	entry := p.mapped.entries[prefix]
	if entry == nil {
		t.Fatal("mapped entry missing")
	}
	generation := entry.generation
	tokens := entry.bucket.tokens
	originalExpiry := entry.expires
	clock.Advance(time.Minute)
	second, decision := p.Acquire(prefix)
	if decision != DecisionAllowed {
		t.Fatalf("post-TTL decision = %v, want allowed", decision)
	}
	if p.mapped.entries[prefix] != entry || entry.generation != generation {
		t.Fatal("renewal replaced the retained entry generation")
	}
	if !entry.expires.After(originalExpiry) || !entry.expires.Equal(clock.Now().Add(time.Minute)) {
		t.Fatalf("renewed expiry = %v, original = %v", entry.expires, originalExpiry)
	}
	if entry.bucket.tokens != tokens-1 {
		t.Fatalf("bucket tokens = %v, want %v", entry.bucket.tokens, tokens-1)
	}
	if entry.active != 2 || p.Active() != 2 {
		t.Fatalf("entry active = %d, public active = %d", entry.active, p.Active())
	}
	second.Release()
	first.Release()
	if entry.active != 0 || p.Active() != 0 {
		t.Fatalf("released entry active = %d, public active = %d", entry.active, p.Active())
	}
}

type testClock struct{ now time.Time }

func newTestClock(now time.Time) *testClock                { return &testClock{now: now} }
func (c *testClock) Now() time.Time                        { return c.now }
func (c *testClock) Advance(d time.Duration)               { c.now = c.now.Add(d) }
func (*testClock) NewTimer(time.Duration) timebase.Timer   { panic("unused") }
func (*testClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }
