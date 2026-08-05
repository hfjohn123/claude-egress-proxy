package admission

import (
	"net/netip"
	"testing"
	"time"
)

func TestPrefixMapKeepsExpiredActiveGeneration(t *testing.T) {
	clock := newTestClock(time.Unix(0, 0))
	m := newPrefixMap(1, time.Minute)
	key := netip.MustParsePrefix("198.51.100.1/32")
	e, state := m.entry(key, clock.Now(), func() bucket { return newBucket(clock, 1, 1) })
	if state != entryNew {
		t.Fatal(state)
	}
	e.active = 1
	clock.Advance(time.Minute)
	if _, state = m.entry(key, clock.Now(), func() bucket { return newBucket(clock, 1, 1) }); state != entryExpired {
		t.Fatal(state)
	}
	if got := len(m.entries); got != 1 {
		t.Fatalf("entries = %d", got)
	}
	e.active = 0
	m.cleanup(clock.Now())
	if got := len(m.entries); got != 0 {
		t.Fatalf("entries = %d", got)
	}
}
