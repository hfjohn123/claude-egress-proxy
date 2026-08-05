package admission

import (
	"net/netip"
	"time"
)

// Prefix is canonical source aggregation: IPv4 /32 and IPv6 /64.
type Prefix = netip.Prefix

func Aggregate(address netip.Addr) Prefix {
	if address.Is4() {
		return netip.PrefixFrom(address, 32).Masked()
	}
	return netip.PrefixFrom(address, 64).Masked()
}

func canonicalPrefix(prefix Prefix) Prefix {
	if !prefix.IsValid() {
		return prefix
	}
	return Aggregate(prefix.Addr())
}

type prefixEntry struct {
	bucket     bucket
	expires    time.Time
	active     int
	generation uint64
}

type prefixMap struct {
	entries map[Prefix]*prefixEntry
	cap     int
	ttl     time.Duration
}

func newPrefixMap(capacity int, ttl time.Duration) prefixMap {
	return prefixMap{entries: make(map[Prefix]*prefixEntry, capacity), cap: capacity, ttl: ttl}
}

func (m *prefixMap) cleanup(now time.Time) {
	for key, entry := range m.entries {
		if !now.Before(entry.expires) && entry.active == 0 {
			delete(m.entries, key)
		}
	}
}

func (m *prefixMap) entry(key Prefix, now time.Time, makeBucket func() bucket) (*prefixEntry, entryState) {
	m.cleanup(now)
	if entry := m.entries[key]; entry != nil {
		if !now.Before(entry.expires) {
			return entry, entryExpired
		}
		return entry, entryExisting
	}
	if len(m.entries) == m.cap {
		return nil, entryFull
	}
	entry := &prefixEntry{bucket: makeBucket(), expires: now.Add(m.ttl), generation: 1}
	m.entries[key] = entry
	return entry, entryNew
}

type entryState uint8

const (
	entryNew entryState = iota
	entryExisting
	entryExpired
	entryFull
)
