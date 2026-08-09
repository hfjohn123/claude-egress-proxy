package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

// SourceChecker is the immediate source-assignment gate used before each dial.
type SourceChecker interface {
	Recheck(context.Context) error
	Address() netip.Addr
}

var ErrSourceUnavailable = errors.New("outbound source IPv4 unavailable")

// SourceMonitor verifies that an optional configured local address remains
// assigned. It never chooses a replacement address.
type SourceMonitor struct {
	Configured netip.Addr
	Clock      timebase.Clock
	Probe      func(context.Context, netip.Addr) error
	Publish    func(bool)

	mu    sync.Mutex
	ready bool
}

func (m *SourceMonitor) Address() netip.Addr { return m.Configured }

// Recheck is used immediately before each outbound connect.
func (m *SourceMonitor) Recheck(ctx context.Context) error {
	if !m.Configured.IsValid() {
		return nil
	}
	probe := m.Probe
	if probe == nil {
		probe = assigned
	}
	err := probe(ctx, m.Configured)
	m.setReady(err == nil)
	if err != nil {
		return ErrSourceUnavailable
	}
	return nil
}

// Run checks once at startup and then at exact five-second ticker boundaries.
func (m *SourceMonitor) Run(ctx context.Context) {
	_ = m.Recheck(ctx)
	if !m.Configured.IsValid() || m.Clock == nil {
		return
	}
	ticker := m.Clock.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			_ = m.Recheck(ctx)
		}
	}
}

func (m *SourceMonitor) setReady(ready bool) {
	m.mu.Lock()
	changed := m.ready != ready
	m.ready = ready
	m.mu.Unlock()
	if changed && m.Publish != nil {
		m.Publish(ready)
	}
}

func assigned(_ context.Context, want netip.Addr) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err == nil && prefix.Addr().Unmap() == want {
				return nil
			}
		}
	}
	return ErrSourceUnavailable
}
