// Package network supplies bounded, policy-gated outbound network operations.
package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
)

var (
	ErrUnsafeAnswer    = errors.New("unsafe DNS answer")
	ErrNoCandidates    = errors.New("no dial candidates")
	ErrSelfAddress     = errors.New("destination is public self")
	ErrPublicSelfStale = errors.New("public self snapshot stale or unavailable")
)

// ClassifyCandidates checks the complete DNS answer set before returning up to
// four first-seen public IPv4 addresses. One unsafe answer rejects all answers.
func ClassifyCandidates(addrs []netip.Addr) ([]netip.Addr, error) {
	if len(addrs) == 0 {
		return nil, ErrNoCandidates
	}
	seen := make(map[netip.Addr]struct{}, len(addrs))
	valid := make([]netip.Addr, 0, 4)
	for _, addr := range addrs {
		if addr.Is4In6() {
			return nil, ErrUnsafeAnswer
		}
		addr = addr.Unmap()
		if policy.Classify(addr) != policy.AddressGlobalIPv4 {
			return nil, ErrUnsafeAnswer
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		if len(valid) < 4 {
			valid = append(valid, addr)
		}
	}
	if len(valid) == 0 {
		return nil, ErrNoCandidates
	}
	return valid, nil
}

// Dialer performs literal tcp4 dials only. Dial is injectable for tests.
type Dialer struct {
	Source   SourceChecker
	Dial     func(context.Context, string, string, netip.Addr) (net.Conn, error)
	Snapshot func() PublicSelfSnapshot
}

// DialCandidates dials already-resolved candidates without a hostname lookup.
func (d Dialer) DialCandidates(ctx context.Context, _ string, port uint16, candidates []netip.Addr, snapshot PublicSelfSnapshot) (net.Conn, netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, contract.V1().Dial)
	defer cancel()
	if !freshPublicSelf(snapshot) {
		return nil, netip.Addr{}, ErrPublicSelfStale
	}
	candidates, err := ClassifyCandidates(candidates)
	if err != nil {
		return nil, netip.Addr{}, err
	}
	if d.Source != nil {
		if err := d.Source.Recheck(ctx); err != nil {
			return nil, netip.Addr{}, err
		}
	}
	self := snapshot.addressSet()
	dial := d.Dial
	if dial == nil {
		dial = literalDial
	}
	var last error
	for _, candidate := range candidates {
		if d.Snapshot != nil {
			current := d.Snapshot()
			if current.Generation != snapshot.Generation || !freshPublicSelf(current) {
				return nil, netip.Addr{}, ErrPublicSelfStale
			}
			snapshot = current
			self = snapshot.addressSet()
		}
		if _, ok := self[candidate]; ok {
			return nil, netip.Addr{}, ErrSelfAddress
		}
		if d.Source != nil {
			if err := d.Source.Recheck(ctx); err != nil {
				return nil, netip.Addr{}, err
			}
		}
		attemptCtx, attemptCancel := context.WithTimeout(ctx, contract.V1().Dial)
		conn, err := dial(attemptCtx, "tcp4", netip.AddrPortFrom(candidate, port).String(), sourceAddress(d.Source))
		attemptCancel()
		if err == nil {
			return conn, candidate, nil
		}
		last = err
	}
	return nil, netip.Addr{}, last
}

func freshPublicSelf(snapshot PublicSelfSnapshot) bool {
	return snapshot.Outcome.String() == "positive" && snapshot.ObservedAt.After(time.Now().Add(-5*time.Second)) && !snapshot.ObservedAt.After(time.Now().Add(time.Second))
}

func literalDial(ctx context.Context, network, address string, source netip.Addr) (net.Conn, error) {
	d := net.Dialer{}
	if source.IsValid() {
		d.LocalAddr = &net.TCPAddr{IP: net.IP(source.AsSlice())}
	}
	return d.DialContext(ctx, network, address)
}

func sourceAddress(source SourceChecker) netip.Addr {
	if source == nil {
		return netip.Addr{}
	}
	return source.Address()
}
