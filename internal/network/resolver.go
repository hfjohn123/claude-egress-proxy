package network

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
)

const maxDNSAnswers = 32

var (
	ErrDNSAnswerLimit = errors.New("DNS answer limit")
	ErrDNSNonIPv4     = errors.New("DNS response contains non-IPv4 address")
)

// Resolver resolves A records only.
type Resolver interface {
	LookupA(context.Context, string) ([]netip.Addr, error)
}

// LookupFunc adapts a resolver function while enforcing response bounds.
type LookupFunc func(context.Context, string) ([]netip.Addr, error)

func (f LookupFunc) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	answers, err := f(ctx, strings.TrimSuffix(strings.ToLower(host), "."))
	if err != nil {
		return nil, err
	}
	if len(answers) > maxDNSAnswers {
		return nil, ErrDNSAnswerLimit
	}
	result := make([]netip.Addr, len(answers))
	for i, answer := range answers {
		if !answer.Is4() {
			return nil, ErrDNSNonIPv4
		}
		result[i] = answer
	}
	return result, nil
}

// SystemResolver uses an injected or system resolver, while retaining A-only
// filtering and a finite answer limit.
type SystemResolver struct{ Resolver *net.Resolver }

func (r SystemResolver) LookupA(ctx context.Context, host string) ([]netip.Addr, error) {
	resolver := r.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addresses, err := resolver.LookupNetIP(ctx, "ip4", strings.TrimSuffix(strings.ToLower(host), "."))
	if err != nil {
		return nil, err
	}
	return LookupFunc(func(context.Context, string) ([]netip.Addr, error) { return addresses, nil }).LookupA(ctx, host)
}
