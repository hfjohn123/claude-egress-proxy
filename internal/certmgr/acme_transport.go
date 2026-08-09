package certmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const (
	acmeHeaderLimit = 32 << 10
	acmeBodyLimit   = 1 << 20
)

var errUnsafeACMEEndpoint = errors.New("unsafe acme endpoint")
var errACMEBodyLimit = errors.New("acme response body limit")

// DirectTransportConfig contains the only dependencies used for CA traffic.
// Resolver and Dial are injectable so ACME never inherits ambient proxy or DNS state.
type DirectTransportConfig struct {
	DirectoryURL string
	Resolver     network.Resolver
	Dial         func(context.Context, string, string, netip.Addr) (net.Conn, error)
	RootCAs      *x509.CertPool
	// PublicSelf, when supplied, must return a fresh positive snapshot before
	// the CA endpoint may be resolved or dialed.
	PublicSelf func() network.PublicSelfSnapshot
	Now        func() time.Time
}

// NewDirectTransport returns a proxy-free, literal-dialing ACME transport.
func NewDirectTransport(config DirectTransportConfig) (*http.Transport, error) {
	if err := validateACMEURL(config.DirectoryURL); err != nil {
		return nil, err
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = network.SystemResolver{}
	}
	dial := config.Dial
	if dial == nil {
		dial = func(ctx context.Context, networkName, address string, _ netip.Addr) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, networkName, address)
		}
	}
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, networkName, address string) (net.Conn, error) {
			if config.PublicSelf != nil {
				now := timebase.Real{}.Now()
				if config.Now != nil {
					now = config.Now()
				}
				snapshot := config.PublicSelf()
				if snapshot.Outcome.String() != "positive" || snapshot.ObservedAt.Before(now.Add(-5*time.Second)) || snapshot.ObservedAt.After(now.Add(time.Second)) {
					return nil, errUnsafeACMEEndpoint
				}
			}
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if net.ParseIP(host) != nil {
				return nil, errUnsafeACMEEndpoint
			}
			resolveCtx, resolveCancel := context.WithTimeout(ctx, 5*time.Second)
			answers, err := resolver.LookupA(resolveCtx, host)
			resolveCancel()
			if err != nil {
				return nil, err
			}
			if len(answers) == 0 || len(answers) > 4 {
				return nil, errUnsafeACMEEndpoint
			}
			var last error
			for _, answer := range answers {
				if !answer.Is4() {
					return nil, errUnsafeACMEEndpoint
				}
				attemptCtx, attemptCancel := context.WithTimeout(ctx, 10*time.Second)
				conn, err := dial(attemptCtx, "tcp4", net.JoinHostPort(answer.String(), port), netip.Addr{})
				attemptCancel()
				if err == nil {
					return conn, nil
				}
				last = err
			}
			return nil, last
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: config.RootCAs},
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 10 * time.Second,
		MaxResponseHeaderBytes: acmeHeaderLimit, MaxConnsPerHost: 4,
		DisableCompression: true, ForceAttemptHTTP2: false,
	}, nil
}

func validateACMEURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Port() != "" || net.ParseIP(u.Hostname()) != nil || strings.HasSuffix(u.Hostname(), ".") {
		return errUnsafeACMEEndpoint
	}
	return nil
}
