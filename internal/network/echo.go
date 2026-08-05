package network

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxEchoBytes = 4 << 10

var (
	ErrInvalidEchoURL = errors.New("invalid public IPv4 echo URL")
	ErrInvalidEcho    = errors.New("invalid public IPv4 echo response")
)

// EchoClient performs an explicitly requested, direct HTTPS public-IPv4 check.
// Resolver and Dialer are required so the request cannot use ambient DNS/proxy state.
type EchoClient struct {
	Resolver  Resolver
	Dialer    Dialer
	TLSConfig *tls.Config // test or explicitly configured trust roots
}

func (e EchoClient) Check(ctx context.Context, rawURL string) (netip.Addr, error) {
	u, err := parseEchoURL(rawURL)
	if err != nil {
		return netip.Addr{}, err
	}
	if e.Resolver == nil || e.Dialer.Snapshot == nil {
		return netip.Addr{}, ErrInvalidEchoURL
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	candidates, err := e.Resolver.LookupA(ctx, u.Hostname())
	if err != nil {
		return netip.Addr{}, err
	}
	candidates, err = ClassifyCandidates(candidates)
	if err != nil {
		return netip.Addr{}, err
	}
	snapshot := e.Dialer.Snapshot()
	transport := &http.Transport{
		Proxy:             nil,
		TLSClientConfig:   e.TLSConfig,
		ForceAttemptHTTP2: false,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			conn, _, dialErr := e.Dialer.DialCandidates(dialCtx, u.Hostname(), 443, candidates, snapshot)
			return conn, dialErr
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return netip.Addr{}, ErrInvalidEchoURL
	}
	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return netip.Addr{}, ErrInvalidEcho
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxEchoBytes+1))
	if err != nil || len(body) > maxEchoBytes {
		return netip.Addr{}, ErrInvalidEcho
	}
	value := strings.Trim(string(body), " \t\r\n")
	if value == "" || strings.ContainsAny(value, " \t\r\n") {
		return netip.Addr{}, ErrInvalidEcho
	}
	address, err := netip.ParseAddr(value)
	if err != nil || !address.Is4() || address.String() != value {
		return netip.Addr{}, ErrInvalidEcho
	}
	return address, nil
}

func parseEchoURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil {
		return nil, ErrInvalidEchoURL
	}
	if port := u.Port(); port != "" && port != strconv.Itoa(443) {
		return nil, ErrInvalidEchoURL
	}
	return u, nil
}
