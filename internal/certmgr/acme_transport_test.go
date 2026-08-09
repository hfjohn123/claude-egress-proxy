package certmgr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
)

func TestDirectTransportRejectsUnsafeDirectoryURL(t *testing.T) {
	for _, raw := range []string{"http://ca.example/directory", "https://127.0.0.1/directory", "https://ca.example:8443/directory", "https://u@ca.example/directory"} {
		if _, err := NewDirectTransport(DirectTransportConfig{DirectoryURL: raw}); err == nil {
			t.Fatalf("NewDirectTransport(%q) accepted unsafe URL", raw)
		}
	}
}

func TestDirectTransportDialsValidatedLiteralWithoutProxy(t *testing.T) {
	old := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("ambient proxy used") })
	t.Cleanup(func() { http.DefaultTransport = old })

	var gotNetwork, gotAddress string
	transport, err := NewDirectTransport(DirectTransportConfig{
		DirectoryURL: "https://ca.example/directory",
		Resolver: network.LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dial: func(_ context.Context, networkName, address string, _ netip.Addr) (net.Conn, error) {
			gotNetwork, gotAddress = networkName, address
			client, server := net.Pipe()
			go func() {
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(time.Second))
				buffer := make([]byte, 1024)
				_, _ = server.Read(buffer)
				_, _ = server.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"))
			}()
			return client, nil
		},
		PublicSelf: func() network.PublicSelfSnapshot { return positiveSelfSnapshot() },
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Get("http://ca.example/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if gotNetwork != "tcp4" || gotAddress != "8.8.8.8:80" {
		t.Fatalf("dial = %q %q", gotNetwork, gotAddress)
	}
}

func TestDirectTransportRejectsUnsafeDNSAnswerBeforeDial(t *testing.T) {
	called := false
	transport, err := NewDirectTransport(DirectTransportConfig{
		DirectoryURL: "https://ca.example/directory",
		Resolver: network.LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}),
		Dial: func(context.Context, string, string, netip.Addr) (net.Conn, error) {
			called = true
			return nil, errors.New("unexpected dial")
		},
		PublicSelf: func() network.PublicSelfSnapshot { return positiveSelfSnapshot() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.DialContext(t.Context(), "tcp", "ca.example:443"); err == nil {
		t.Fatal("unsafe DNS answer accepted")
	}
	if called {
		t.Fatal("dial hook called for unsafe answer")
	}
}

func TestDirectTransportRequiresFreshPositivePublicSelfWhenConfigured(t *testing.T) {
	called := false
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	transport, err := NewDirectTransport(DirectTransportConfig{
		DirectoryURL: "https://ca.example/directory",
		PublicSelf: func() network.PublicSelfSnapshot {
			return network.PublicSelfSnapshot{ObservedAt: now.Add(-6 * time.Second)}
		},
		Now: func() time.Time { return now },
		Resolver: network.LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
			called = true
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.DialContext(t.Context(), "tcp", "ca.example:443"); !errors.Is(err, errUnsafeACMEEndpoint) {
		t.Fatalf("dial error = %v", err)
	}
	if called {
		t.Fatal("resolved while public-self gate was stale")
	}
}

func TestDirectTransportSynchronouslyRefreshesStalePublicSelf(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	current := network.PublicSelfSnapshot{Generation: 1, ObservedAt: now.Add(-6 * time.Second)}
	fresh := positiveSelfSnapshot()
	fresh.Generation, fresh.ObservedAt = 2, now
	acquired := false
	dialError := errors.New("dial reached")
	transport, err := NewDirectTransport(DirectTransportConfig{
		DirectoryURL: "https://ca.example/directory", Now: func() time.Time { return now },
		PublicSelf: func() network.PublicSelfSnapshot { return current },
		Acquire: func(context.Context) network.PublicSelfSnapshot {
			acquired = true
			current = fresh
			return fresh
		},
		Resolver: network.LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dial: func(context.Context, string, string, netip.Addr) (net.Conn, error) { return nil, dialError },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.DialContext(t.Context(), "tcp", "ca.example:443"); !errors.Is(err, dialError) {
		t.Fatalf("dial error = %v", err)
	}
	if !acquired {
		t.Fatal("stale public-self state was not refreshed")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func positiveSelfSnapshot() network.PublicSelfSnapshot {
	outcome, _ := contract.ParsePublicSelfOutcome("positive")
	return network.PublicSelfSnapshot{Generation: 1, ObservedAt: time.Now(), Outcome: outcome, Addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
}
