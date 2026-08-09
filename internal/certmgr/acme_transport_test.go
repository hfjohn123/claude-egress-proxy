package certmgr

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

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
			return []netip.Addr{netip.MustParseAddr("203.0.113.7")}, nil
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
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := (&http.Client{Transport: transport}).Get("http://ca.example/status")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if gotNetwork != "tcp4" || gotAddress != "203.0.113.7:80" {
		t.Fatalf("dial = %q %q", gotNetwork, gotAddress)
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
