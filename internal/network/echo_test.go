package network

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestEchoRejectsNonHTTPSAndUnsafeEndpointsBeforeNetwork(t *testing.T) {
	for _, raw := range []string{
		"http://echo.example/", "https://user@echo.example/", "https://127.0.0.1/",
		"https://[::1]/", "https://echo.example:8443/",
	} {
		t.Run(raw, func(t *testing.T) {
			called := false
			_, err := (EchoClient{Resolver: LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
				called = true
				return nil, nil
			})}).Check(context.Background(), raw)
			if !errors.Is(err, ErrInvalidEchoURL) || called {
				t.Fatalf("Check(%q) = %v resolver=%v", raw, err, called)
			}
		})
	}
}

func TestEchoAcceptsOnlyOneCanonicalIPv4(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("  8.8.8.8\t\n")) }))
	defer server.Close()
	snapshot := PublicSelfSnapshot{Generation: 1, ObservedAt: time.Now(), Outcome: publicSelfOutcome("positive")}
	echo := EchoClient{
		Resolver: LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}),
		Dialer: Dialer{Snapshot: func() PublicSelfSnapshot { return snapshot }, Dial: func(ctx context.Context, network, _ string, _ netip.Addr) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		}},
		TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig,
	}
	got, err := echo.Check(context.Background(), "https://example.com/")
	if err != nil || got != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Check = %v, %v", got, err)
	}
}

func TestEchoRejectsRedirectAndNonCanonicalBody(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{"redirect", http.StatusFound, ""}, {"extra tokens", http.StatusOK, "8.8.8.8 1.1.1.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			snapshot := PublicSelfSnapshot{Generation: 1, ObservedAt: time.Now(), Outcome: publicSelfOutcome("positive")}
			echo := EchoClient{Resolver: LookupFunc(func(context.Context, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
			}), Dialer: Dialer{Snapshot: func() PublicSelfSnapshot { return snapshot }, Dial: func(ctx context.Context, network, _ string, _ netip.Addr) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}}, TLSConfig: server.Client().Transport.(*http.Transport).TLSClientConfig}
			if _, err := echo.Check(context.Background(), "https://example.com/"); err == nil {
				t.Fatal("Check accepted forbidden response")
			}
		})
	}
}
