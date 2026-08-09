package proxy

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

type recordingTunnel struct {
	releases int
	result   contract.CloseResult
}

func (t *recordingTunnel) Release(result contract.CloseResult, _ contract.ByteTotals) bool {
	t.releases++
	t.result = result
	return t.releases == 1
}
func (*recordingTunnel) Context() context.Context { return context.Background() }

type alwaysFailWriter struct{}

func (alwaysFailWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

type countingPublicSelf struct{ calls uint64 }

func (p *countingPublicSelf) Acquire(context.Context) network.PublicSelfSnapshot {
	p.calls++
	return network.PublicSelfSnapshot{Generation: p.calls, ObservedAt: time.Now()}
}
func (p *countingPublicSelf) Snapshot() network.PublicSelfSnapshot {
	return network.PublicSelfSnapshot{Generation: p.calls, ObservedAt: time.Now()}
}

type connectClock struct{ now time.Time }

func (c connectClock) Now() time.Time                        { return c.now }
func (connectClock) NewTimer(time.Duration) timebase.Timer   { panic("unused") }
func (connectClock) NewTicker(time.Duration) timebase.Ticker { panic("unused") }

func TestPublicConfigUsesSuppliedClock(t *testing.T) {
	want := time.Unix(123, 0)
	if got := publicNow(PublicConfig{Clock: connectClock{now: want}}); !got.Equal(want) {
		t.Fatalf("now=%v want=%v", got, want)
	}
}

func TestWritePublicPreservesSelectedFrameStatus(t *testing.T) {
	for _, tc := range []struct {
		frame wire.Frame
		want  int
	}{
		{wire.FrameForbidden, http.StatusForbidden},
		{wire.FrameProxyAuthenticationRequired, http.StatusProxyAuthRequired},
		{wire.FrameBadGateway, http.StatusBadGateway},
		{wire.FrameServiceUnavailable, http.StatusServiceUnavailable},
		{wire.FrameGatewayTimeout, http.StatusGatewayTimeout},
		{wire.FrameInternalError, http.StatusInternalServerError},
		{wire.FrameTooManyRequests, http.StatusTooManyRequests},
	} {
		t.Run(string(tc.frame), func(t *testing.T) {
			rr := httptest.NewRecorder()
			writePublic(rr, httptest.NewRequest(http.MethodConnect, "http://proxy/", nil), nil, tc.frame)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d", rr.Code, tc.want)
			}
			if tc.frame == wire.FrameTooManyRequests && rr.Header().Get("Retry-After") != "60" {
				t.Fatalf("Retry-After=%q", rr.Header().Get("Retry-After"))
			}
		})
	}
}

func TestEstablishedTunnelWriteFailureReleasesCanonicalOutcomeOnce(t *testing.T) {
	client, peer := net.Pipe()
	defer peer.Close()
	origin, upstream := net.Pipe()
	defer upstream.Close()
	tunnel := &recordingTunnel{}
	rw := bufio.NewReadWriter(bufio.NewReader(bytes.NewReader(nil)), bufio.NewWriter(alwaysFailWriter{}))
	relayEstablished(tunnel, client, rw, origin, time.Second, 0)
	if tunnel.releases != 1 || tunnel.result.String() != "io_error" {
		t.Fatalf("release count=%d result=%s", tunnel.releases, tunnel.result)
	}
}

func TestPublicConfigAcquiresFreshSelfForEachSetup(t *testing.T) {
	p := &countingPublicSelf{}
	first, ok := publicSelfForSetup(context.Background(), PublicConfig{PublicSelf: p})
	if !ok {
		t.Fatal("first snapshot unavailable")
	}
	second, ok := publicSelfForSetup(context.Background(), PublicConfig{PublicSelf: p})
	if !ok || first.Generation != 1 || second.Generation != 2 || p.calls != 2 {
		t.Fatalf("first=%d second=%d calls=%d", first.Generation, second.Generation, p.calls)
	}
}

func TestPublicRoutePrecedenceAndPAC(t *testing.T) {
	coordinator := session.NewCoordinator(credential.Verifier{}, admission.NewAuthentication(timebase.Real{}))
	snapshot, _ := credential.NewValidatedSnapshot([16]byte{}, 1, nil)
	coordinator.InstallCredentials(snapshot)
	h := NewPublicHandler(PublicConfig{Coordinator: coordinator, PACEnabled: true, PACBody: []byte("PAC"), PACAdmission: admission.NewPAC(timebase.Real{})})
	for _, tc := range []struct {
		name, method, target string
		headers              http.Header
		want                 int
		allow, body          string
	}{
		{"pac", http.MethodGet, "/proxy.pac", nil, http.StatusOK, "", "PAC"},
		{"pac method", http.MethodPost, "/proxy.pac", nil, http.StatusMethodNotAllowed, "GET", "method not allowed\n"},
		{"unknown", http.MethodGet, "/missing", nil, http.StatusNotFound, "", "not found\n"},
		{"absolute", http.MethodGet, "http://example.com/", nil, http.StatusBadRequest, "", "bad request\n"},
		{"authority method", http.MethodGet, "example.com:443", nil, http.StatusMethodNotAllowed, "CONNECT", "method not allowed\n"},
		{"duplicate auth", http.MethodConnect, "example.com:443", http.Header{"Proxy-Authorization": {"Basic a", "Basic b"}}, http.StatusBadRequest, "", "bad request\n"},
		{"missing auth before policy", http.MethodConnect, "denied.example:443", nil, http.StatusProxyAuthRequired, "", "proxy authentication required\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.RequestURI = tc.target
			for name, values := range tc.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}
			h.ServeHTTP(rr, req)
			if rr.Code != tc.want || rr.Header().Get("Allow") != tc.allow || rr.Body.String() != tc.body {
				t.Fatalf("status=%d allow=%q body=%q", rr.Code, rr.Header().Get("Allow"), rr.Body.String())
			}
		})
	}

	disabled := NewPublicHandler(PublicConfig{})
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/proxy.pac", nil)
	disabled.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("disabled PAC status=%d want 404", rr.Code)
	}
}
