package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

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
	} {
		t.Run(string(tc.frame), func(t *testing.T) {
			rr := httptest.NewRecorder()
			writePublic(rr, httptest.NewRequest(http.MethodConnect, "http://proxy/", nil), nil, tc.frame)
			if rr.Code != tc.want {
				t.Fatalf("status=%d want=%d", rr.Code, tc.want)
			}
		})
	}
}
