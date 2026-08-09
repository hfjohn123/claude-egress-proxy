package proxy

import (
	"bytes"
	"errors"
	"net/http"

	"github.com/hfjohn123/claude-egress-proxy/internal/admintoken"
	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
	"github.com/prometheus/common/expfmt"
)

var errMetricsTooLarge = errors.New("proxy: metrics response too large")

const maxMetricsResponse = 1 << 20

type boundedBuffer struct{ bytes.Buffer }

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > maxMetricsResponse {
		return 0, errMetricsTooLarge
	}
	return b.Buffer.Write(p)
}

// AdminConfig keeps the administrative surface explicitly independent from the
// public proxy configuration.
type AdminConfig struct {
	MetricsEnabled bool
	Verifier       admintoken.Verifier
	Admission      *admission.Admin
	Readiness      *Readiness
	Metrics        *telemetry.Metrics
	Coordinator    *session.Coordinator
}

// NewAdminHandler serves the three closed loopback endpoints. It deliberately
// emits no application telemetry for administrative requests.
func NewAdminHandler(cfg AdminConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, routeDecision := wire.AdaptRequest(r)
		if routeDecision == wire.DecisionHTTPVersionNotSupported {
			writeAdmin(w, r, cfg.Coordinator, http.StatusHTTPVersionNotSupported, "http version not supported\n", "text/plain; charset=utf-8")
			return
		}
		if routeDecision != wire.DecisionAllow || req.Target != wire.TargetOrigin {
			writeAdmin(w, r, cfg.Coordinator, http.StatusBadRequest, "bad request\n", "text/plain; charset=utf-8")
			return
		}
		switch req.RequestURI {
		case "/healthz":
		case "/readyz":
		case "/metrics":
			if !cfg.MetricsEnabled {
				writeAdmin(w, r, cfg.Coordinator, http.StatusNotFound, "not found\n", "text/plain; charset=utf-8")
				return
			}
		default:
			writeAdmin(w, r, cfg.Coordinator, http.StatusNotFound, "not found\n", "text/plain; charset=utf-8")
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			writeAdmin(w, r, cfg.Coordinator, http.StatusMethodNotAllowed, "method not allowed\n", "text/plain; charset=utf-8")
			return
		}
		if req.RequestURI == "/healthz" {
			writeAdmin(w, r, cfg.Coordinator, http.StatusOK, "ok\n", "text/plain; charset=utf-8")
			return
		}
		if req.RequestURI == "/readyz" {
			if cfg.Readiness != nil && cfg.Readiness.Ready() {
				writeAdmin(w, r, cfg.Coordinator, http.StatusOK, "ready\n", "text/plain; charset=utf-8")
			} else {
				writeAdmin(w, r, cfg.Coordinator, http.StatusServiceUnavailable, "not ready\n", "text/plain; charset=utf-8")
			}
			return
		}

		header, count := wire.TakeAuthorization(r.Header, "Authorization")
		if count != 1 || !cfg.Verifier.Verify(header).Authorized {
			w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
			writeAdmin(w, r, cfg.Coordinator, http.StatusUnauthorized, "unauthorized\n", "text/plain; charset=utf-8")
			return
		}
		if cfg.Admission == nil || cfg.Metrics == nil {
			writeAdmin(w, r, cfg.Coordinator, http.StatusInternalServerError, "internal_error\n", "text/plain; charset=utf-8")
			return
		}
		work, decision := cfg.Admission.AcquireMetricsWork()
		if !decision.Allowed() {
			writeAdmin(w, r, cfg.Coordinator, http.StatusServiceUnavailable, "service unavailable\n", "text/plain; charset=utf-8")
			return
		}
		defer work.Release()
		families, err := cfg.Metrics.Gatherer().Gather()
		if err != nil {
			writeAdmin(w, r, cfg.Coordinator, http.StatusInternalServerError, "internal_error\n", "text/plain; charset=utf-8")
			return
		}
		var body boundedBuffer
		for _, family := range families {
			if _, err := expfmt.MetricFamilyToText(&body, family); err != nil {
				writeAdmin(w, r, cfg.Coordinator, http.StatusInternalServerError, "internal_error\n", "text/plain; charset=utf-8")
				return
			}
		}
		writeAdmin(w, r, cfg.Coordinator, http.StatusOK, body.String(), "text/plain; version=0.0.4; charset=utf-8")
	})
}

func writeAdmin(w http.ResponseWriter, r *http.Request, c *session.Coordinator, status int, body, contentType string) {
	if c != nil {
		if _, owned := wire.ConnectionOwner(r); owned {
			_ = WriteFixedResponse(w, r, c, adminFrame(status, body), []byte(body))
			return
		}
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

func adminFrame(status int, body string) wire.Frame {
	switch status {
	case http.StatusOK:
		if body == "ok\n" {
			return wire.FrameHealthOK
		}
		if body == "ready\n" {
			return wire.FrameReadyOK
		}
		return wire.FrameMetricsOK
	case http.StatusUnauthorized:
		return wire.FrameMetricsUnauthorized
	case http.StatusNotFound:
		return wire.FrameNotFound
	case http.StatusMethodNotAllowed:
		return wire.FrameMethodNotAllowedGet
	case http.StatusServiceUnavailable:
		if body == "not ready\n" {
			return wire.FrameNotReady
		}
		return wire.FrameServiceUnavailable
	case http.StatusBadRequest:
		return wire.FrameBadRequest
	case http.StatusHTTPVersionNotSupported:
		return wire.FrameHTTPVersionNotSupported
	default:
		return wire.FrameInternalError
	}
}
