package proxy

import (
	"bufio"
	"context"
	"net/http"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

// PublicConfig contains only dependencies needed by public CONNECT handling.
type PublicConfig struct {
	Coordinator *session.Coordinator
	Policy      policy.Policy
	Resolver    network.Resolver
	Dialer      network.Dialer
	PublicSelf  network.PublicSelfSnapshot
	Clock       timebase.Clock
}

// NewPublicHandler handles only authenticated CONNECT tunnels. It never parses
// bytes after the successful CONNECT response.
func NewPublicHandler(cfg PublicConfig) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { servePublic(cfg, w, r) })
}

func servePublic(cfg PublicConfig, w http.ResponseWriter, r *http.Request) {
	req, decision := wire.AdaptRequest(r)
	if decision == wire.DecisionHTTPVersionNotSupported {
		writePublic(w, r, cfg.Coordinator, wire.FrameHTTPVersionNotSupported)
		return
	}
	if decision != wire.DecisionAllow {
		writePublic(w, r, cfg.Coordinator, wire.FrameBadRequest)
		return
	}
	if req.Target != wire.TargetAuthority || r.Method != http.MethodConnect {
		writePublic(w, r, cfg.Coordinator, wire.FrameMethodNotAllowedConnect)
		return
	}
	header, count := wire.TakeAuthorization(r.Header, "Proxy-Authorization")
	if count != 1 {
		writePublic(w, r, cfg.Coordinator, wire.FrameProxyAuthenticationRequired)
		return
	}
	authority, semantic := policy.ParseAuthority([]byte(req.RequestURI))
	if semantic != policy.SemanticNone || !cfg.Policy.MatchHost(authority.Host()) {
		writePublic(w, r, cfg.Coordinator, wire.FrameForbidden)
		return
	}
	owner, ok := wire.ConnectionOwner(r)
	if !ok || cfg.Coordinator == nil {
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	leased, ok := owner.(interface{ PublicLease() admission.PublicLease })
	if !ok {
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	attempt, _, result := cfg.Coordinator.Authenticate(header, leased.PublicLease(), publicNow(cfg))
	if result.String() != "established" {
		writePublic(w, r, cfg.Coordinator, frameFor(result.String()))
		return
	}
	handoff, result := cfg.Coordinator.BeginSetup(attempt)
	if result.String() != "established" {
		writePublic(w, r, cfg.Coordinator, frameFor(result.String()))
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		handoff.Release()
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		handoff.Release()
		return
	}
	// net/http leaves its handler write deadline installed across Hijack.
	// Clear it before bounded setup so CONNECT tunnels do not inherit 10s.
	_ = conn.SetDeadline(time.Time{})
	if conn != owner {
		_ = conn.Close()
		handoff.Release()
		return
	}
	if err := handoff.Attach(conn, rw); err != nil {
		_ = conn.Close()
		handoff.Release()
		return
	}
	reservation, result := cfg.Coordinator.Transfer(handoff)
	if result.String() != "established" {
		handoff.Release()
		_ = writeFrame(rw, wire.FrameServiceUnavailable)
		_ = conn.Close()
		return
	}
	ctx, cancel := context.WithTimeout(reservation.Context(), 10*time.Second)
	defer cancel()
	if cfg.Resolver == nil {
		reservation.Release(resultFor("dns_failed"))
		_ = writeFrame(rw, wire.FrameBadGateway)
		_ = conn.Close()
		return
	}
	answers, err := cfg.Resolver.LookupA(ctx, authority.Host())
	if err != nil {
		reservation.Release(resultFor("dns_failed"))
		_ = writeFrame(rw, wire.FrameBadGateway)
		_ = conn.Close()
		return
	}
	origin, _, err := cfg.Dialer.DialCandidates(ctx, authority.Host(), authority.Port(), answers, cfg.PublicSelf)
	if err != nil {
		reservation.Release(resultFor("dial_failed"))
		_ = writeFrame(rw, wire.FrameBadGateway)
		_ = conn.Close()
		return
	}
	tunnel, result := cfg.Coordinator.Commit(reservation, origin)
	if result.String() != "established" {
		_ = origin.Close()
		_ = writeFrame(rw, frameFor(result.String()))
		_ = conn.Close()
		return
	}
	if err := writeFrame(rw, wire.FrameConnectEstablished); err != nil {
		tunnel.Release(closeFor("write_error"), contract.ByteTotals{})
		return
	}
	_ = conn.SetDeadline(cfg.Clock.Now().Add(contract.V1().Idle))
	bytes := RelayBuffered(conn, rw.Reader, origin)
	tunnel.Release(closeFor("client_eof"), contract.ByteTotals{ClientToOrigin: bytes.ClientToOrigin, OriginToClient: bytes.OriginToClient})
}

func writePublic(w http.ResponseWriter, r *http.Request, c *session.Coordinator, frame wire.Frame) {
	if c != nil {
		if _, owned := wire.ConnectionOwner(r); owned {
			_ = WriteFixedResponse(w, r, c, frame, nil)
			return
		}
	}
	status, body := publicFrameStatus(frame)
	w.Header().Set("Connection", "close")
	switch frame {
	case wire.FrameMethodNotAllowedConnect:
		w.Header().Set("Allow", "CONNECT")
	case wire.FrameProxyAuthenticationRequired:
		w.Header().Set("Proxy-Authenticate", `Basic realm="claude-egress-proxy"`)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write([]byte(body))
	}
}

func publicFrameStatus(frame wire.Frame) (int, string) {
	switch frame {
	case wire.FrameHTTPVersionNotSupported:
		return http.StatusHTTPVersionNotSupported, "http version not supported\n"
	case wire.FrameMethodNotAllowedConnect:
		return http.StatusMethodNotAllowed, "method not allowed\n"
	case wire.FrameProxyAuthenticationRequired:
		return http.StatusProxyAuthRequired, "proxy authentication required\n"
	case wire.FrameForbidden:
		return http.StatusForbidden, "forbidden\n"
	case wire.FrameBadGateway:
		return http.StatusBadGateway, "bad gateway\n"
	case wire.FrameServiceUnavailable:
		return http.StatusServiceUnavailable, "service unavailable\n"
	case wire.FrameGatewayTimeout:
		return http.StatusGatewayTimeout, "gateway timeout\n"
	case wire.FrameInternalError:
		return http.StatusInternalServerError, "internal_error\n"
	default:
		return http.StatusBadRequest, "bad request\n"
	}
}
func writeFrame(rw *bufio.ReadWriter, frame wire.Frame) error {
	if err := wire.WriteFrame(rw, []byte(http.MethodConnect), frame, nil); err != nil {
		return err
	}
	return rw.Flush()
}
func resultFor(s string) contract.ConnectResult {
	r, ok := contract.ParseConnectResult(s)
	if !ok {
		panic(s)
	}
	return r
}
func closeFor(s string) contract.CloseResult {
	r, ok := contract.ParseCloseResult(s)
	if !ok {
		panic(s)
	}
	return r
}
func frameFor(s string) wire.Frame {
	switch s {
	case "draining", "global_capacity", "device_capacity", "credential_store_unavailable":
		return wire.FrameServiceUnavailable
	case "port_denied", "hostname_denied", "address_denied", "malformed_request":
		return wire.FrameForbidden
	case "dns_failed", "dial_failed":
		return wire.FrameBadGateway
	case "setup_timeout":
		return wire.FrameGatewayTimeout
	default:
		return wire.FrameInternalError
	}
}

func publicNow(cfg PublicConfig) time.Time {
	if cfg.Clock != nil {
		return cfg.Clock.Now()
	}
	return timebase.Real{}.Now()
}
