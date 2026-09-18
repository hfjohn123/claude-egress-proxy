package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
)

type PublicSelfProvider interface {
	Acquire(context.Context) network.PublicSelfSnapshot
	Snapshot() network.PublicSelfSnapshot
}

// PublicConfig contains only dependencies needed by public CONNECT handling.
type PublicConfig struct {
	Coordinator  *session.Coordinator
	Policy       policy.Policy
	Resolver     network.Resolver
	Dialer       network.Dialer
	PublicSelf   PublicSelfProvider
	Clock        timebase.Clock
	Idle         time.Duration
	Absolute     time.Duration
	PACEnabled   bool
	PACBody      []byte
	PACAdmission *admission.PAC
	Metrics      *telemetry.Metrics
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
		recordConnectOnly(cfg, resultFor("malformed_request"))
		writePublic(w, r, cfg.Coordinator, wire.FrameBadRequest)
		return
	}
	header, count := wire.TakeAuthorization(r.Header, "Proxy-Authorization")
	if count > 1 {
		recordConnectOnly(cfg, resultFor("malformed_request"))
		writePublic(w, r, cfg.Coordinator, wire.FrameBadRequest)
		return
	}
	switch req.Target {
	case wire.TargetAbsolute, wire.TargetAsterisk:
		recordConnectOnly(cfg, resultFor("malformed_request"))
		writePublic(w, r, cfg.Coordinator, wire.FrameBadRequest)
		return
	case wire.TargetOrigin:
		if req.RequestURI != "/proxy.pac" {
			recordPAC(cfg, "not_found", "")
			writePublic(w, r, cfg.Coordinator, wire.FrameNotFound)
			return
		}
		if !cfg.PACEnabled {
			recordPAC(cfg, "disabled", "")
			writePublic(w, r, cfg.Coordinator, wire.FrameNotFound)
			return
		}
		if r.Method != http.MethodGet {
			writePublic(w, r, cfg.Coordinator, wire.FrameMethodNotAllowedGet)
			return
		}
		servePAC(cfg, w, r)
		return
	}
	if r.Method != http.MethodConnect {
		writePublic(w, r, cfg.Coordinator, wire.FrameMethodNotAllowedConnect)
		return
	}
	owner, ok := wire.ConnectionOwner(r)
	if cfg.Coordinator == nil {
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	var lease admission.PublicLease
	var prefix admission.Prefix
	if ok {
		leased, leaseOK := owner.(interface{ PublicLease() admission.PublicLease })
		address, addressOK := remoteAddress(owner.RemoteAddr())
		if !leaseOK || !addressOK {
			writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
			return
		}
		lease = leased.PublicLease()
		prefix = admission.Aggregate(address)
	}
	attempt, authentication, result := cfg.Coordinator.Authenticate(header, count == 1, prefix, lease, time.Time{})
	if result.String() == "draining" {
		recordConnectOnly(cfg, result)
		writePublic(w, r, cfg.Coordinator, wire.FrameServiceUnavailable)
		return
	}
	recordAuthentication(cfg, authentication)
	switch authentication.String() {
	case "challenge", "invalid":
		writePublic(w, r, cfg.Coordinator, wire.FrameProxyAuthenticationRequired)
		return
	case "throttled", "map_capacity":
		writePublic(w, r, cfg.Coordinator, wire.FrameTooManyRequests)
		return
	case "store_unavailable":
		writePublic(w, r, cfg.Coordinator, wire.FrameServiceUnavailable)
		return
	case "valid":
		// Continue below only after uniform authentication has committed.
	default:
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	if result.String() != "established" {
		recordConnectOnly(cfg, result)
		writePublic(w, r, cfg.Coordinator, frameFor(result.String()))
		return
	}
	started := publicNow(cfg)
	if !session.SetSetupStarted(attempt, started) {
		result := resultFor("internal_error")
		attempt.Release(result)
		recordSetup(cfg, result, started)
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	if !ok {
		result := resultFor("internal_error")
		attempt.Release(result)
		recordSetup(cfg, result, started)
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	authority, semantic := policy.ParseAuthority([]byte(req.RequestURI))
	if semantic != policy.SemanticNone {
		result, frame := resultFor("malformed_request"), wire.FrameBadRequest
		if semantic == policy.SemanticPortDenied {
			result, frame = resultFor("port_denied"), wire.FrameForbidden
		} else if semantic == policy.SemanticAddressDenied {
			result, frame = resultFor("address_denied"), wire.FrameForbidden
		}
		attempt.Release(result)
		recordSetup(cfg, result, started)
		writePublic(w, r, cfg.Coordinator, frame)
		return
	}
	if !cfg.Policy.MatchHost(authority.Host()) {
		attempt.Release(resultFor("hostname_denied"))
		recordSetup(cfg, resultFor("hostname_denied"), started)
		writePublic(w, r, cfg.Coordinator, wire.FrameForbidden)
		return
	}
	if !session.SetDestination(attempt, authority.Host()) {
		result := resultFor("internal_error")
		attempt.Release(result)
		recordSetup(cfg, result, started)
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	handoff, result := cfg.Coordinator.BeginSetup(attempt)
	if result.String() != "established" {
		recordSetup(cfg, result, started)
		writePublic(w, r, cfg.Coordinator, frameFor(result.String()))
		return
	}
	h, ok := w.(http.Hijacker)
	if !ok {
		handoff.Release()
		recordSetup(cfg, resultFor("internal_error"), started)
		writePublic(w, r, cfg.Coordinator, wire.FrameInternalError)
		return
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		handoff.Release()
		recordSetup(cfg, resultFor("client_disconnected"), started)
		return
	}
	// net/http leaves its handler write deadline installed across Hijack.
	// Clear it before bounded setup so CONNECT tunnels do not inherit 10s.
	_ = conn.SetDeadline(time.Time{})
	if conn != owner {
		_ = conn.Close()
		handoff.Release()
		recordSetup(cfg, resultFor("internal_error"), started)
		return
	}
	if err := handoff.Attach(conn, rw); err != nil {
		_ = conn.Close()
		handoff.Release()
		recordSetup(cfg, resultFor("client_disconnected"), started)
		return
	}
	reservation, result := cfg.Coordinator.Transfer(handoff)
	if result.String() != "established" {
		recordSetup(cfg, result, started)
		writeFrameThenRelease(rw, wire.FrameServiceUnavailable, func() { handoff.Release() })
		return
	}
	ctx, cancel := context.WithTimeout(reservation.Context(), 10*time.Second)
	defer cancel()
	self, ok := publicSelfForSetup(ctx, cfg)
	if !ok {
		result := resultFor("self_address_state_unavailable")
		recordSetup(cfg, result, started)
		writeFrameThenRelease(rw, wire.FrameServiceUnavailable, func() { reservation.Release(result) })
		return
	}
	if cfg.Resolver == nil {
		result := resultFor("dns_failed")
		recordSetup(cfg, result, started)
		writeFrameThenRelease(rw, wire.FrameBadGateway, func() { reservation.Release(result) })
		return
	}
	answers, err := cfg.Resolver.LookupA(ctx, authority.Host())
	if err != nil {
		result := resultFor("dns_failed")
		recordSetup(cfg, result, started)
		writeFrameThenRelease(rw, wire.FrameBadGateway, func() { reservation.Release(result) })
		return
	}
	dialer := cfg.Dialer
	if dialer.Snapshot == nil {
		dialer.Snapshot = cfg.PublicSelf.Snapshot
	}
	origin, _, err := dialer.DialCandidates(ctx, authority.Host(), authority.Port(), answers, self)
	if err != nil {
		result, frame := resultFor("dial_failed"), wire.FrameBadGateway
		if errors.Is(err, network.ErrPublicSelfStale) {
			result, frame = resultFor("self_address_state_unavailable"), wire.FrameServiceUnavailable
		} else if errors.Is(err, network.ErrUnsafeAnswer) || errors.Is(err, network.ErrSelfAddress) {
			result, frame = resultFor("address_denied"), wire.FrameForbidden
		}
		recordSetup(cfg, result, started)
		writeFrameThenRelease(rw, frame, func() { reservation.Release(result) })
		return
	}
	tunnel, result := cfg.Coordinator.Commit(reservation, origin)
	if result.String() != "established" {
		recordSetup(cfg, result, started)
		_ = origin.Close()
		writeFrameThenRelease(rw, frameFor(result.String()), func() { reservation.Release(result) })
		return
	}
	recordSetup(cfg, result, started)
	idle := cfg.Idle
	if idle <= 0 {
		idle = contract.V1().Idle
	}
	relayEstablished(tunnel, conn, rw, origin, idle, cfg.Absolute)
}

func servePAC(cfg PublicConfig, w http.ResponseWriter, r *http.Request) {
	if cfg.PACAdmission == nil || len(cfg.PACBody) > contract.V1().PACBytes {
		recordPAC(cfg, "capacity", "")
		writePublic(w, r, cfg.Coordinator, wire.FrameServiceUnavailable)
		return
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		recordPAC(cfg, "capacity", "")
		writePublic(w, r, cfg.Coordinator, wire.FrameServiceUnavailable)
		return
	}
	lease, decision := cfg.PACAdmission.Acquire(admission.Aggregate(remote.Addr()))
	if !decision.Allowed() {
		switch decision {
		case admission.PACPrefixThrottled:
			recordPAC(cfg, "prefix_rate_limited", "throttled")
		case admission.PACGlobalThrottled:
			recordPAC(cfg, "global_rate_limited", "throttled")
		case admission.PACMapFull:
			recordPAC(cfg, "map_capacity", "map_full")
		default:
			recordPAC(cfg, "capacity", "")
		}
		writePublic(w, r, cfg.Coordinator, wire.FrameTooManyRequests)
		return
	}
	defer lease.Release()
	recordPAC(cfg, "served", "allowed")
	writePublicPayload(w, r, cfg.Coordinator, wire.FramePACOK, cfg.PACBody)
}

func recordAuthentication(cfg PublicConfig, result contract.AuthenticationResult) {
	if cfg.Metrics == nil {
		return
	}
	cfg.Metrics.IncAuthentication(result)
	limiterEvent := ""
	switch result.String() {
	case "invalid":
		limiterEvent = "allowed"
	case "throttled":
		limiterEvent = "throttled"
	case "map_capacity":
		limiterEvent = "map_full"
	}
	if limiterEvent != "" {
		limiter, _ := contract.ParseLimiter("authentication")
		event, _ := contract.ParseLimiterEvent(limiterEvent)
		cfg.Metrics.IncLimiter(limiter, event)
	}
}

func recordConnectOnly(cfg PublicConfig, result contract.ConnectResult) {
	if cfg.Metrics != nil {
		cfg.Metrics.IncConnect(result)
	}
}

func recordSetup(cfg PublicConfig, result contract.ConnectResult, started time.Time) {
	if cfg.Metrics == nil {
		return
	}
	cfg.Metrics.IncConnect(result)
	outcome, _ := contract.ParseSetupOutcome("failure")
	if result.String() == "established" {
		outcome, _ = contract.ParseSetupOutcome("success")
	}
	duration := publicNow(cfg).Sub(started)
	if duration < 0 {
		duration = 0
	}
	cfg.Metrics.ObserveSetup(outcome, duration)
}

func recordPAC(cfg PublicConfig, resultName, limiterEvent string) {
	if cfg.Metrics == nil {
		return
	}
	result, _ := contract.ParsePACResult(resultName)
	cfg.Metrics.IncPAC(result)
	if limiterEvent != "" {
		limiter, _ := contract.ParseLimiter("pac")
		event, _ := contract.ParseLimiterEvent(limiterEvent)
		cfg.Metrics.IncLimiter(limiter, event)
	}
}

func publicSelfForSetup(ctx context.Context, cfg PublicConfig) (network.PublicSelfSnapshot, bool) {
	if cfg.PublicSelf == nil {
		return network.PublicSelfSnapshot{}, false
	}
	snapshot := cfg.PublicSelf.Acquire(ctx)
	return snapshot, network.FreshPublicSelfAt(snapshot, publicNow(cfg))
}

func relayEstablished(tunnel session.Tunnel, client net.Conn, rw *bufio.ReadWriter, origin net.Conn, idle, absolute time.Duration) {
	result := relayClose("io_error")
	var totals contract.ByteTotals
	defer func() { tunnel.Release(result, totals) }()
	if err := writeFrame(rw, wire.FrameConnectEstablished); err != nil {
		return
	}
	relay := RelayBufferedWithLimits(client, rw.Reader, origin, idle, absolute)
	result = relay.CloseResult
	totals = contract.ByteTotals{ClientToOrigin: relay.ClientToOrigin, OriginToClient: relay.OriginToClient}
}

func writePublic(w http.ResponseWriter, r *http.Request, c *session.Coordinator, frame wire.Frame) {
	writePublicPayload(w, r, c, frame, nil)
}

func writePublicPayload(w http.ResponseWriter, r *http.Request, c *session.Coordinator, frame wire.Frame, payload []byte) {
	if c != nil {
		if _, owned := wire.ConnectionOwner(r); owned {
			_ = WriteFixedResponse(w, r, c, frame, payload)
			return
		}
	}
	if frame == wire.FramePACOK {
		w.Header().Set("Connection", "close")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
		return
	}
	status, body := publicFrameStatus(frame)
	w.Header().Set("Connection", "close")
	switch frame {
	case wire.FrameMethodNotAllowedConnect:
		w.Header().Set("Allow", "CONNECT")
	case wire.FrameMethodNotAllowedGet:
		w.Header().Set("Allow", "GET")
	case wire.FrameProxyAuthenticationRequired:
		w.Header().Set("Proxy-Authenticate", `Basic realm="claude-egress-proxy"`)
	case wire.FrameTooManyRequests:
		w.Header().Set("Retry-After", "60")
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
	case wire.FrameMethodNotAllowedGet:
		return http.StatusMethodNotAllowed, "method not allowed\n"
	case wire.FrameNotFound:
		return http.StatusNotFound, "not found\n"
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
	case wire.FrameTooManyRequests:
		return http.StatusTooManyRequests, "too many requests\n"
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

func writeFrameThenRelease(rw *bufio.ReadWriter, frame wire.Frame, release func()) {
	_ = writeFrame(rw, frame)
	release()
}
func resultFor(s string) contract.ConnectResult {
	r, ok := contract.ParseConnectResult(s)
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
