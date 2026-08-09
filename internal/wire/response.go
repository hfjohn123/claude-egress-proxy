package wire

import (
	"fmt"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"io"
)

// Frame is one closed application response frame.
type Frame string

const (
	FrameBadRequest                  Frame = "bad_request"
	FrameForbidden                   Frame = "forbidden"
	FrameNotFound                    Frame = "not_found"
	FrameMethodNotAllowedConnect     Frame = "method_not_allowed_connect"
	FrameMethodNotAllowedGet         Frame = "method_not_allowed_get"
	FrameProxyAuthenticationRequired Frame = "proxy_authentication_required"
	FrameTooManyRequests             Frame = "too_many_requests"
	FrameInternalError               Frame = "internal_error"
	FrameBadGateway                  Frame = "bad_gateway"
	FrameServiceUnavailable          Frame = "service_unavailable"
	FrameGatewayTimeout              Frame = "gateway_timeout"
	FrameHTTPVersionNotSupported     Frame = "http_version_not_supported"
	FrameConnectEstablished          Frame = "connect_established"
	FramePACOK                       Frame = "pac_ok"
	FrameHealthOK                    Frame = "health_ok"
	FrameReadyOK                     Frame = "ready_ok"
	FrameNotReady                    Frame = "not_ready"
	FrameMetricsUnauthorized         Frame = "metrics_unauthorized"
	FrameMetricsOK                   Frame = "metrics_ok"
)

type frameSpec struct {
	status, special, contentType, body string
	tunnel, suppliedBody               bool
}

var frameSpecs = map[Frame]frameSpec{
	FrameBadRequest: {"400 Bad Request", "", "text/plain; charset=utf-8", "bad request\n", false, false}, FrameForbidden: {"403 Forbidden", "", "text/plain; charset=utf-8", "forbidden\n", false, false}, FrameNotFound: {"404 Not Found", "", "text/plain; charset=utf-8", "not found\n", false, false}, FrameMethodNotAllowedConnect: {"405 Method Not Allowed", "Allow: CONNECT", "text/plain; charset=utf-8", "method not allowed\n", false, false}, FrameMethodNotAllowedGet: {"405 Method Not Allowed", "Allow: GET", "text/plain; charset=utf-8", "method not allowed\n", false, false}, FrameProxyAuthenticationRequired: {"407 Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"claude-egress-proxy\"", "text/plain; charset=utf-8", "proxy authentication required\n", false, false}, FrameTooManyRequests: {"429 Too Many Requests", "Retry-After: 60", "text/plain; charset=utf-8", "too many requests\n", false, false}, FrameInternalError: {"500 Internal Server Error", "", "text/plain; charset=utf-8", "internal_error\n", false, false}, FrameBadGateway: {"502 Bad Gateway", "", "text/plain; charset=utf-8", "bad gateway\n", false, false}, FrameServiceUnavailable: {"503 Service Unavailable", "", "text/plain; charset=utf-8", "service unavailable\n", false, false}, FrameGatewayTimeout: {"504 Gateway Timeout", "", "text/plain; charset=utf-8", "gateway timeout\n", false, false}, FrameHTTPVersionNotSupported: {"505 HTTP Version Not Supported", "", "text/plain; charset=utf-8", "http version not supported\n", false, false}, FrameConnectEstablished: {"200 Connection Established", "", "", "", true, false}, FramePACOK: {"200 OK", "Cache-Control: no-store", "application/x-ns-proxy-autoconfig", "", false, true}, FrameHealthOK: {"200 OK", "", "text/plain; charset=utf-8", "ok\n", false, false}, FrameReadyOK: {"200 OK", "", "text/plain; charset=utf-8", "ready\n", false, false}, FrameNotReady: {"503 Service Unavailable", "", "text/plain; charset=utf-8", "not ready\n", false, false}, FrameMetricsUnauthorized: {"401 Unauthorized", "WWW-Authenticate: Bearer realm=\"metrics\"", "text/plain; charset=utf-8", "unauthorized\n", false, false}, FrameMetricsOK: {"200 OK", "", "text/plain; version=0.0.4; charset=utf-8", "", false, true},
}

// AllFrames returns the closed wire frame identifiers.
func AllFrames() []Frame {
	values := contract.AllFrames()
	frames := make([]Frame, len(values))
	for i, value := range values {
		frames[i] = Frame(value)
	}
	return frames
}

// ParseFrame checks a wire frame identifier against the closed contract.
func ParseFrame(value string) (Frame, bool) {
	_, ok := contract.ParseFrame(value)
	return Frame(value), ok
}

// WriteFrame writes exactly one already-selected application response frame.
func WriteFrame(w io.Writer, method []byte, frame Frame, body []byte) error {
	spec, ok := frameSpecs[frame]
	if !ok {
		return fmt.Errorf("unknown frame %q", frame)
	}
	if spec.tunnel {
		_, err := io.WriteString(w, "HTTP/1.1 200 Connection Established\r\n\r\n")
		return err
	}
	if !spec.suppliedBody {
		body = []byte(spec.body)
	}
	if _, err := fmt.Fprintf(w, "HTTP/1.1 %s\r\n", spec.status); err != nil {
		return err
	}
	if frame == FramePACOK {
		if _, err := io.WriteString(w, "Content-Type: application/x-ns-proxy-autoconfig\r\n"); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "Cache-Control: no-store\r\n"); err != nil {
			return err
		}
	} else if spec.special != "" {
		if _, err := io.WriteString(w, spec.special+"\r\n"); err != nil {
			return err
		}
	}
	if frame != FramePACOK {
		if _, err := io.WriteString(w, "Content-Type: "+spec.contentType+"\r\n"); err != nil {
			return err
		}
	}
	if string(method) == "HEAD" {
		_, err := io.WriteString(w, "Connection: close\r\n\r\n")
		return err
	}
	if _, err := fmt.Fprintf(w, "Content-Length: %d\r\nConnection: close\r\n\r\n", len(body)); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}
