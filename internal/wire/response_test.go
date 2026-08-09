package wire

import (
	"bytes"
	"testing"
)

func TestFrameUsesExactIndependentGolden(t *testing.T) {
	tests := []struct {
		name       string
		method     []byte
		frame      Frame
		body, want string
	}{
		{"bad request", nil, FrameBadRequest, "", "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\nbad request\n"},
		{"forbidden", nil, FrameForbidden, "", "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nConnection: close\r\n\r\nforbidden\n"},
		{"not found", nil, FrameNotFound, "", "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot found\n"},
		{"allow connect", nil, FrameMethodNotAllowedConnect, "", "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 19\r\nConnection: close\r\n\r\nmethod not allowed\n"},
		{"allow get", nil, FrameMethodNotAllowedGet, "", "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 19\r\nConnection: close\r\n\r\nmethod not allowed\n"},
		{"proxy auth", nil, FrameProxyAuthenticationRequired, "", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"claude-egress-proxy\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 30\r\nConnection: close\r\n\r\nproxy authentication required\n"},
		{"rate", nil, FrameTooManyRequests, "", "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 18\r\nConnection: close\r\n\r\ntoo many requests\n"},
		{"internal", nil, FrameInternalError, "", "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 15\r\nConnection: close\r\n\r\ninternal_error\n"},
		{"gateway", nil, FrameBadGateway, "", "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\nbad gateway\n"},
		{"unavailable", nil, FrameServiceUnavailable, "", "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 20\r\nConnection: close\r\n\r\nservice unavailable\n"},
		{"timeout", nil, FrameGatewayTimeout, "", "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 16\r\nConnection: close\r\n\r\ngateway timeout\n"},
		{"version", nil, FrameHTTPVersionNotSupported, "", "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 27\r\nConnection: close\r\n\r\nhttp version not supported\n"},
		{"head", []byte("HEAD"), FrameNotFound, "", "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{"connect", nil, FrameConnectEstablished, "", "HTTP/1.1 200 Connection Established\r\n\r\n"},
		{"pac", nil, FramePACOK, "x", "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"},
		{"health", nil, FrameHealthOK, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n"},
		{"ready", nil, FrameReadyOK, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 6\r\nConnection: close\r\n\r\nready\n"},
		{"not ready", nil, FrameNotReady, "", "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 10\r\nConnection: close\r\n\r\nnot ready\n"},
		{"metrics unauthorized", nil, FrameMetricsUnauthorized, "", "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"metrics\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 13\r\nConnection: close\r\n\r\nunauthorized\n"},
		{"metrics", nil, FrameMetricsOK, "# x\n", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: 4\r\nConnection: close\r\n\r\n# x\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteFrame(&out, tt.method, tt.frame, []byte(tt.body)); err != nil || out.String() != tt.want {
				t.Fatalf("got %q, %v", out.String(), err)
			}
		})
	}
}

func TestFrameHEADGoldens(t *testing.T) {
	tests := []struct {
		frame      Frame
		body, want string
	}{
		{FrameBadRequest, "", "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameForbidden, "", "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameNotFound, "", "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameMethodNotAllowedConnect, "", "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameMethodNotAllowedGet, "", "HTTP/1.1 405 Method Not Allowed\r\nAllow: GET\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameProxyAuthenticationRequired, "", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"claude-egress-proxy\"\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameTooManyRequests, "", "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 60\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameInternalError, "", "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameBadGateway, "", "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameServiceUnavailable, "", "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameGatewayTimeout, "", "HTTP/1.1 504 Gateway Timeout\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameHTTPVersionNotSupported, "", "HTTP/1.1 505 HTTP Version Not Supported\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FramePACOK, "x", "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n"},
		{FrameHealthOK, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameReadyOK, "", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameNotReady, "", "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameMetricsUnauthorized, "", "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer realm=\"metrics\"\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{FrameMetricsOK, "# x\n", "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nConnection: close\r\n\r\n"},
	}
	for _, tt := range tests {
		t.Run(string(tt.frame), func(t *testing.T) {
			var out bytes.Buffer
			if err := WriteFrame(&out, []byte("HEAD"), tt.frame, []byte(tt.body)); err != nil || out.String() != tt.want {
				t.Fatalf("got %q, %v", out.String(), err)
			}
		})
	}
}

func TestFrameCoverageMatchesClosedContract(t *testing.T) {
	if len(AllFrames()) != len(frameSpecs) {
		t.Fatalf("frames=%d specs=%d", len(AllFrames()), len(frameSpecs))
	}
	for _, f := range AllFrames() {
		if _, ok := ParseFrame(string(f)); !ok {
			t.Fatalf("missing %s", f)
		}
	}
}
