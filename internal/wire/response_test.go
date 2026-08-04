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
		{"proxy auth", nil, FrameProxyAuthenticationRequired, "", "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"claude-egress-proxy\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 30\r\nConnection: close\r\n\r\nproxy authentication required\n"},
		{"head", []byte("HEAD"), FrameNotFound, "", "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"},
		{"connect", nil, FrameConnectEstablished, "", "HTTP/1.1 200 Connection Established\r\n\r\n"},
		{"pac", nil, FramePACOK, "x", "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nCache-Control: no-store\r\nContent-Length: 1\r\nConnection: close\r\n\r\nx"},
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
