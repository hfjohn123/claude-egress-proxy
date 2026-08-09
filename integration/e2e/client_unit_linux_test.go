//go:build linux

package e2e_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestReadConnectStatusAcceptsOnlyClosedHTTP11Responses(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    int
		wantErr bool
	}{
		{"authentication required", "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", http.StatusProxyAuthRequired, false},
		{"established", "HTTP/1.1 200 Connection Established\r\n\r\n", http.StatusOK, false},
		{"wrong protocol", "HTTP/1.0 200 Connection Established\r\n\r\n", 0, true},
		{"unexpected status", "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n", 0, true},
		{"oversized", "HTTP/1.1 407 Proxy Authentication Required\r\nX-Fill: " + strings.Repeat("x", 4096) + "\r\n\r\n", 0, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := readConnectStatus(bufio.NewReader(strings.NewReader(test.raw)))
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("status = %d, err = %v; want %d, error=%v", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestOriginExchangeRequiresExactSentinel(t *testing.T) {
	bundle, err := generatePKI(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(bundle.originCertPEM, bundle.originKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.caPEM) {
		t.Fatal("CA PEM rejected")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sentinel := []byte("e2e-sentinel")
	origin, err := startOrigin(ctx, "127.0.0.1:0", certificate, sentinel)
	if err != nil {
		t.Fatal(err)
	}
	defer origin.Close()

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "origin.e2e.invalid", NextProtos: []string{"http/1.1"}}, ForceAttemptHTTP2: false}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+origin.Address()+"/e2e", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "origin.e2e.invalid"
	request.Header.Set("X-E2E-Sentinel", string(sentinel))
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || string(body) != string(sentinel) {
		t.Fatalf("response = %d %q, %v", response.StatusCode, body, err)
	}

	badRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+origin.Address()+"/e2e", nil)
	if err != nil {
		t.Fatal(err)
	}
	badRequest.Host = "origin.e2e.invalid"
	badRequest.Header.Set("X-E2E-Sentinel", "mutated")
	badResponse, badErr := client.Do(badRequest)
	if badErr == nil {
		_ = badResponse.Body.Close()
		if badResponse.StatusCode == http.StatusOK {
			t.Fatal("mutated sentinel was accepted")
		}
	}
	if got := origin.Accepted(); got != 1 {
		t.Fatalf("accepted requests = %d, want 1", got)
	}
}
