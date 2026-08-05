package certmgr

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestSelectExactSNIAndALPN(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	serving := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	challenge := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	m := New("proxy.example.com", func() time.Time { return now })
	m.InstallServing(serving)
	m.InstallChallenge(challenge)

	tests := []struct {
		name  string
		sni   string
		alpn  []string
		want  *tls.Certificate
		proto string
	}{
		{"serving no alpn", "proxy.example.com", nil, &serving, ""},
		{"serving http1", "proxy.example.com", []string{"http/1.1"}, &serving, "http/1.1"},
		{"challenge sole acme", "proxy.example.com", []string{"acme-tls/1"}, &challenge, "acme-tls/1"},
		{"mixed acme first", "proxy.example.com", []string{"acme-tls/1", "http/1.1"}, nil, ""},
		{"mixed acme last", "proxy.example.com", []string{"http/1.1", "acme-tls/1"}, nil, ""},
		{"wrong sni", "wrong.example.com", []string{"http/1.1"}, nil, ""},
		{"missing sni", "", []string{"http/1.1"}, nil, ""},
		{"unsupported alpn", "proxy.example.com", []string{"h2"}, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := m.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{ServerName: tt.sni, SupportedProtos: tt.alpn})
			if tt.want == nil {
				if err == nil {
					t.Fatal("selection succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("selection: %v", err)
			}
			if config.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion=%x", config.MinVersion)
			}
			if len(config.Certificates) != 1 || string(config.Certificates[0].Certificate[0]) != string(tt.want.Certificate[0]) {
				t.Fatal("wrong certificate")
			}
			if len(config.NextProtos) != 0 && config.NextProtos[0] != tt.proto {
				t.Fatalf("NextProtos=%q, want %q", config.NextProtos, tt.proto)
			}
			for _, p := range config.NextProtos {
				if p == "h2" {
					t.Fatal("advertised h2")
				}
			}
		})
	}
}

func TestSelectCertificateTimeBoundary(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	cert := testCertificate(t, "proxy.example.com", now, now.Add(time.Hour))
	for _, tt := range []struct {
		name string
		at   time.Time
		want bool
	}{
		{"before", now.Add(-time.Nanosecond), false}, {"not before", now, true},
		{"before expiry", now.Add(time.Hour - time.Nanosecond), true}, {"expiry", now.Add(time.Hour), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := New("proxy.example.com", func() time.Time { return tt.at })
			m.InstallServing(cert)
			_, err := m.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "proxy.example.com", SupportedProtos: []string{"http/1.1"}})
			if (err == nil) != tt.want {
				t.Fatalf("success=%v want %v (%v)", err == nil, tt.want, err)
			}
		})
	}
}

func TestRealTLSHandshakeNegotiatesOnlyHTTP1(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	m := New("proxy.example.com", func() time.Time { return now })
	if err := m.InstallServing(testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour))); err != nil {
		t.Fatal(err)
	}
	serverRaw, clientRaw := net.Pipe()
	defer clientRaw.Close()
	server := tls.Server(serverRaw, m.TLSConfig())
	done := make(chan error, 1)
	go func() { done <- server.Handshake(); _ = server.Close() }()
	client := tls.Client(clientRaw, &tls.Config{ServerName: "proxy.example.com", InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("protocol=%q", got)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testCertificate(t *testing.T, host string, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
