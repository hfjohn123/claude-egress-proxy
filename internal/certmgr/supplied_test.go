package certmgr

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestSuppliedReloadKeepsLastValidCertificate(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	old := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	writePair(t, certPath, keyPath, old)
	m, err := NewSupplied(SuppliedConfig{Hostname: "proxy.example.com", CertificateFile: certPath, PrivateKeyFile: keyPath, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("NewSupplied: %v", err)
	}
	bad := testCertificate(t, "wrong.example.com", now.Add(-time.Hour), now.Add(time.Hour))
	writePair(t, certPath, keyPath, bad)
	if got := m.ReloadOnce(t.Context()); got.String() != "failure" {
		t.Fatalf("bad reload=%s", got.String())
	}
	assertSelectedCertificate(t, m, old)
	newCert := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(2*time.Hour))
	writePair(t, certPath, keyPath, newCert)
	if got := m.ReloadOnce(t.Context()); got.String() != "recovered" {
		t.Fatalf("recovery=%s", got.String())
	}
	assertSelectedCertificate(t, m, newCert)
}

func TestSuppliedRejectsExpiredInitialCertificate(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	writePair(t, certPath, keyPath, testCertificate(t, "proxy.example.com", now.Add(-2*time.Hour), now.Add(-time.Nanosecond)))
	if _, err := NewSupplied(SuppliedConfig{Hostname: "proxy.example.com", CertificateFile: certPath, PrivateKeyFile: keyPath, Now: func() time.Time { return now }}); err == nil {
		t.Fatal("accepted expired certificate")
	}
}

func TestSuppliedStartIsIdempotent(t *testing.T) {
	m := &Supplied{Manager: New("proxy.example.com", time.Now), clock: timebase.Real{}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !m.started.Load() {
		t.Fatal("poller did not start")
	}
}

func writePair(t *testing.T, certPath, keyPath string, cert tls.Certificate) {
	t.Helper()
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertSelectedCertificate(t *testing.T, m *Supplied, want tls.Certificate) {
	t.Helper()
	config, err := m.TLSConfig().GetConfigForClient(&tls.ClientHelloInfo{ServerName: "proxy.example.com", SupportedProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(config.Certificates[0].Certificate[0]) != string(want.Certificate[0]) {
		t.Fatal("certificate changed unexpectedly")
	}
}
