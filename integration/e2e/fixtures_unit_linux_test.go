//go:build linux

package e2e_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"testing"
	"time"
)

func TestGeneratedPKISeparatesNames(t *testing.T) {
	now := time.Unix(1_786_252_800, 0).UTC()
	bundle, err := generatePKI(now)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle.caPEM) {
		t.Fatal("CA PEM rejected")
	}
	proxy := parseLeaf(t, bundle.proxyCertPEM)
	origin := parseLeaf(t, bundle.originCertPEM)
	verifyAt := func(certificate *x509.Certificate, name string) error {
		_, err := certificate.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now})
		return err
	}
	if err := verifyAt(proxy, "proxy.e2e.invalid"); err != nil {
		t.Fatalf("proxy certificate: %v", err)
	}
	if err := verifyAt(origin, "origin.e2e.invalid"); err != nil {
		t.Fatalf("origin certificate: %v", err)
	}
	if err := verifyAt(proxy, "origin.e2e.invalid"); err == nil {
		t.Fatal("proxy certificate accepted origin name")
	}
}

func TestRedactRemovesEveryOccurrence(t *testing.T) {
	if got := redact("secret before secret after", "secret"); got != "[REDACTED] before [REDACTED] after" {
		t.Fatalf("redacted = %q", got)
	}
}

func TestDNSFixtureAnswersOnlyAllowedOrigin(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture, err := startDNSFixture(ctx, "127.0.0.1:0", "origin.e2e.invalid", netip.MustParseAddr("192.0.0.10"))
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	resolver := fixtureResolver(fixture.Address())
	got, err := resolver.LookupNetIP(ctx, "ip4", "origin.e2e.invalid")
	if err != nil || len(got) != 1 || got[0].String() != "192.0.0.10" {
		t.Fatalf("answer = %v, %v", got, err)
	}
	if _, err := resolver.LookupNetIP(ctx, "ip4", "unknown.e2e.invalid"); err == nil {
		t.Fatal("unknown name resolved")
	}
}

func TestDNSFixtureAnswersConfiguredNames(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture, err := startDNSFixtureForAnswers(ctx, "127.0.0.1:0", map[string]netip.Addr{
		"proxy.e2e.invalid":  netip.MustParseAddr("192.0.0.9"),
		"origin.e2e.invalid": netip.MustParseAddr("192.0.0.10"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	resolver := fixtureResolver(fixture.Address())
	for name, want := range map[string]string{"proxy.e2e.invalid": "192.0.0.9", "origin.e2e.invalid": "192.0.0.10"} {
		got, err := resolver.LookupNetIP(ctx, "ip4", name)
		if err != nil || len(got) != 1 || got[0].String() != want {
			t.Fatalf("%s answer = %v, %v", name, got, err)
		}
	}
}

func parseLeaf(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		t.Fatal("invalid certificate PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}
