package certmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedACMEFirstBootPersistsBeforePublishing(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	certificate := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	state := managedTestState(t, certificate)
	store := ACMEStore{Path: filepath.Join(t.TempDir(), "acme.json")}
	manager, err := newManagedACME(ManagedACMEConfig{Hostname: "proxy.example.com", Store: store, Now: func() time.Time { return now }}, func(context.Context, *Manager, crypto.Signer) (issuedACME, error) {
		if managerReadyFromStore(store, now) {
			t.Fatal("certificate published before durable state")
		}
		return issuedACME{Certificate: certificate, State: state}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := manager.ReloadOnce(context.Background()).String(); got != "success" {
		t.Fatalf("ReloadOnce=%s", got)
	}
	if !manager.Ready(now) {
		t.Fatal("issued certificate not published")
	}
	if _, err := store.Load(); err != nil {
		t.Fatalf("state not durable: %v", err)
	}
}

func TestManagedACMEStartAttemptsImmediatelyWhenCacheAbsent(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	certificate := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	state := managedTestState(t, certificate)
	called := make(chan struct{}, 1)
	manager, err := newManagedACME(ManagedACMEConfig{Hostname: "proxy.example.com", Store: ACMEStore{Path: filepath.Join(t.TempDir(), "acme.json")}, Now: func() time.Time { return now }}, func(context.Context, *Manager, crypto.Signer) (issuedACME, error) {
		called <- struct{}{}
		return issuedACME{Certificate: certificate, State: state}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := manager.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-called:
	case <-time.After(time.Second):
		t.Fatal("ACME Start remained a no-op")
	}
}

func TestManagedACMELoadsValidCachedCertificate(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	certificate := testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(90*24*time.Hour))
	store := ACMEStore{Path: filepath.Join(t.TempDir(), "acme.json")}
	if err := store.Save(context.Background(), managedTestState(t, certificate)); err != nil {
		t.Fatal(err)
	}
	manager, err := newManagedACME(ManagedACMEConfig{Hostname: "proxy.example.com", Store: store, Now: func() time.Time { return now }}, func(context.Context, *Manager, crypto.Signer) (issuedACME, error) {
		t.Fatal("valid 90-day cache triggered issuance")
		return issuedACME{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !manager.Ready(now) || manager.Expiry(now) != 90*24*time.Hour {
		t.Fatalf("cached certificate unavailable, expiry=%v", manager.Expiry(now))
	}
}

func TestManagedACMERetryDelayUsesInjectedJitter(t *testing.T) {
	m := &ManagedACME{jitter: func(base time.Duration) time.Duration { return base + 7*time.Second }}
	if got := m.retryDelay(time.Minute); got != time.Minute+7*time.Second {
		t.Fatalf("retry delay=%v", got)
	}
}

func TestManagedACMERetryDelayClampsJitterToContractBounds(t *testing.T) {
	m := &ManagedACME{jitter: func(time.Duration) time.Duration { return 54 * time.Second }}
	if got := m.retryDelay(time.Minute); got != time.Minute {
		t.Fatalf("minimum retry = %v", got)
	}
	m.jitter = func(time.Duration) time.Duration { return 13*time.Hour + 12*time.Minute }
	if got := m.retryDelay(12 * time.Hour); got != 12*time.Hour {
		t.Fatalf("maximum retry = %v", got)
	}
}

func managedTestState(t *testing.T, certificate tls.Certificate) ACMEState {
	t.Helper()
	account, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accountDER, _ := x509.MarshalPKCS8PrivateKey(account)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	certificatePEM := []byte{}
	for _, der := range certificate.Certificate {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return ACMEState{
		AccountKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: accountDER}),
		CertificatePEM: certificatePEM,
		PrivateKeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}
}

func managerReadyFromStore(store ACMEStore, now time.Time) bool {
	state, err := store.Load()
	if err != nil {
		return false
	}
	certificate, err := tls.X509KeyPair(state.CertificatePEM, state.PrivateKeyPEM)
	return err == nil && len(certificate.Certificate) > 0 && now.Before(now.Add(time.Hour))
}
