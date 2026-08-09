package certmgr

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

type fakeACMEProtocol struct {
	t          *testing.T
	now        time.Time
	key        crypto.Signer
	challenge  tls.Certificate
	accepted   bool
	registered bool
}

func (f *fakeACMEProtocol) SetKey(key crypto.Signer) { f.key = key }
func (f *fakeACMEProtocol) Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error) {
	f.registered = true
	return &acme.Account{URI: "https://ca.example/account/1"}, nil
}
func (f *fakeACMEProtocol) GetReg(context.Context, string) (*acme.Account, error) {
	return &acme.Account{URI: "https://ca.example/account/1"}, nil
}
func (f *fakeACMEProtocol) AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error) {
	return &acme.Order{URI: "https://ca.example/order/1", AuthzURLs: []string{"https://ca.example/auth/1"}, FinalizeURL: "https://ca.example/finalize/1"}, nil
}
func (f *fakeACMEProtocol) GetAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusPending, Challenges: []*acme.Challenge{{Type: "tls-alpn-01", Token: "token"}}}, nil
}
func (f *fakeACMEProtocol) TLSALPN01ChallengeCert(string, string, ...acme.CertOption) (tls.Certificate, error) {
	return f.challenge, nil
}
func (f *fakeACMEProtocol) Accept(context.Context, *acme.Challenge) (*acme.Challenge, error) {
	f.accepted = true
	return &acme.Challenge{Status: acme.StatusProcessing}, nil
}
func (f *fakeACMEProtocol) WaitAuthorization(context.Context, string) (*acme.Authorization, error) {
	return &acme.Authorization{Status: acme.StatusValid}, nil
}
func (f *fakeACMEProtocol) WaitOrder(context.Context, string) (*acme.Order, error) {
	return &acme.Order{Status: acme.StatusReady, FinalizeURL: "https://ca.example/finalize/1"}, nil
}
func (f *fakeACMEProtocol) CreateOrderCert(_ context.Context, _ string, csrDER []byte, _ bool) ([][]byte, string, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "proxy.example.com" {
		f.t.Fatalf("invalid CSR: %v", err)
	}
	issuerKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	issuerTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	issuerDER, _ := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, issuerKey.Public(), issuerKey)
	issuer, _ := x509.ParseCertificate(issuerDER)
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: csr.DNSNames, NotBefore: f.now.Add(-time.Hour), NotAfter: f.now.Add(90 * 24 * time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, csr.PublicKey, issuerKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return [][]byte{leafDER, issuerDER}, "https://ca.example/cert/1", nil
}

func TestDirectACMEIssuerCompletesTLSALPNOrder(t *testing.T) {
	now := time.Date(2026, 8, 9, 0, 0, 0, 0, time.UTC)
	protocol := &fakeACMEProtocol{t: t, now: now, challenge: testCertificate(t, "proxy.example.com", now.Add(-time.Hour), now.Add(time.Hour))}
	manager := New("proxy.example.com", func() time.Time { return now })
	issued, err := issueDirectACME(context.Background(), manager, nil, protocol, "proxy.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !protocol.registered || !protocol.accepted || protocol.key == nil {
		t.Fatalf("registered=%v accepted=%v key=%v", protocol.registered, protocol.accepted, protocol.key != nil)
	}
	if len(issued.State.AccountKeyPEM) == 0 || len(issued.State.CertificatePEM) == 0 || len(issued.State.PrivateKeyPEM) == 0 {
		t.Fatal("issued state incomplete")
	}
	if _, err := validateMaterial(issued.Certificate, "proxy.example.com", now); err != nil {
		t.Fatalf("issued certificate invalid: %v", err)
	}
	if _, err := manager.selectClient(&tls.ClientHelloInfo{ServerName: "proxy.example.com", SupportedProtos: []string{"acme-tls/1"}}); err == nil {
		t.Fatal("challenge remained installed after order")
	}
}
