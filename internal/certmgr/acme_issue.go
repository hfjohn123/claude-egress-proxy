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
	"errors"
	"net/http"

	"golang.org/x/crypto/acme"
)

type acmeProtocol interface {
	SetKey(crypto.Signer)
	Register(context.Context, *acme.Account, func(string) bool) (*acme.Account, error)
	GetReg(context.Context, string) (*acme.Account, error)
	AuthorizeOrder(context.Context, []acme.AuthzID, ...acme.OrderOption) (*acme.Order, error)
	GetAuthorization(context.Context, string) (*acme.Authorization, error)
	TLSALPN01ChallengeCert(string, string, ...acme.CertOption) (tls.Certificate, error)
	Accept(context.Context, *acme.Challenge) (*acme.Challenge, error)
	WaitAuthorization(context.Context, string) (*acme.Authorization, error)
	WaitOrder(context.Context, string) (*acme.Order, error)
	CreateOrderCert(context.Context, string, []byte, bool) ([][]byte, string, error)
}

type protocolClient struct{ client *acme.Client }

func (p protocolClient) SetKey(key crypto.Signer) { p.client.Key = key }
func (p protocolClient) Register(ctx context.Context, account *acme.Account, prompt func(string) bool) (*acme.Account, error) {
	return p.client.Register(ctx, account, prompt)
}
func (p protocolClient) GetReg(ctx context.Context, url string) (*acme.Account, error) {
	return p.client.GetReg(ctx, url)
}
func (p protocolClient) AuthorizeOrder(ctx context.Context, ids []acme.AuthzID, options ...acme.OrderOption) (*acme.Order, error) {
	return p.client.AuthorizeOrder(ctx, ids, options...)
}
func (p protocolClient) GetAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return p.client.GetAuthorization(ctx, url)
}
func (p protocolClient) TLSALPN01ChallengeCert(token, identifier string, options ...acme.CertOption) (tls.Certificate, error) {
	return p.client.TLSALPN01ChallengeCert(token, identifier, options...)
}
func (p protocolClient) Accept(ctx context.Context, challenge *acme.Challenge) (*acme.Challenge, error) {
	return p.client.Accept(ctx, challenge)
}
func (p protocolClient) WaitAuthorization(ctx context.Context, url string) (*acme.Authorization, error) {
	return p.client.WaitAuthorization(ctx, url)
}
func (p protocolClient) WaitOrder(ctx context.Context, url string) (*acme.Order, error) {
	return p.client.WaitOrder(ctx, url)
}
func (p protocolClient) CreateOrderCert(ctx context.Context, url string, csr []byte, bundle bool) ([][]byte, string, error) {
	return p.client.CreateOrderCert(ctx, url, csr, bundle)
}

type DirectManagedACMEConfig struct {
	ManagedACMEConfig
	DirectoryURL string
	Transport    http.RoundTripper
}

func NewManagedACME(config DirectManagedACMEConfig) (*ManagedACME, error) {
	client, err := NewACMEClient(ACMEConfig{DirectoryURL: config.DirectoryURL, Transport: config.Transport})
	if err != nil {
		return nil, err
	}
	return newManagedACME(config.ManagedACMEConfig, func(ctx context.Context, manager *Manager, account crypto.Signer) (issuedACME, error) {
		return issueDirectACME(ctx, manager, account, protocolClient{client: client.Client}, config.Hostname)
	})
}

func issueDirectACME(ctx context.Context, manager *Manager, account crypto.Signer, client acmeProtocol, hostname string) (issuedACME, error) {
	if ctx == nil || manager == nil || client == nil || hostname == "" {
		return issuedACME{}, ErrACMEStateInvalid
	}
	newAccount := account == nil
	if newAccount {
		generated, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return issuedACME{}, err
		}
		account = generated
	}
	client.SetKey(account)
	if newAccount {
		if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); errors.Is(err, acme.ErrAccountAlreadyExists) {
			if _, err = client.GetReg(ctx, ""); err != nil {
				return issuedACME{}, err
			}
		} else if err != nil {
			return issuedACME{}, err
		}
	} else if _, err := client.GetReg(ctx, ""); err != nil {
		return issuedACME{}, err
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(hostname))
	if err != nil || order == nil || order.URI == "" || order.FinalizeURL == "" || len(order.AuthzURLs) == 0 || len(order.AuthzURLs) > 4 {
		return issuedACME{}, ErrACMEStateInvalid
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil || authorization == nil {
			return issuedACME{}, ErrACMEStateInvalid
		}
		if authorization.Status == acme.StatusValid {
			continue
		}
		if authorization.Status != acme.StatusPending {
			return issuedACME{}, ErrACMEStateInvalid
		}
		var challenge *acme.Challenge
		for _, candidate := range authorization.Challenges {
			if candidate != nil && candidate.Type == "tls-alpn-01" {
				challenge = candidate
				break
			}
		}
		if challenge == nil || challenge.Token == "" {
			return issuedACME{}, ErrACMEStateInvalid
		}
		challengeCertificate, err := client.TLSALPN01ChallengeCert(challenge.Token, hostname)
		if err != nil || manager.InstallChallenge(challengeCertificate) != nil {
			return issuedACME{}, ErrACMEStateInvalid
		}
		if _, err = client.Accept(ctx, challenge); err == nil {
			var completed *acme.Authorization
			completed, err = client.WaitAuthorization(ctx, authorizationURL)
			if err == nil && (completed == nil || completed.Status != acme.StatusValid) {
				err = ErrACMEStateInvalid
			}
		}
		manager.ClearChallenge()
		if err != nil {
			return issuedACME{}, err
		}
	}
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil || readyOrder == nil {
		return issuedACME{}, ErrACMEStateInvalid
	}
	finalizeURL := readyOrder.FinalizeURL
	if finalizeURL == "" {
		finalizeURL = order.FinalizeURL
	}
	certificateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return issuedACME{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, certificateKey)
	if err != nil {
		return issuedACME{}, err
	}
	chain, _, err := client.CreateOrderCert(ctx, finalizeURL, csr, true)
	if err != nil || len(chain) == 0 {
		return issuedACME{}, ErrACMEStateInvalid
	}
	certificate := tls.Certificate{Certificate: chain, PrivateKey: certificateKey}
	accountDER, err := x509.MarshalPKCS8PrivateKey(account)
	if err != nil {
		return issuedACME{}, err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(certificateKey)
	if err != nil {
		return issuedACME{}, err
	}
	certificatePEM := make([]byte, 0)
	for _, der := range chain {
		certificatePEM = append(certificatePEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return issuedACME{Certificate: certificate, State: ACMEState{
		AccountKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: accountDER}), CertificatePEM: certificatePEM,
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}),
	}}, nil
}
