package certmgr

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

var errNoCertificate = errors.New("no certificate")

func (m *Manager) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, GetConfigForClient: m.selectClient}
}

func (m *Manager) selectClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	if hello == nil || hello.ServerName != m.hostname {
		return nil, errNoCertificate
	}
	s := m.snapshot.Load()
	if s == nil {
		return nil, errNoCertificate
	}
	now := m.now()
	if soleACME(hello.SupportedProtos) {
		if !validAt(s.challenge, now) {
			return nil, errNoCertificate
		}
		return configFor(s.challenge.certificate, "acme-tls/1"), nil
	}
	if containsACME(hello.SupportedProtos) || (!noALPN(hello.SupportedProtos) && !containsHTTP1(hello.SupportedProtos)) || !validAt(s.serving, now) {
		return nil, errNoCertificate
	}
	if noALPN(hello.SupportedProtos) {
		return configFor(s.serving.certificate, ""), nil
	}
	return configFor(s.serving.certificate, "http/1.1"), nil
}

func configFor(c tls.Certificate, protocol string) *tls.Config {
	config := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{c}}
	if protocol != "" {
		config.NextProtos = []string{protocol}
	}
	return config
}

func validAt(m *material, now time.Time) bool {
	return m != nil && !now.Before(m.notBefore) && now.Before(m.notAfter)
}
func noALPN(p []string) bool { return len(p) == 0 }
func containsHTTP1(p []string) bool {
	for _, value := range p {
		if value == "http/1.1" {
			return true
		}
	}
	return false
}
func containsACME(p []string) bool {
	for _, value := range p {
		if value == "acme-tls/1" {
			return true
		}
	}
	return false
}
func soleACME(p []string) bool { return len(p) == 1 && p[0] == "acme-tls/1" }

func validateMaterial(c tls.Certificate, hostname string, now time.Time) (*material, error) {
	if len(c.Certificate) == 0 || c.PrivateKey == nil {
		return nil, errNoCertificate
	}
	chain := make([]*x509.Certificate, len(c.Certificate))
	for i, der := range c.Certificate {
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errNoCertificate
		}
		chain[i] = parsed
	}
	leaf := chain[0]
	if !exactDNSName(leaf, hostname) || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errNoCertificate
	}
	cloned, err := cloneCertificate(c)
	if err != nil {
		return nil, errNoCertificate
	}
	return &material{certificate: cloned, notBefore: leaf.NotBefore, notAfter: leaf.NotAfter}, nil
}

func cloneCertificate(c tls.Certificate) (tls.Certificate, error) {
	der := make([][]byte, len(c.Certificate))
	for i, bytes := range c.Certificate {
		der[i] = append([]byte(nil), bytes...)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := x509.ParsePKCS8PrivateKey(append([]byte(nil), keyBytes...))
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: der, PrivateKey: key, OCSPStaple: append([]byte(nil), c.OCSPStaple...), SignedCertificateTimestamps: cloneBytes(c.SignedCertificateTimestamps)}, nil
}

func cloneBytes(in [][]byte) [][]byte {
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

func exactDNSName(c *x509.Certificate, hostname string) bool {
	for _, name := range c.DNSNames {
		if name == hostname {
			return true
		}
	}
	return false
}
