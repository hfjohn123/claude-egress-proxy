//go:build linux

package e2e_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

type pkiBundle struct {
	caPEM         []byte
	proxyCertPEM  []byte
	proxyKeyPEM   []byte
	originCertPEM []byte
	originKeyPEM  []byte
}

func generatePKI(now time.Time) (pkiBundle, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return pkiBundle{}, fmt.Errorf("generate CA key: %w", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Claude Egress Proxy E2E CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return pkiBundle{}, fmt.Errorf("create CA certificate: %w", err)
	}
	proxyCert, proxyKey, err := generateLeaf(now, 2, "proxy.e2e.invalid", caTemplate, caKey)
	if err != nil {
		return pkiBundle{}, err
	}
	originCert, originKey, err := generateLeaf(now, 3, "origin.e2e.invalid", caTemplate, caKey)
	if err != nil {
		return pkiBundle{}, err
	}
	return pkiBundle{
		caPEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
		proxyCertPEM:  proxyCert,
		proxyKeyPEM:   proxyKey,
		originCertPEM: originCert,
		originKeyPEM:  originKey,
	}, nil
}

func generateLeaf(now time.Time, serial int64, name string, ca *x509.Certificate, caKey *ecdsa.PrivateKey) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate %s key: %w", name, err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(48 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create %s certificate: %w", name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode %s key: %w", name, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func redact(text string, forbidden ...string) string {
	for _, value := range forbidden {
		if value != "" {
			text = strings.ReplaceAll(text, value, "[REDACTED]")
		}
	}
	return text
}

type dnsFixture struct {
	address  string
	allowed  dnsmessage.Name
	answer   [4]byte
	udp      net.PacketConn
	tcp      net.Listener
	cancel   context.CancelFunc
	done     chan struct{}
	queries  atomic.Uint64
	closeErr error
	close    sync.Once
}

func startDNSFixture(ctx context.Context, address, allowedHost string, answer netip.Addr) (*dnsFixture, error) {
	if ctx == nil || !answer.Is4() || answer.Is4In6() {
		return nil, errors.New("invalid DNS fixture configuration")
	}
	allowed, err := dnsmessage.NewName(strings.TrimSuffix(allowedHost, ".") + ".")
	if err != nil {
		return nil, fmt.Errorf("allowed DNS name: %w", err)
	}
	tcp, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("listen DNS TCP: %w", err)
	}
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("listen DNS UDP: %w", err)
	}
	fixtureContext, cancel := context.WithCancel(ctx)
	f := &dnsFixture{address: tcp.Addr().String(), allowed: allowed, answer: answer.As4(), udp: udp, tcp: tcp, cancel: cancel, done: make(chan struct{})}
	var workers sync.WaitGroup
	workers.Add(2)
	go func() { defer workers.Done(); f.serveUDP(fixtureContext) }()
	go func() { defer workers.Done(); f.serveTCP(fixtureContext) }()
	go func() {
		workers.Wait()
		close(f.done)
	}()
	go func() {
		<-fixtureContext.Done()
		_ = udp.Close()
		_ = tcp.Close()
	}()
	return f, nil
}

func (f *dnsFixture) Address() string { return f.address }
func (f *dnsFixture) Queries() uint64 { return f.queries.Load() }

func (f *dnsFixture) Close() error {
	f.close.Do(func() {
		f.cancel()
		errUDP := f.udp.Close()
		errTCP := f.tcp.Close()
		<-f.done
		if errUDP != nil && !errors.Is(errUDP, net.ErrClosed) {
			f.closeErr = errUDP
		} else if errTCP != nil && !errors.Is(errTCP, net.ErrClosed) {
			f.closeErr = errTCP
		}
	})
	return f.closeErr
}

func (f *dnsFixture) serveUDP(ctx context.Context) {
	buffer := make([]byte, 512)
	for {
		_ = f.udp.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, peer, err := f.udp.ReadFrom(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		response, err := f.response(buffer[:n])
		if err == nil && len(response) <= 512 {
			_, _ = f.udp.WriteTo(response, peer)
		}
	}
}

func (f *dnsFixture) serveTCP(ctx context.Context) {
	listener, ok := f.tcp.(*net.TCPListener)
	if !ok {
		return
	}
	for {
		_ = listener.SetDeadline(time.Now().Add(200 * time.Millisecond))
		connection, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				continue
			}
			return
		}
		f.handleTCP(connection)
	}
}

func (f *dnsFixture) handleTCP(connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	var length [2]byte
	if _, err := io.ReadFull(connection, length[:]); err != nil {
		return
	}
	n := int(binary.BigEndian.Uint16(length[:]))
	if n == 0 || n > 4096 {
		return
	}
	request := make([]byte, n)
	if _, err := io.ReadFull(connection, request); err != nil {
		return
	}
	response, err := f.response(request)
	if err != nil || len(response) > 4096 {
		return
	}
	binary.BigEndian.PutUint16(length[:], uint16(len(response)))
	_, _ = connection.Write(append(length[:], response...))
}

func (f *dnsFixture) response(request []byte) ([]byte, error) {
	var parser dnsmessage.Parser
	header, err := parser.Start(request)
	if err != nil || header.Response {
		return nil, errors.New("invalid DNS request")
	}
	question, err := parser.Question()
	if err != nil {
		return nil, errors.New("invalid DNS question")
	}
	if _, err := parser.Question(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		return nil, errors.New("multiple DNS questions")
	}
	f.queries.Add(1)
	allowed := question.Name == f.allowed && question.Type == dnsmessage.TypeA && question.Class == dnsmessage.ClassINET
	responseHeader := dnsmessage.Header{ID: header.ID, Response: true, Authoritative: true}
	if !allowed {
		responseHeader.RCode = dnsmessage.RCodeNameError
	}
	builder := dnsmessage.NewBuilder(nil, responseHeader)
	builder.EnableCompression()
	if err := builder.StartQuestions(); err != nil {
		return nil, err
	}
	if err := builder.Question(question); err != nil {
		return nil, err
	}
	if allowed {
		if err := builder.StartAnswers(); err != nil {
			return nil, err
		}
		resource := dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 0}
		if err := builder.AResource(resource, dnsmessage.AResource{A: f.answer}); err != nil {
			return nil, err
		}
	}
	return builder.Finish()
}

func fixtureResolver(address string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
}
