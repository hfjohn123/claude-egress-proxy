//go:build linux

package e2e_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxFixtureHTTPBytes = 4096

type originFixture struct {
	address     string
	listener    net.Listener
	cancel      context.CancelFunc
	done        chan struct{}
	connections atomic.Uint64
	accepted    atomic.Uint64
	close       sync.Once
	closeErr    error
}

func startOrigin(ctx context.Context, address string, certificate tls.Certificate, sentinel []byte) (*originFixture, error) {
	if ctx == nil || len(sentinel) == 0 {
		return nil, errors.New("invalid origin fixture configuration")
	}
	base, err := net.Listen("tcp4", address)
	if err != nil {
		return nil, fmt.Errorf("listen origin: %w", err)
	}
	fixtureContext, cancel := context.WithCancel(ctx)
	listener := tls.NewListener(base, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	o := &originFixture{address: base.Addr().String(), listener: listener, cancel: cancel, done: make(chan struct{})}
	go o.serve(fixtureContext, append([]byte(nil), sentinel...))
	go func() {
		<-fixtureContext.Done()
		_ = listener.Close()
	}()
	return o, nil
}

func (o *originFixture) Address() string     { return o.address }
func (o *originFixture) Accepted() uint64    { return o.accepted.Load() }
func (o *originFixture) Connections() uint64 { return o.connections.Load() }

func (o *originFixture) Close() error {
	o.close.Do(func() {
		o.cancel()
		err := o.listener.Close()
		<-o.done
		if err != nil && !errors.Is(err, net.ErrClosed) {
			o.closeErr = err
		}
	})
	return o.closeErr
}

func (o *originFixture) serve(ctx context.Context, sentinel []byte) {
	defer close(o.done)
	for {
		connection, err := o.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		o.connections.Add(1)
		o.handle(connection, sentinel)
	}
}

func (o *originFixture) handle(connection net.Conn, sentinel []byte) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	request, err := http.ReadRequest(bufio.NewReaderSize(connection, maxFixtureHTTPBytes))
	if err != nil {
		return
	}
	if request.Body != nil {
		_ = request.Body.Close()
	}
	valid := request.Method == http.MethodGet && request.Host == "origin.e2e.invalid" && request.URL.RequestURI() == "/e2e" && request.Header.Get("X-E2E-Sentinel") == string(sentinel)
	if !valid {
		_, _ = io.WriteString(connection, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	o.accepted.Add(1)
	_, _ = fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(sentinel))
	_, _ = connection.Write(sentinel)
}

type proxyClient struct {
	proxyAddress    string
	proxyName       string
	originAuthority string
	originName      string
	roots           *x509.CertPool
}

func (c proxyClient) reject(authHeader string) error {
	connection, reader, err := c.connectOuter()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeConnect(connection, c.originAuthority, authHeader); err != nil {
		return err
	}
	status, err := readConnectStatus(reader)
	if err != nil {
		return err
	}
	if status != http.StatusProxyAuthRequired {
		return fmt.Errorf("proxy rejection status %d", status)
	}
	return requireServerEOF(reader)
}

func (c proxyClient) roundTrip(authHeader string, sentinel []byte) error {
	connection, reader, err := c.connectOuter()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := writeConnect(connection, c.originAuthority, authHeader); err != nil {
		return err
	}
	status, err := readConnectStatus(reader)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("proxy CONNECT status %d", status)
	}
	inner := tls.Client(connection, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots, ServerName: c.originName, NextProtos: []string{"http/1.1"}})
	if err := inner.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return errors.New("set inner TLS deadline")
	}
	if err := inner.Handshake(); err != nil {
		return fmt.Errorf("inner TLS handshake: %w", err)
	}
	if inner.ConnectionState().NegotiatedProtocol != "http/1.1" {
		return errors.New("inner TLS ALPN mismatch")
	}
	request := "GET /e2e HTTP/1.1\r\nHost: " + c.originName + "\r\nX-E2E-Sentinel: " + string(sentinel) + "\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(inner, request); err != nil {
		return errors.New("write inner request")
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(inner, maxFixtureHTTPBytes), nil)
	if err != nil {
		return fmt.Errorf("read inner response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFixtureHTTPBytes+1))
	if err != nil || len(body) > maxFixtureHTTPBytes {
		return errors.New("read inner response body")
	}
	if response.StatusCode != http.StatusOK || !bytes.Equal(body, sentinel) {
		return fmt.Errorf("inner response mismatch status=%d bytes=%d", response.StatusCode, len(body))
	}
	return nil
}

func (c proxyClient) connectOuter() (net.Conn, *bufio.Reader, error) {
	plain, err := (&net.Dialer{Timeout: 3 * time.Second}).Dial("tcp4", c.proxyAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("dial proxy: %w", err)
	}
	outer := tls.Client(plain, &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: c.roots, ServerName: c.proxyName, NextProtos: []string{"http/1.1"}})
	if err := outer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		_ = plain.Close()
		return nil, nil, errors.New("set outer TLS deadline")
	}
	if err := outer.Handshake(); err != nil {
		_ = plain.Close()
		return nil, nil, fmt.Errorf("outer TLS handshake: %w", err)
	}
	if outer.ConnectionState().NegotiatedProtocol != "http/1.1" {
		_ = outer.Close()
		return nil, nil, errors.New("outer TLS ALPN mismatch")
	}
	return outer, bufio.NewReaderSize(outer, maxFixtureHTTPBytes), nil
}

func writeConnect(writer io.Writer, authority, authHeader string) error {
	var request strings.Builder
	request.WriteString("CONNECT ")
	request.WriteString(authority)
	request.WriteString(" HTTP/1.1\r\nHost: ")
	request.WriteString(authority)
	request.WriteString("\r\n")
	if authHeader != "" {
		request.WriteString("Proxy-Authorization: ")
		request.WriteString(authHeader)
		request.WriteString("\r\n")
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(writer, request.String()); err != nil {
		return errors.New("write CONNECT request")
	}
	return nil
}

func readConnectStatus(reader *bufio.Reader) (int, error) {
	used := 0
	connectionClose := false
	readLine := func() (string, error) {
		line, err := reader.ReadString('\n')
		used += len(line)
		if used > maxFixtureHTTPBytes {
			return "", errors.New("CONNECT response too large")
		}
		if err != nil || !strings.HasSuffix(line, "\r\n") {
			return "", fmt.Errorf("invalid CONNECT response: bytes=%d read=%v", len(line), err)
		}
		return line, nil
	}
	statusLine, err := readLine()
	if err != nil {
		return 0, err
	}
	parts := strings.SplitN(strings.TrimSuffix(statusLine, "\r\n"), " ", 3)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || len(parts[1]) != 3 {
		return 0, errors.New("invalid CONNECT status line")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status != http.StatusOK && status != http.StatusProxyAuthRequired {
		return 0, errors.New("unexpected CONNECT status")
	}
	for {
		line, err := readLine()
		if err != nil {
			return 0, err
		}
		if line == "\r\n" {
			if status == http.StatusProxyAuthRequired && !connectionClose {
				return 0, errors.New("proxy rejection did not require connection close")
			}
			return status, nil
		}
		name, value, ok := strings.Cut(strings.TrimSuffix(line, "\r\n"), ":")
		if !ok {
			return 0, errors.New("invalid CONNECT header")
		}
		if strings.EqualFold(name, "Connection") && strings.EqualFold(strings.TrimSpace(value), "close") {
			connectionClose = true
		}
	}
}

func requireServerEOF(reader *bufio.Reader) error {
	remainder, err := io.ReadAll(io.LimitReader(reader, maxFixtureHTTPBytes+1))
	if err != nil {
		return errors.New("proxy rejection connection remained open")
	}
	if len(remainder) > maxFixtureHTTPBytes {
		return errors.New("proxy rejection response too large")
	}
	return nil
}
