package check

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
)

func TestHealthProbeAcceptsOnlyExactLoopbackFrameAndEOF(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	request := make(chan string, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		bytes := make([]byte, len(healthRequest))
		_, _ = io.ReadFull(conn, bytes)
		request <- string(bytes)
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
	}()
	if err := Health(context.Background(), listener.Addr().String()); err != nil {
		t.Fatal(err)
	}
	if got := <-request; got != "GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n" {
		t.Fatalf("request = %q", got)
	}
}

func TestHealthProbeRejectsNonCanonicalOrNonLoopbackAddress(t *testing.T) {
	for _, address := range []string{"localhost:80", "127.0.0.2:80", "127.0.0.1:080", "[::1%zone]:80", "[::1]:0"} {
		if err := Health(context.Background(), address); !errors.Is(err, ErrInvalidHealthAddress) {
			t.Fatalf("Health(%q) error = %v", address, err)
		}
	}
}

func TestHealthProbeRejectsWrongResponse(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			defer conn.Close()
			bytes := make([]byte, len(healthRequest))
			_, _ = io.ReadFull(conn, bytes)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope")
		}
	}()
	if err := Health(context.Background(), listener.Addr().String()); !errors.Is(err, ErrHealthProbe) {
		t.Fatalf("Health error = %v", err)
	}
}
