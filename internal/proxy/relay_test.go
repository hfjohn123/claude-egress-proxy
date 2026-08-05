package proxy

import (
	"net"
	"testing"
	"time"
)

func TestRelayCopiesOpaqueBytesBothDirections(t *testing.T) {
	client, tunnel := net.Pipe()
	origin, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	done := make(chan RelayResult, 1)
	go func() { done <- Relay(tunnel, origin) }()
	if _, err := client.Write([]byte("client hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("client hello"))
	if _, err := upstream.Read(buf); err != nil || string(buf) != "client hello" {
		t.Fatalf("upstream=%q err=%v", buf, err)
	}
	if _, err := upstream.Write([]byte("origin bytes")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("origin bytes"))
	if _, err := client.Read(buf); err != nil || string(buf) != "origin bytes" {
		t.Fatalf("client=%q err=%v", buf, err)
	}
	_ = client.Close()
	select {
	case got := <-done:
		if got.ClientToOrigin != uint64(len("client hello")) || got.OriginToClient != uint64(len("origin bytes")) {
			t.Fatalf("bytes=%+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}
