package proxy

import (
	"bytes"
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

func TestRelayBufferedDeliversBytesReadBeforeHijack(t *testing.T) {
	client, tunnel := net.Pipe()
	origin, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	done := make(chan RelayResult, 1)
	go func() { done <- RelayBuffered(tunnel, bytes.NewBufferString("early"), origin) }()
	buf := make([]byte, len("early"))
	if _, err := upstream.Read(buf); err != nil || string(buf) != "early" {
		t.Fatalf("upstream=%q err=%v", buf, err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestRelayWithLimitsReturnsCanonicalCleanOutcome(t *testing.T) {
	client, tunnel := net.Pipe()
	origin, upstream := net.Pipe()
	defer upstream.Close()
	done := make(chan RelayResult, 1)
	go func() { done <- RelayBufferedWithLimits(tunnel, tunnel, origin, time.Second, 0) }()
	_ = client.Close()
	select {
	case got := <-done:
		if got.CloseResult.String() != "clean" {
			t.Fatalf("close result=%s want clean", got.CloseResult)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not stop")
	}
}

func TestRelayWithLimitsEnforcesIdleTimeout(t *testing.T) {
	client, tunnel := net.Pipe()
	origin, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	done := make(chan RelayResult, 1)
	go func() { done <- RelayBufferedWithLimits(tunnel, tunnel, origin, 20*time.Millisecond, 0) }()
	select {
	case got := <-done:
		if got.CloseResult.String() != "idle_timeout" {
			t.Fatalf("close result=%s want idle_timeout", got.CloseResult)
		}
	case <-time.After(time.Second):
		t.Fatal("idle timeout did not stop relay")
	}
}

func TestRelayWithLimitsEnforcesAbsoluteLifetime(t *testing.T) {
	client, tunnel := net.Pipe()
	origin, upstream := net.Pipe()
	defer client.Close()
	defer upstream.Close()
	done := make(chan RelayResult, 1)
	go func() { done <- RelayBufferedWithLimits(tunnel, tunnel, origin, time.Second, 20*time.Millisecond) }()
	select {
	case got := <-done:
		if got.CloseResult.String() != "absolute_lifetime" {
			t.Fatalf("close result=%s want absolute_lifetime", got.CloseResult)
		}
	case <-time.After(time.Second):
		t.Fatal("absolute lifetime did not stop relay")
	}
}
