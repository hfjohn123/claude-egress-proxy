package main

import (
	"context"
	"os"
	"testing"
)

func TestRunForegroundInstallsCancellationContext(t *testing.T) {
	var signals []os.Signal
	notify := func(parent context.Context, requested ...os.Signal) (context.Context, context.CancelFunc) {
		signals = append(signals, requested...)
		ctx, cancel := context.WithCancel(parent)
		cancel()
		return ctx, func() {}
	}
	called := false
	code := runForeground(func(ctx context.Context) int {
		called = true
		if ctx.Err() == nil {
			t.Fatal("foreground context was not canceled")
		}
		return 7
	}, notify)
	if code != 7 || !called || len(signals) != 2 {
		t.Fatalf("code=%d called=%v signals=%v", code, called, signals)
	}
}
