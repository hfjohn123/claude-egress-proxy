package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/hfjohn123/claude-egress-proxy/internal/app"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
)

type notifyContextFunc func(context.Context, ...os.Signal) (context.Context, context.CancelFunc)

func runForeground(run func(context.Context) int, notify notifyContextFunc) int {
	ctx, cancel := notify(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return run(ctx)
}

func main() {
	run := func(ctx context.Context) int {
		return app.Run(ctx, app.ProductionDependencies(), os.Args[1:], os.Stdout, os.Stderr)
	}
	serviceRun := func(ctx context.Context) (bool, uint32) {
		return app.RunService(ctx, app.ProductionDependencies(), os.Args[1:])
	}
	if handled, code := service.RunWindowsService(serviceRun); handled {
		os.Exit(code)
	}
	os.Exit(runForeground(run, signal.NotifyContext))
}
