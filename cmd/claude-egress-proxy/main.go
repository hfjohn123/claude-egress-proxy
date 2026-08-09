package main

import (
	"context"
	"os"

	"github.com/hfjohn123/claude-egress-proxy/internal/app"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
)

func main() {
	run := func(ctx context.Context) int {
		return app.Run(ctx, app.ProductionDependencies(), os.Args[1:], os.Stdout, os.Stderr)
	}
	if handled, code := service.RunWindowsService(run); handled {
		os.Exit(code)
	}
	os.Exit(run(context.Background()))
}
