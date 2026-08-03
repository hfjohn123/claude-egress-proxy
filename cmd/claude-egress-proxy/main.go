package main

import (
	"context"
	"os"

	"github.com/hfjohn123/claude-egress-proxy/internal/app"
)

func main() {
	os.Exit(app.Run(context.Background(), app.ProductionDependencies(), os.Args[1:], os.Stdout, os.Stderr))
}
