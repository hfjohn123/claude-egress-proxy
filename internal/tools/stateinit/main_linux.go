//go:build linux

package main

import (
	"os"

	"github.com/hfjohn123/claude-egress-proxy/internal/containerinit"
)

func main() {
	if len(os.Args) != 1 || containerinit.Prepare("/var/lib/claude-egress-proxy", 65532, 65532) != nil {
		os.Exit(1)
	}
}
