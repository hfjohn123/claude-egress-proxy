// Package app dispatches a parsed invocation to the injected command handlers.
package app

import (
	"context"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
)

type Result struct {
	ExitCode                     int
	Stdout, Stderr, OutputFailed []byte
}

type Handler func(context.Context, cli.Invocation) Result

type Dependencies struct {
	Serve, Init, Credential, AdminToken         Handler
	PAC, CheckConfig, CheckHealth, CheckNetwork Handler
	Service                                     Handler
}

func (d Dependencies) handler(command cli.Command) Handler {
	switch command {
	case cli.Serve:
		return d.Serve
	case cli.Init:
		return d.Init
	case cli.CredentialAdd, cli.CredentialRevoke, cli.CredentialPurge, cli.CredentialList:
		return d.Credential
	case cli.AdminTokenRotate:
		return d.AdminToken
	case cli.PAC:
		return d.PAC
	case cli.CheckConfig:
		return d.CheckConfig
	case cli.CheckHealth:
		return d.CheckHealth
	case cli.CheckNetwork:
		return d.CheckNetwork
	case cli.Service:
		return d.Service
	default:
		panic("invalid parsed command")
	}
}
