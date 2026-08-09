package app

import (
	"context"
	"errors"
	"testing"

	checkpkg "github.com/hfjohn123/claude-egress-proxy/internal/check"
	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
)

func TestHealthHandlerMapsExactCLIResults(t *testing.T) {
	for _, test := range []struct {
		name   string
		err    error
		exit   int
		stderr string
	}{
		{name: "healthy"},
		{name: "probe failure", err: checkpkg.ErrHealthProbe, exit: 1, stderr: "health probe failed\n"},
		{name: "invalid address", err: checkpkg.ErrInvalidHealthAddress, exit: 2, stderr: string(cli.UsageCheckHealth)},
	} {
		t.Run(test.name, func(t *testing.T) {
			handler := newHealthHandler(func(context.Context, string) error { return test.err })
			result := handler(context.Background(), cli.Invocation{Command: cli.CheckHealth, HealthAddress: "127.0.0.1:1"})
			if result.ExitCode != test.exit || len(result.Stdout) != 0 || string(result.Stderr) != test.stderr {
				t.Fatalf("result = %+v", result)
			}
		})
	}
}

func TestHealthHandlerTreatsUnexpectedErrorsAsProbeFailure(t *testing.T) {
	handler := newHealthHandler(func(context.Context, string) error { return errors.New("secret detail") })
	result := handler(context.Background(), cli.Invocation{HealthAddress: "127.0.0.1:1"})
	if result.ExitCode != 1 || string(result.Stderr) != "health probe failed\n" {
		t.Fatalf("result = %+v", result)
	}
}
