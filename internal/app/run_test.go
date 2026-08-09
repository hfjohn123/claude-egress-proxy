package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"runtime"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

func TestRunDispatchesEveryCommandToItsFrozenHandler(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
	}{
		{"serve", []string{"serve"}, "serve"}, {"init", []string{"init"}, "init"},
		{"credential add", []string{"credential", "add", "--device", "laptop-1"}, "credential"},
		{"credential revoke", []string{"credential", "revoke", "--record", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, "credential"},
		{"credential purge", []string{"credential", "purge", "--record", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, "credential"},
		{"credential list", []string{"credential", "list"}, "credential"}, {"admin", []string{"admin-token", "rotate"}, "admin"},
		{"pac", []string{"pac", "--output", appAbsolutePath()}, "pac"}, {"check config", []string{"check", "config"}, "config"},
		{"check health", []string{"check", "health", "--address", "127.0.0.1:9090"}, "health"}, {"check network", []string{"check", "network"}, "network"},
		{"service", []string{"service", "install"}, "service"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deps := Dependencies{
				Serve: handler("serve"), Init: handler("init"), Credential: handler("credential"), AdminToken: handler("admin"),
				PAC: handler("pac"), CheckConfig: handler("config"), CheckHealth: handler("health"), CheckNetwork: handler("network"), Service: handler("service"),
			}
			var stdout, stderr bytes.Buffer
			if got := Run(context.Background(), deps, test.argv, &stdout, &stderr); got != 0 {
				t.Fatalf("Run exit = %d, want 0", got)
			}
			if got := stdout.String(); got != test.want+"\n" || stderr.Len() != 0 {
				t.Fatalf("Run output = stdout %q stderr %q, want dispatched handler output", got, stderr.String())
			}
		})
	}
}

func TestRunServiceReturnsSCMSpecificDiagnosticCode(t *testing.T) {
	deps := Dependencies{Serve: func(context.Context, cli.Invocation) Result { return initFailure(contract.D007) }}
	specific, code := RunService(context.Background(), deps, []string{"serve"})
	if !specific || code != contract.ServiceCode(contract.D007) {
		t.Fatalf("RunService specific=%v code=%d", specific, code)
	}
}

func TestRunWritesUsageOnlyToStderrForParseFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), Dependencies{}, []string{"credential", "add"}, &stdout, &stderr); got != 2 {
		t.Fatalf("Run exit = %d, want 2", got)
	}
	if stdout.Len() != 0 || stderr.String() != "usage: claude-egress-proxy [--config <absolute-file>] credential add --device <device-identifier>\n" {
		t.Fatalf("usage output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestRunWritesHandlerStdoutThenStderrWithoutChangingItsExit(t *testing.T) {
	deps := Dependencies{Serve: func(context.Context, cli.Invocation) Result {
		return Result{ExitCode: 2, Stdout: []byte("first\n"), Stderr: []byte("second\n")}
	}}
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), deps, []string{"serve"}, &stdout, &stderr); got != 2 {
		t.Fatalf("Run exit = %d, want 2", got)
	}
	if stdout.String() != "first\n" || stderr.String() != "second\n" {
		t.Fatalf("Run output = stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestRunTurnsIncompleteStdoutIntoOneFixedOutputFailure(t *testing.T) {
	tests := []struct {
		name string
		argv []string
		want string
		deps Dependencies
	}{
		{"credential", []string{"credential", "list"}, "credential error: output_failed\n", Dependencies{Credential: func(context.Context, cli.Invocation) Result {
			return Result{ExitCode: 0, Stdout: []byte("credential id\n"), Stderr: []byte("ordinary error\n"), OutputFailed: []byte("credential error: output_failed\n")}
		}}},
		{"admin token", []string{"admin-token", "rotate"}, "admin-token error: output_failed\n", Dependencies{AdminToken: func(context.Context, cli.Invocation) Result {
			return Result{ExitCode: 0, Stdout: []byte("admin token\n"), Stderr: []byte("ordinary error\n"), OutputFailed: []byte("admin-token error: output_failed\n")}
		}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stdout := shortWriter{n: 3}
			var stderr bytes.Buffer
			if got := Run(context.Background(), test.deps, test.argv, &stdout, &stderr); got != 1 {
				t.Fatalf("Run exit = %d, want 1", got)
			}
			if stderr.String() != test.want {
				t.Fatalf("incomplete stdout stderr = %q, want only fixed output-failure line", stderr.String())
			}
		})
	}
}

func TestRunDoesNotRetryOrReplaceFailedStderr(t *testing.T) {
	deps := Dependencies{Serve: func(context.Context, cli.Invocation) Result { return Result{ExitCode: 2, Stderr: []byte("fixed\n")} }}
	stderr := failingWriter{}
	if got := Run(context.Background(), deps, []string{"serve"}, io.Discard, &stderr); got != 2 {
		t.Fatalf("Run exit = %d, want handler's intended exit", got)
	}
	if stderr.calls != 1 {
		t.Fatalf("stderr writes = %d, want one (no recursive diagnostic)", stderr.calls)
	}
}

func TestRunPanicsForInjectedInvalidExitCode(t *testing.T) {
	deps := Dependencies{Serve: func(context.Context, cli.Invocation) Result { return Result{ExitCode: 3} }}
	defer func() {
		if recover() == nil {
			t.Fatal("invalid handler exit code did not panic")
		}
	}()
	Run(context.Background(), deps, []string{"serve"}, io.Discard, io.Discard)
}

func TestRunLeavesNilHandlerInert(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := Run(context.Background(), Dependencies{}, []string{"serve"}, &stdout, &stderr); got != 1 || stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("nil handler result = exit %d stdout %q stderr %q, want inert exit 1", got, stdout.String(), stderr.String())
	}
}

func handler(label string) Handler {
	return func(context.Context, cli.Invocation) Result { return Result{ExitCode: 0, Stdout: []byte(label + "\n")} }
}

func appAbsolutePath() string {
	if runtime.GOOS == "windows" {
		return "C:\\temp\\proxy.pac"
	}
	return "/tmp/proxy.pac"
}

type shortWriter struct{ n int }

func (w *shortWriter) Write(p []byte) (int, error) { return w.n, nil }

type failingWriter struct{ calls int }

func (w *failingWriter) Write([]byte) (int, error) {
	w.calls++
	return 0, errors.New("sink unavailable")
}
