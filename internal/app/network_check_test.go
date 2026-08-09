package app

import (
	"context"
	"runtime"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
)

type fakeNetworkLoaded struct{ closed bool }

func (f *fakeNetworkLoaded) Close() error { f.closed = true; return nil }

func TestNetworkHandlerUsesOperationalSnapshotAndClosedOutput(t *testing.T) {
	path := "/config.yaml"
	if runtime.GOOS == "windows" {
		path = `C:\config.yaml`
	}
	loaded := &fakeNetworkLoaded{}
	handler := newNetworkHandler(networkDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: path}, nil },
		load: func(got string, mode config.ValidationMode) (networkLoaded, error) {
			if got != path || mode != config.ValidateOperational {
				t.Fatalf("load=%q mode=%v", got, mode)
			}
			return loaded, nil
		},
		check: func(context.Context, networkLoaded, string) ([]byte, bool) {
			return []byte("local_bind=ready\n"), true
		},
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.CheckNetwork})
	if result.ExitCode != 0 || string(result.Stdout) != "local_bind=ready\n" || len(result.Stderr) != 0 || !loaded.closed {
		t.Fatalf("result=%+v closed=%v", result, loaded.closed)
	}
}

func TestNetworkHandlerWarnsBeforeOptionalEchoAndFailsClosed(t *testing.T) {
	loaded := &fakeNetworkLoaded{}
	handler := newNetworkHandler(networkDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "/config.yaml"}, nil },
		load:     func(string, config.ValidationMode) (networkLoaded, error) { return loaded, nil },
		check:    func(context.Context, networkLoaded, string) ([]byte, bool) { return nil, false },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.CheckNetwork, PublicIPURL: "https://echo.example/"})
	if result.ExitCode != 1 || len(result.Stdout) != 0 || string(result.Stderr) != publicIPWarning+"network check failed\n" {
		t.Fatalf("result=%+v", result)
	}
}
