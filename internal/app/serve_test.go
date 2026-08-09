package app

import (
	"context"
	"crypto/tls"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/proxy"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type fakeServeLoaded struct{ closed bool }

func (f *fakeServeLoaded) Close() error { f.closed = true; return nil }

func TestServeHandlerLoadsPreServeConfigAndClosesIt(t *testing.T) {
	path := "/selected/config.yaml"
	if runtime.GOOS == "windows" {
		path = `C:\selected\config.yaml`
	}
	loaded := &fakeServeLoaded{}
	run := false
	handler := newServeHandler(serveDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: path}, nil },
		load: func(got string, mode config.ValidationMode) (serveLoaded, error) {
			if got != path || mode != config.ValidatePreServe {
				t.Fatalf("load path=%q mode=%v", got, mode)
			}
			return loaded, nil
		},
		run: func(context.Context, serveLoaded) error { run = true; return nil },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.Serve, ConfigPath: path})
	if result.ExitCode != 0 || !run || !loaded.closed {
		t.Fatalf("result=%+v run=%v closed=%v", result, run, loaded.closed)
	}
}

func TestServeHandlerMapsRuntimeFailureToClosedDiagnostic(t *testing.T) {
	loaded := &fakeServeLoaded{}
	handler := newServeHandler(serveDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "/config.yaml"}, nil },
		load:     func(string, config.ValidationMode) (serveLoaded, error) { return loaded, nil },
		run:      func(context.Context, serveLoaded) error { return diagnosticError{code: contract.D009} },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.Serve})
	if result.ExitCode != 1 || string(result.Stderr) != string(contract.Fatal(contract.D009)) || !loaded.closed {
		t.Fatalf("result=%+v closed=%v", result, loaded.closed)
	}
}

func TestServeHandlerRejectsMissingRuntime(t *testing.T) {
	handler := newServeHandler(serveDependencies{})
	result := handler(context.Background(), cli.Invocation{Command: cli.Serve})
	if result.ExitCode != 1 || string(result.Stderr) != string(contract.Fatal(contract.D010)) {
		t.Fatalf("result=%+v", result)
	}
}

func TestPublicAdmissionsAreSharedAcrossAllBinds(t *testing.T) {
	controllers := sharedPublicAdmissions(timebase.Real{}, 2)
	if len(controllers) != 2 || controllers[0] == nil || controllers[0] != controllers[1] {
		t.Fatalf("controllers=%v", controllers)
	}
}

type startRecordingProvider struct{ starts int }

func (*startRecordingProvider) TLSConfig() *tls.Config         { return &tls.Config{} }
func (*startRecordingProvider) Ready(time.Time) bool           { return false }
func (*startRecordingProvider) Expiry(time.Time) time.Duration { return 0 }
func (p *startRecordingProvider) Start(context.Context) error  { p.starts++; return nil }
func (*startRecordingProvider) ReloadOnce(context.Context) contract.ReloadResult {
	r, _ := contract.ParseReloadResult("success")
	return r
}

type boundTestListener struct{}

func (boundTestListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (boundTestListener) Close() error              { return nil }
func (boundTestListener) Addr() net.Addr            { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }

func TestCertificateLifecycleRequiresBoundEndpoint(t *testing.T) {
	provider := &startRecordingProvider{}
	if err := startCertificateAfterBind(context.Background(), provider, nil); err == nil || provider.starts != 0 {
		t.Fatalf("empty endpoints err=%v starts=%d", err, provider.starts)
	}
	endpoints := []proxy.ServerEndpoint{{Listener: boundTestListener{}}}
	if err := startCertificateAfterBind(context.Background(), provider, endpoints); err != nil || provider.starts != 1 {
		t.Fatalf("bound endpoints err=%v starts=%d", err, provider.starts)
	}
}
