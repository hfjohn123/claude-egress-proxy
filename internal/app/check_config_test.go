package app

import (
	"context"
	"runtime"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
)

func TestServiceHandlerUsesSelectedDefaultConfig(t *testing.T) {
	path := "/service/config.yaml"
	if runtime.GOOS == "windows" {
		path = `C:\service\config.yaml`
	}
	platform := &serviceRecordingPlatform{}
	handler := newServiceHandler(serviceDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: path}, nil },
		platform: func() service.Platform { return platform },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.Service, ServiceAction: cli.ServiceStart})
	if result.ExitCode != 0 || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatalf("service result = %+v", result)
	}
	if platform.action != service.Start || platform.configPath != path {
		t.Fatalf("service call = %q %q", platform.action, platform.configPath)
	}
}

type serviceRecordingPlatform struct {
	action     service.Action
	configPath string
}

func (p *serviceRecordingPlatform) Apply(_ context.Context, action service.Action, configPath string) error {
	p.action, p.configPath = action, configPath
	return nil
}

func TestCheckConfigLoadsSelectedPathAndClosesSnapshot(t *testing.T) {
	loaded := &checkLoaded{}
	seen := ""
	h := newCheckConfigHandler(checkConfigDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "/default/config.yaml"}, nil },
		load:     func(path string) (pacLoaded, error) { seen = path; return loaded, nil },
	})
	result := h(context.Background(), cli.Invocation{Command: cli.CheckConfig, ConfigPath: "/selected/config.yaml"})
	if result.ExitCode != 0 || seen != "/selected/config.yaml" || !loaded.closed {
		t.Fatalf("result=%+v path=%q closed=%v", result, seen, loaded.closed)
	}
}

type checkLoaded struct{ closed bool }

func (*checkLoaded) Config() config.Config { return config.Config{} }
func (c *checkLoaded) Close() error        { c.closed = true; return nil }
