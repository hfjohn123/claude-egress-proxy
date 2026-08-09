package app

import (
	"context"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
)

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
