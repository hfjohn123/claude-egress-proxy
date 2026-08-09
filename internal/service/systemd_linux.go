//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
)

const (
	linuxUser   = "claude-egress-proxy"
	unitPath    = "/etc/systemd/system/claude-egress-proxy.service"
	executable  = "/usr/local/bin/claude-egress-proxy"
	serviceName = "claude-egress-proxy.service"
)

type systemdPlatform struct {
	run func(context.Context, string, ...string) error
}

// NewPlatform returns the host platform adapter.
func NewPlatform() Platform {
	return systemdPlatform{run: runCommand}
}

func runCommand(ctx context.Context, name string, arguments ...string) error {
	return exec.CommandContext(ctx, name, arguments...).Run()
}

func (p systemdPlatform) Apply(ctx context.Context, action Action, selection Selection) error {
	if p.run == nil {
		return ErrUnsupported
	}
	switch action {
	case Install:
		return p.install(ctx, selection)
	case Uninstall:
		if err := p.requireInstalledSelector(selection); err != nil {
			return err
		}
		if err := p.run(ctx, "systemctl", "disable", "--now", serviceName); err != nil {
			return err
		}
		if err := os.Remove(unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return p.run(ctx, "systemctl", "daemon-reload")
	case Start, Stop:
		if err := p.requireInstalledSelector(selection); err != nil {
			return err
		}
		return p.run(ctx, "systemctl", action.String(), serviceName)
	default:
		return ErrInvalidAction
	}
}

func (p systemdPlatform) Prepare(ctx context.Context, action Action) (Undo, error) {
	if action != Install || p.run == nil {
		return nil, nil
	}
	return ensureSystemUser(ctx, p.run)
}

func (p systemdPlatform) install(ctx context.Context, selection Selection) error {
	unit := renderUnit(selection)
	return RunTransaction(ctx, []Step{
		func(ctx context.Context) (Undo, error) { return ensureSystemUser(ctx, p.run) },
		func(context.Context) (Undo, error) { return installUnit(unit) },
		func(ctx context.Context) (Undo, error) {
			if err := p.run(ctx, "systemctl", "daemon-reload"); err != nil {
				return nil, err
			}
			return func(undoContext context.Context) error { return p.run(undoContext, "systemctl", "daemon-reload") }, nil
		},
		func(ctx context.Context) (Undo, error) {
			if err := p.run(ctx, "systemctl", "enable", serviceName); err != nil {
				return nil, err
			}
			return func(undoContext context.Context) error {
				return p.run(undoContext, "systemctl", "disable", serviceName)
			}, nil
		},
	})
}

func ensureSystemUser(ctx context.Context, run func(context.Context, string, ...string) error) (Undo, error) {
	if _, err := user.Lookup(linuxUser); err == nil {
		return nil, nil
	}
	if err := run(ctx, "useradd", "--system", "--user-group", "--no-create-home", linuxUser); err != nil {
		return nil, err
	}
	return func(undoContext context.Context) error { return run(undoContext, "userdel", linuxUser) }, nil
}

func installUnit(unit string) (Undo, error) {
	existing, err := os.ReadFile(unitPath)
	if err == nil {
		if string(existing) != unit {
			return nil, fmt.Errorf("service unit conflict")
		}
		return nil, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(unitPath), 0o755); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(filepath.Dir(unitPath), ".claude-egress-proxy-*.service")
	if err != nil {
		return nil, err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o644); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if _, err := temporary.WriteString(unit); err != nil {
		_ = temporary.Close()
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(name, unitPath); err != nil {
		return nil, err
	}
	return func(context.Context) error { return os.Remove(unitPath) }, nil
}

func (p systemdPlatform) requireInstalledSelector(selection Selection) error {
	unit, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if string(unit) != renderUnit(selection) {
		return fmt.Errorf("service selector conflict")
	}
	return nil
}

func renderUnit(selection Selection) string {
	return fmt.Sprintf(`[Unit]
Description=Claude Egress Proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=claude-egress-proxy
Group=claude-egress-proxy
ExecStart=/usr/local/bin/claude-egress-proxy --config %s serve
Restart=on-failure
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=%s
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
StandardOutput=null
StandardError=journal
KillSignal=SIGTERM
TimeoutStopSec=25s

[Install]
WantedBy=multi-user.target
`, systemdQuote(selection.ConfigPath), systemdQuote(selection.StateRoot))
}

func systemdQuote(value string) string {
	if !strings.ContainsAny(value, " \t\\\"") {
		return value
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}
