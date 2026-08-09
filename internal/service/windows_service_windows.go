//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

// WindowsServiceName is stable across install, Event Log, and SCM operations.
const WindowsServiceName = "ClaudeEgressProxy"

const (
	eventSourceName = "claude-egress-proxy"
	eventSourceKey  = `SYSTEM\CurrentControlSet\Services\EventLog\Application\claude-egress-proxy`
)

type windowsPlatform struct {
	run        func(context.Context, string, ...string) error
	executable func() (string, error)
}

// NewPlatform returns the Windows SCM and Event Log adapter.
func NewPlatform() Platform {
	return windowsPlatform{run: runWindowsCommand, executable: os.Executable}
}

func runWindowsCommand(ctx context.Context, name string, arguments ...string) error {
	return exec.CommandContext(ctx, name, arguments...).Run()
}

func (p windowsPlatform) Apply(ctx context.Context, action Action, configPath string) error {
	// A service registered with SCM must enter svc.Run and report status/control
	// transitions. The executable does not yet provide that dispatcher, so doing
	// any of these mutations would install a service that cannot be controlled.
	// Keep the public command boundary inert until the runtime host is wired.
	if !windowsSCMDispatcherAvailable() {
		return ErrUnsupported
	}

	if p.run == nil || p.executable == nil {
		return ErrUnsupported
	}
	if action == Install {
		return p.install(ctx, configPath)
	}
	switch action {
	case Start, Stop:
		return p.run(ctx, "sc.exe", action.String(), WindowsServiceName)
	case Uninstall:
		if err := p.run(ctx, "sc.exe", "stop", WindowsServiceName); err != nil {
			return err
		}
		if err := p.run(ctx, "sc.exe", "delete", WindowsServiceName); err != nil {
			return err
		}
		return removeEventSource()
	default:
		return ErrInvalidAction
	}
}

// windowsSCMDispatcherAvailable is deliberately false until the executable
// enters a real SCM dispatcher and maps controls to the server drain path.
func windowsSCMDispatcherAvailable() bool { return false }

func (p windowsPlatform) install(ctx context.Context, configPath string) error {
	executable, err := p.executable()
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return fmt.Errorf("service executable: %w", err)
	}
	return RunTransaction(ctx, []Step{
		func(context.Context) (Undo, error) { return registerEventSource(executable) },
		func(ctx context.Context) (Undo, error) {
			command := windowsCommandLine(executable, configPath)
			if err := p.run(ctx, "sc.exe", "create", WindowsServiceName, "binPath=", command, "start=", "auto"); err != nil {
				return nil, err
			}
			return func(undoContext context.Context) error {
				return p.run(undoContext, "sc.exe", "delete", WindowsServiceName)
			}, nil
		},
	})
}

func windowsCommandLine(executable, configPath string) string {
	return windowsQuote(executable) + " --config " + windowsQuote(configPath) + " serve"
}

func windowsQuote(value string) string {
	return `"` + value + `"`
}

func registerEventSource(executable string) (Undo, error) {
	key, exists, err := registry.CreateKey(registry.LOCAL_MACHINE, eventSourceKey, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return nil, err
	}
	defer key.Close()
	if exists {
		messageFile, messageType, err := key.GetStringValue("EventMessageFile")
		if err != nil || messageType != registry.SZ || messageFile != executable {
			return nil, errors.New("event log source conflict")
		}
		types, valueType, err := key.GetIntegerValue("TypesSupported")
		if err != nil || valueType != registry.DWORD || types != 7 {
			return nil, errors.New("event log source conflict")
		}
		return nil, nil
	}
	if err := key.SetStringValue("EventMessageFile", executable); err != nil {
		return nil, err
	}
	if err := key.SetDWordValue("TypesSupported", 7); err != nil {
		return nil, err
	}
	return func(context.Context) error { return removeEventSource() }, nil
}

func removeEventSource() error {
	return registry.DeleteKey(registry.LOCAL_MACHINE, eventSourceKey)
}
