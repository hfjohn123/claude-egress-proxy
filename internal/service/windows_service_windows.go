//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc/mgr"
)

// WindowsServiceName is stable across install, Event Log, and SCM operations.
const WindowsServiceName = "ClaudeEgressProxy"

const (
	eventSourceName = "claude-egress-proxy"
	eventSourceKey  = `SYSTEM\CurrentControlSet\Services\EventLog\Application\claude-egress-proxy`
)

type windowsPlatform struct {
	run         func(context.Context, string, ...string) error
	executable  func() (string, error)
	query       func() (string, error)
	preshutdown func() error
}

// NewPlatform returns the Windows SCM and Event Log adapter.
func NewPlatform() Platform {
	return windowsPlatform{run: runWindowsCommand, executable: os.Executable, query: installedCommandLine, preshutdown: configurePreshutdownTimeout}
}

func runWindowsCommand(ctx context.Context, name string, arguments ...string) error {
	return exec.CommandContext(ctx, name, arguments...).Run()
}

func (p windowsPlatform) Apply(ctx context.Context, action Action, selection Selection) error {
	// Refuse service mutation only in builds where the SCM dispatcher is absent.
	if !windowsSCMDispatcherAvailable() {
		return ErrUnsupported
	}

	if p.run == nil || p.executable == nil || p.query == nil || action == Install && p.preshutdown == nil {
		return ErrUnsupported
	}
	if action == Install {
		return p.install(ctx, selection.ConfigPath)
	}
	if err := p.requireInstalledSelector(selection.ConfigPath); err != nil {
		return err
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

func installedCommandLine() (string, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer manager.Disconnect()
	installed, err := manager.OpenService(WindowsServiceName)
	if err != nil {
		return "", err
	}
	defer installed.Close()
	configuration, err := installed.Config()
	if err != nil {
		return "", err
	}
	return configuration.BinaryPathName, nil
}

func (p windowsPlatform) requireInstalledSelector(configPath string) error {
	executable, err := p.executable()
	if err != nil {
		return err
	}
	installed, err := p.query()
	if err != nil {
		return err
	}
	if installed != windowsCommandLine(executable, configPath) {
		return errors.New("service selector conflict")
	}
	return nil
}

func windowsSCMDispatcherAvailable() bool { return true }

func (p windowsPlatform) install(ctx context.Context, configPath string) error {
	executable, err := p.executable()
	if err != nil || !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return fmt.Errorf("service executable: %w", err)
	}
	return RunTransaction(ctx, []Step{
		func(context.Context) (Undo, error) { return registerEventSource(executable) },
		func(ctx context.Context) (Undo, error) {
			command := windowsCommandLine(executable, configPath)
			if err := p.run(ctx, "sc.exe", windowsCreateArguments(command)...); err != nil {
				return nil, err
			}
			return func(undoContext context.Context) error {
				return p.run(undoContext, "sc.exe", "delete", WindowsServiceName)
			}, nil
		},
		func(ctx context.Context) (Undo, error) {
			if err := p.run(ctx, "sc.exe", "sidtype", WindowsServiceName, "unrestricted"); err != nil {
				return nil, err
			}
			return nil, nil
		},
		func(context.Context) (Undo, error) {
			if err := p.preshutdown(); err != nil {
				return nil, err
			}
			return nil, nil
		},
	})
}

func configurePreshutdownTimeout() error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	installed, err := manager.OpenService(WindowsServiceName)
	if err != nil {
		return err
	}
	defer installed.Close()
	timeout := uint32(windowsStopWaitHint)
	return windows.ChangeServiceConfig2(installed.Handle, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, (*byte)(unsafe.Pointer(&timeout)))
}

func windowsCreateArguments(command string) []string {
	return []string{"create", WindowsServiceName, "binPath=", command, "start=", "auto", "obj=", `NT SERVICE\ClaudeEgressProxy`}
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
