package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
)

func TestServiceHandlerUsesSelectedDefaultConfig(t *testing.T) {
	path := "/service/config.yaml"
	if runtime.GOOS == "windows" {
		path = `C:\service\config.yaml`
	}
	platform := &serviceRecordingPlatform{}
	loaded := &serviceTestLoaded{stateRoot: filepath.Dir(path)}
	handler := newServiceHandler(serviceDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: path}, nil },
		load: func(got string, mode config.ValidationMode) (serviceLoaded, error) {
			if got != path || mode != config.ValidateOperational {
				t.Fatalf("load = %q mode %v", got, mode)
			}
			return loaded, nil
		},
		platform: func() service.Platform { return platform },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.Service, ServiceAction: cli.ServiceStart})
	if result.ExitCode != 0 || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatalf("service result = %+v", result)
	}
	if platform.action != service.Start || platform.selection.ConfigPath != path || platform.selection.StateRoot != filepath.Dir(path) || !loaded.closed {
		t.Fatalf("service call = %q %+v closed=%v", platform.action, platform.selection, loaded.closed)
	}
}

type serviceTestLoaded struct {
	stateRoot string
	closed    bool
}

func (l *serviceTestLoaded) StateRootPath() string { return l.stateRoot }
func (l *serviceTestLoaded) Close() error          { l.closed = true; return nil }

type serviceRecordingPlatform struct {
	action     service.Action
	selection  service.Selection
	prepared   bool
	rolledBack bool
}

func (p *serviceRecordingPlatform) Apply(_ context.Context, action service.Action, selection service.Selection) error {
	p.action, p.selection = action, selection
	return nil
}

func (p *serviceRecordingPlatform) Prepare(_ context.Context, action service.Action) (service.Undo, error) {
	if action != service.Install {
		return nil, nil
	}
	p.prepared = true
	return func(context.Context) error { p.rolledBack = true; return nil }, nil
}

func TestServiceInstallPreparesIdentityBeforeOperationalLoad(t *testing.T) {
	path := "/service/config.yaml"
	if runtime.GOOS == "windows" {
		path = `C:\service\config.yaml`
	}
	platform := &serviceRecordingPlatform{}
	handler := newServiceHandler(serviceDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: path}, nil },
		load: func(string, config.ValidationMode) (serviceLoaded, error) {
			if !platform.prepared {
				t.Fatal("operational load ran before identity preparation")
			}
			return nil, errors.New("load failed")
		},
		platform: func() service.Platform { return platform },
	})
	result := handler(context.Background(), cli.Invocation{Command: cli.Service, ServiceAction: cli.ServiceInstall})
	if result.ExitCode != 1 || !platform.prepared || !platform.rolledBack {
		t.Fatalf("result=%+v prepared=%v rolledBack=%v", result, platform.prepared, platform.rolledBack)
	}
}

func TestCheckConfigLoadsSelectedPathAndClosesSnapshot(t *testing.T) {
	loaded := &checkLoaded{}
	seen := ""
	var seenMode config.ValidationMode
	h := newCheckConfigHandler(checkConfigDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "/default/config.yaml"}, nil },
		load: func(path string, mode config.ValidationMode) (pacLoaded, error) {
			seen, seenMode = path, mode
			return loaded, nil
		},
	})
	result := h(context.Background(), cli.Invocation{Command: cli.CheckConfig, ConfigPath: "/selected/config.yaml"})
	if result.ExitCode != 0 || seen != "/selected/config.yaml" || seenMode != config.ValidateOperational || !loaded.closed {
		t.Fatalf("result=%+v path=%q mode=%v closed=%v", result, seen, seenMode, loaded.closed)
	}
}

func TestCheckConfigAppendsNonSensitivePathStage(t *testing.T) {
	p := securefs.IdentityOnlyPermissions()
	base := t.TempDir()
	root, err := securefs.OpenRoot(base, securefs.RootPolicy{Access: p})
	if err != nil {
		t.Fatal(err)
	}
	checkout := root.Identity()
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	_, staged := (config.Loader{CheckoutIdentity: checkout, Policies: config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
	}}).Load(filepath.Join(base, "config.yaml"), config.ValidatePure)
	if staged == nil {
		t.Fatal("expected staged path error")
	}
	h := newCheckConfigHandler(checkConfigDependencies{
		load: func(string, config.ValidationMode) (pacLoaded, error) { return nil, staged },
	})
	result := h(context.Background(), cli.Invocation{Command: cli.CheckConfig, ConfigPath: "selected"})
	want := append(append([]byte(nil), contract.Fatal(contract.D004)...), []byte("path_stage=config_directory\n")...)
	if result.ExitCode != 1 || string(result.Stderr) != string(want) {
		t.Fatalf("result=%+v stderr=%q", result, result.Stderr)
	}
}

func TestCheckConfigLeavesUnstagedFatalDiagnosticUnchanged(t *testing.T) {
	h := newCheckConfigHandler(checkConfigDependencies{
		load: func(string, config.ValidationMode) (pacLoaded, error) {
			return nil, diagnosticError{code: contract.D004}
		},
	})
	result := h(context.Background(), cli.Invocation{Command: cli.CheckConfig, ConfigPath: "selected"})
	if result.ExitCode != 1 || string(result.Stderr) != string(contract.Fatal(contract.D004)) {
		t.Fatalf("result=%+v stderr=%q", result, result.Stderr)
	}
}

type checkLoaded struct {
	closed bool
	config config.Config
}

func (c *checkLoaded) Config() config.Config { return c.config }
func (c *checkLoaded) Close() error          { c.closed = true; return nil }

func TestCheckConfigRendersSecurityWarningsInRequiredOrder(t *testing.T) {
	stateRoot := "/tmp/claude-egress-proxy-test"
	if runtime.GOOS == "windows" {
		stateRoot = `C:\claude-egress-proxy-test`
	}
	document := fmt.Sprintf("format_version: 1\ninstance_id: 00112233445566778899aabbccddeeff\nstate_root: %q\npublic_listener:\n  addresses: [127.0.0.1:8080]\n  pac_enabled: false\ntls:\n  mode: insecure_loopback\nresolver:\n  mode: system\npublic_self_ipv4s: []\nper_device_capacity: 64\nabsolute_tunnel_lifetime: disabled\ngraceful_shutdown_drain: 20s\ndestination:\n  profile: code\n  exact_hosts: []\n  suffixes: [Example.NET]\n  dangerous_custom_suffixes: true\nlogging:\n  sink: default\n  sensitive_metadata: false\nmetrics:\n  enabled: false\n", stateRoot)
	cfg, err := config.Decode([]byte(document))
	if err != nil {
		t.Fatal(err)
	}
	loaded := &checkLoaded{config: cfg}
	h := newCheckConfigHandler(checkConfigDependencies{
		defaults: func() (config.DefaultPaths, error) { return config.DefaultPaths{Config: "/config.yaml"}, nil },
		load:     func(string, config.ValidationMode) (pacLoaded, error) { return loaded, nil },
	})
	result := h(context.Background(), cli.Invocation{Command: cli.CheckConfig, ConfigPath: "/config.yaml"})
	want := "INSECURE LOOPBACK TEST MODE: Basic proxy credentials are sent in plaintext on\nthis host. Use only a fresh disposable local-test credential; never reuse a\ncredential from a TLS deployment.\n\nWARNING: dangerous_custom_suffixes is enabled.\nEach listed suffix permits CONNECT to the suffix itself and every subdomain:\n- example.net\n"
	if result.ExitCode != 0 || string(result.Stdout) != want || len(result.Stderr) != 0 || !loaded.closed {
		t.Fatalf("result=%+v stdout=%q closed=%v", result, result.Stdout, loaded.closed)
	}
	if strings.Contains(string(result.Stdout), stateRoot) {
		t.Fatal("warning leaked state root")
	}
}
