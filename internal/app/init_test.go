package app

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

type countingEntropy struct{ reads int }

func (r *countingEntropy) Read(p []byte) (int, error) {
	r.reads++
	clear(p)
	return len(p), nil
}

func TestInitCreatesConfigLastAndNeverOverwrites(t *testing.T) {
	base := t.TempDir()
	configPath := filepath.Join(base, "config", "config.yaml")
	statePath := filepath.Join(base, "state")
	p := securefs.IdentityOnlyPermissions()
	deps := InitDependencies{
		Entropy: bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}),
		Defaults: func() (config.DefaultPaths, error) {
			return config.DefaultPaths{Config: configPath, StateRoot: statePath}, nil
		},
		Security: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigContainer: securefs.RootPolicy{Access: p}, ConfigDirectory: securefs.RootPolicy{Access: p},
				ConfigFile:     securefs.FilePolicy{Presence: securefs.MustBeAbsent, Kind: securefs.RegularFile, Access: p, MaxBytes: 1 << 20},
				StateContainer: securefs.RootPolicy{Access: p}, StateDirectory: securefs.RootPolicy{Access: p},
			}, nil
		},
	}
	h := NewInitHandler(deps)
	result := h(context.Background(), cli.Invocation{Command: cli.Init})
	if result.ExitCode != 0 || len(result.Stdout) != 0 || len(result.Stderr) != 0 {
		t.Fatalf("init result = %+v", result)
	}
	bytesOnDisk, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bytesOnDisk), "instance_id: 000102030405060708090a0b0c0d0e0f") {
		t.Fatalf("config = %q", bytesOnDisk)
	}
	if _, err := os.Stat(statePath); err != nil {
		t.Fatal(err)
	}
	configEntries, err := os.ReadDir(filepath.Dir(configPath))
	if err != nil {
		t.Fatal(err)
	}
	if len(configEntries) != 1 || configEntries[0].Name() != "config.yaml" {
		t.Fatalf("config artifacts = %v", configEntries)
	}
	stateEntries, err := os.ReadDir(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(stateEntries) != 0 {
		t.Fatalf("runtime artifacts = %v", stateEntries)
	}
	if second := h(context.Background(), cli.Invocation{Command: cli.Init}); second.ExitCode != 1 || string(second.Stderr) != "ERROR D001 CONFIG_READ: cannot safely read the selected configuration; check its existence, type, and access.\n" {
		t.Fatalf("second init = %+v", second)
	}
	after, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(bytesOnDisk) {
		t.Fatal("init overwrote existing config")
	}
}

func TestInitRejectsFrozenRuntimeArtifactsBeforeCommit(t *testing.T) {
	reserved := []string{
		"credentials.json", "credentials.lock", "credentials.json.new",
		"admin-token.json", "admin-token.lock", "admin-token.json.new",
	}
	for _, name := range reserved {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			configPath := filepath.Join(base, "config", "config.yaml")
			statePath := filepath.Join(base, "state")
			if err := os.Mkdir(statePath, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(statePath, name), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			entropy := &countingEntropy{}
			result := NewInitHandler(testInitDependencies(configPath, statePath, entropy))(context.Background(), cli.Invocation{Command: cli.Init})
			if result.ExitCode != 1 {
				t.Fatalf("init result = %+v", result)
			}
			if entropy.reads != 0 {
				t.Fatalf("entropy reads = %d, want zero", entropy.reads)
			}
			if _, err := os.Stat(configPath); !os.IsNotExist(err) {
				t.Fatalf("config committed before artifact rejection: %v", err)
			}
		})
	}
}

func TestInitAcceptsUnrelatedExistingStateMember(t *testing.T) {
	base := t.TempDir()
	configPath := filepath.Join(base, "config", "config.yaml")
	statePath := filepath.Join(base, "state")
	if err := os.Mkdir(statePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(statePath, "operator-note.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	result := NewInitHandler(testInitDependencies(configPath, statePath, &countingEntropy{}))(context.Background(), cli.Invocation{Command: cli.Init})
	if result.ExitCode != 0 {
		t.Fatalf("init result = %+v", result)
	}
}

func TestInitRecoversWithQuarantinedFailedConfigMember(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "shared")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	quarantine := filepath.Join(root, ".securefs-cleanup-file-000102030405060708090a0b")
	if err := os.WriteFile(quarantine, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.yaml")
	result := NewInitHandler(testInitDependencies(configPath, root, &countingEntropy{}))(context.Background(), cli.Invocation{Command: cli.Init})
	if result.ExitCode != 0 {
		t.Fatalf("init result = %+v", result)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config was not committed: %v", err)
	}
	if got, err := os.ReadFile(quarantine); err != nil || string(got) != "partial" {
		t.Fatalf("quarantine = %q,%v", got, err)
	}
}

func TestInitCreateFileFailureDiagnostics(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want contract.DiagnosticCode
	}{
		{"unsafe path", securefs.ErrUnsafePath, contract.D004},
		{"identity", securefs.ErrIdentityChanged, contract.D004},
		{"permissions", securefs.ErrPermissions, contract.D004},
		{"unsupported", securefs.ErrUnsupportedInspection, contract.D010},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := initCreateFileCode(test.err); got != test.want {
				t.Fatalf("diagnostic = %v, want %v", got, test.want)
			}
		})
	}
}

func TestInitConfigAndStateDirectoryPlatformFailuresAreExactD010(t *testing.T) {
	for _, directory := range []string{"config", "state"} {
		t.Run(directory, func(t *testing.T) {
			result := initDirectoryFailure(securefs.ErrUnsupportedInspection)
			if result.ExitCode != 1 || string(result.Stderr) != string(contract.Fatal(contract.D010)) || len(result.Stdout) != 0 {
				t.Fatalf("directory failure = %+v, want exact D010", result)
			}
		})
	}
	if result := initDirectoryFailure(securefs.ErrPermissions); string(result.Stderr) != string(contract.Fatal(contract.D004)) {
		t.Fatalf("permission failure = %+v, want exact D004", result)
	}
}

func testInitDependencies(configPath, statePath string, entropy io.Reader) InitDependencies {
	p := securefs.IdentityOnlyPermissions()
	return InitDependencies{
		Entropy: entropy,
		Defaults: func() (config.DefaultPaths, error) {
			return config.DefaultPaths{Config: configPath, StateRoot: statePath}, nil
		},
		Security: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigContainer: securefs.RootPolicy{Access: p}, ConfigDirectory: securefs.RootPolicy{Access: p},
				ConfigFile:     securefs.FilePolicy{Presence: securefs.MustBeAbsent, Kind: securefs.RegularFile, Access: p, MaxBytes: 1 << 20},
				StateContainer: securefs.RootPolicy{Access: p}, StateDirectory: securefs.RootPolicy{Access: p},
			}, nil
		},
	}
}

func TestInitRejectsCheckoutOutputBeforeMutation(t *testing.T) {
	base := t.TempDir()
	checkout, err := securefs.OpenRoot(base, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	checkoutID := checkout.Identity()
	_ = checkout.Close()
	p := securefs.IdentityOnlyPermissions()
	deps := InitDependencies{Entropy: bytes.NewReader(make([]byte, 16)), Checkout: checkoutID, Defaults: func() (config.DefaultPaths, error) {
		return config.DefaultPaths{Config: filepath.Join(base, "config", "config.yaml"), StateRoot: filepath.Join(base, "state")}, nil
	}, Security: func() (config.SecurityPolicies, error) {
		return config.SecurityPolicies{ConfigContainer: securefs.RootPolicy{Access: p}, ConfigDirectory: securefs.RootPolicy{Access: p}, ConfigFile: securefs.FilePolicy{Presence: securefs.MustBeAbsent, Kind: securefs.RegularFile, Access: p, MaxBytes: 1 << 20}, StateContainer: securefs.RootPolicy{Access: p}, StateDirectory: securefs.RootPolicy{Access: p}}, nil
	}}
	result := NewInitHandler(deps)(context.Background(), cli.Invocation{Command: cli.Init})
	if result.ExitCode != 1 || string(result.Stderr) != "ERROR D004 PATH_SECURITY: required state failed identity or access checks; review ownership, permissions, and links.\n" {
		t.Fatalf("checkout init = %+v", result)
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("checkout artifacts = %v", entries)
	}
}

func TestInitRejectsCaseAliasedWindowsDirectoryPoliciesBeforeMutation(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows identity alias")
	}
	base := t.TempDir()
	dir := filepath.Join(base, "Shared")
	p := securefs.IdentityOnlyPermissions()
	deps := InitDependencies{Entropy: bytes.NewReader(make([]byte, 16)), Defaults: func() (config.DefaultPaths, error) {
		return config.DefaultPaths{Config: filepath.Join(dir, "config.yaml"), StateRoot: strings.ToUpper(dir)}, nil
	}, Security: func() (config.SecurityPolicies, error) {
		return config.SecurityPolicies{ConfigContainer: securefs.RootPolicy{Access: p}, ConfigDirectory: securefs.RootPolicy{Access: p}, ConfigFile: securefs.FilePolicy{Presence: securefs.MustBeAbsent, Kind: securefs.RegularFile, Access: p, MaxBytes: 1 << 20}, StateContainer: securefs.RootPolicy{Access: p}, StateDirectory: securefs.RootPolicy{Access: securefs.LinuxExactPermissions(0, 0o700)}}, nil
	}}
	result := NewInitHandler(deps)(context.Background(), cli.Invocation{Command: cli.Init})
	if result.ExitCode != 1 || string(result.Stderr) != "ERROR D004 PATH_SECURITY: required state failed identity or access checks; review ownership, permissions, and links.\n" {
		t.Fatalf("alias init = %+v", result)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("directory mutated: %v", err)
	}
}

func TestProductionDependenciesWiresAvailableCommands(t *testing.T) {
	d := ProductionDependencies()
	if d.Init == nil {
		t.Fatal("production init is nil")
	}
	if d.PAC == nil {
		t.Fatal("production PAC is nil")
	}
	if d.AdminToken == nil {
		t.Fatal("production admin-token handler is nil")
	}
	if d.CheckConfig == nil {
		t.Fatal("production check-config handler is nil")
	}
	if d.Serve != nil || d.Credential != nil || d.CheckHealth != nil || d.CheckNetwork != nil || d.Service != nil {
		t.Fatal("later handlers became live")
	}
}
