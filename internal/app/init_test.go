package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

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

func TestProductionDependenciesWiresOnlyInit(t *testing.T) {
	d := ProductionDependencies()
	if d.Init == nil {
		t.Fatal("production init is nil")
	}
	if d.Serve != nil || d.Credential != nil || d.AdminToken != nil || d.PAC != nil || d.CheckConfig != nil || d.CheckHealth != nil || d.CheckNetwork != nil || d.Service != nil {
		t.Fatal("later handlers became live")
	}
}
