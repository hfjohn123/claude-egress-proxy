//go:build windows

package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsDefaultsUseOnlyKnownProgramData(t *testing.T) {
	old := programDataKnownFolder
	t.Cleanup(func() { programDataKnownFolder = old })
	base := filepath.Join(t.TempDir(), "system-program-data")
	programDataKnownFolder = func() (string, error) { return base, nil }
	for _, name := range []string{"ProgramData", "PROGRAMDATA", "programdata", "USERPROFILE", "HOME"} {
		t.Setenv(name, filepath.Join(t.TempDir(), "poison"))
	}
	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldCWD) })
	got, err := PlatformDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != filepath.Join(base, "ClaudeEgressProxy", "config.yaml") || got.StateRoot != filepath.Join(base, "ClaudeEgressProxy") {
		t.Fatalf("defaults = %+v", got)
	}
	programDataKnownFolder = func() (string, error) { return "", errors.New("unavailable") }
	if _, err := PlatformDefaults(); !errors.Is(err, ErrPlatform) {
		t.Fatalf("missing known folder = %v", err)
	}
}

func TestWindowsSecurityPoliciesResolveExactVirtualServiceAccount(t *testing.T) {
	old := lookupServiceSID
	t.Cleanup(func() { lookupServiceSID = old })
	var gotSystem, gotAccount string
	lookupServiceSID = func(system, account string) (*windows.SID, string, uint32, error) {
		gotSystem, gotAccount = system, account
		if account != `NT SERVICE\ClaudeEgressProxy` {
			return nil, "", 0, errors.New("bare or wrong service account")
		}
		sid, err := windows.StringToSid("S-1-5-18")
		return sid, "NT SERVICE", 0, err
	}
	if _, err := PlatformSecurityPolicies(); err != nil {
		t.Fatalf("PlatformSecurityPolicies = %v", err)
	}
	if gotSystem != "" || gotAccount != `NT SERVICE\ClaudeEgressProxy` {
		t.Fatalf("LookupSID(%q, %q), want local exact virtual-service account", gotSystem, gotAccount)
	}
}
