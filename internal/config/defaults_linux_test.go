//go:build linux

package config

import (
	"os"
	"testing"
)

func TestLinuxDefaultsAreFixedAbsoluteLiterals(t *testing.T) {
	for _, name := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "ProgramData"} {
		t.Setenv(name, "/poison")
	}
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	got, err := PlatformDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if got.Config != "/etc/claude-egress-proxy/config.yaml" || got.StateRoot != "/var/lib/claude-egress-proxy" {
		t.Fatalf("defaults = %+v", got)
	}
}
