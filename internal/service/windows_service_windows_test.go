//go:build windows

package service

import (
	"context"
	"reflect"
	"testing"
)

func TestWindowsServiceCommandQuotesBothPaths(t *testing.T) {
	got := windowsCommandLine(`C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe`, `C:\ProgramData\Claude Egress Proxy\config.yaml`)
	want := `"C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe" --config "C:\ProgramData\Claude Egress Proxy\config.yaml" serve`
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestWindowsCreateUsesVirtualServiceAccount(t *testing.T) {
	got := windowsCreateArguments(`"C:\proxy.exe" --config "C:\config.yaml" serve`)
	want := []string{"create", WindowsServiceName, "binPath=", `"C:\proxy.exe" --config "C:\config.yaml" serve`, "start=", "auto", "obj=", `NT SERVICE\ClaudeEgressProxy`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("arguments = %q, want %q", got, want)
	}
}

func TestWindowsSelectorMismatchFailsBeforeMutation(t *testing.T) {
	mutated := false
	platform := windowsPlatform{
		run:        func(context.Context, string, ...string) error { mutated = true; return nil },
		executable: func() (string, error) { return `C:\proxy.exe`, nil },
		query:      func() (string, error) { return `"C:\proxy.exe" --config "C:\other.yaml" serve`, nil },
	}
	err := platform.Apply(context.Background(), Stop, Selection{ConfigPath: `C:\config.yaml`, StateRoot: `C:\state`})
	if err == nil || err.Error() != "service selector conflict" {
		t.Fatalf("Apply error = %v, want selector conflict", err)
	}
	if mutated {
		t.Fatal("service mutated before selector validation")
	}
}

func TestWindowsServiceDispatcherIsAvailable(t *testing.T) {
	if !windowsSCMDispatcherAvailable() {
		t.Fatal("SCM dispatcher must be available")
	}
}
