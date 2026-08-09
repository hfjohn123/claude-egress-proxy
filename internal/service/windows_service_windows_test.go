//go:build windows

package service

import "testing"

func TestWindowsServiceCommandQuotesBothPaths(t *testing.T) {
	got := windowsCommandLine(`C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe`, `C:\ProgramData\Claude Egress Proxy\config.yaml`)
	want := `"C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe" --config "C:\ProgramData\Claude Egress Proxy\config.yaml" serve`
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestWindowsServiceDispatcherIsAvailable(t *testing.T) {
	if !windowsSCMDispatcherAvailable() {
		t.Fatal("SCM dispatcher must be available")
	}
}
