//go:build windows

package service

import (
	"context"
	"errors"
	"testing"
)

func TestWindowsServiceCommandQuotesBothPaths(t *testing.T) {
	got := windowsCommandLine(`C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe`, `C:\ProgramData\Claude Egress Proxy\config.yaml`)
	want := `"C:\Program Files\Claude Egress Proxy\claude-egress-proxy.exe" --config "C:\ProgramData\Claude Egress Proxy\config.yaml" serve`
	if got != want {
		t.Fatalf("command = %q, want %q", got, want)
	}
}

func TestWindowsServiceCommandsFailClosedWithoutSCMDispatcher(t *testing.T) {
	platform := NewPlatform()
	for _, action := range []Action{Install, Uninstall, Start, Stop} {
		if err := Execute(context.Background(), platform, action, `C:\ProgramData\Claude Egress Proxy\config.yaml`); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s error = %v, want ErrUnsupported", action, err)
		}
	}
}
