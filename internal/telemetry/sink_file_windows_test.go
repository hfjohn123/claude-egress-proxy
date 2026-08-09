//go:build windows

package telemetry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"golang.org/x/sys/windows"
)

func TestOpenFileSinkCreatesGenerationMembersAndAppendsRecord(t *testing.T) {
	root, path, policy := newWindowsFileSinkRoot(t)
	defer root.Close()
	sink, err := OpenFileSink(context.Background(), root, "events", policy)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := TunnelClosed(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), mustCloseResult(t, "clean"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.WriteRecord([]byte(clean.JSON())); err != nil {
		t.Fatal(err)
	}
	if err := sink.Close(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events", "events.1", "events.2", "events.lock", "events.delete"} {
		if _, err := os.Stat(filepath.Join(path, name)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(path, "events"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != clean.JSON()+"\n" {
		t.Fatalf("active = %q", got)
	}
}

func newWindowsFileSinkRoot(t *testing.T) (securefs.MutableRoot, string, securefs.FilePolicy) {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	const all = uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	access, err := securefs.WindowsRestrictedPermissions([]string{user.User.Sid.String()}, all)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	parent, err := securefs.OpenCreateCapableRoot(dir, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = parent.Close() })
	state, err := securefs.CreateRoot(parent, "state", securefs.RootPolicy{Access: access})
	if err != nil {
		t.Fatal(err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state")
	root, err := securefs.OpenMutableRoot(path, securefs.RootPolicy{Access: access})
	if err != nil {
		t.Fatal(err)
	}
	return root, path, securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: access, MaxBytes: fileSinkMemberBytes}
}
