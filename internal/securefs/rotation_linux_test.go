//go:build linux

package securefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"testing"
)

func TestLinuxRotationNamespaceRotatesPinnedGenerations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	policy := FilePolicy{Presence: Optional, Kind: RegularFile, Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o600)), MaxBytes: 64}
	root, err := OpenMutableRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	leaves := [3]string{"state", "state.1", "state.2"}
	ns, err := root.AcquireRotationNamespace(context.Background(), "state", leaves, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Close()
	ids := [3]Identity{}
	for i, name := range leaves {
		f, err := ns.Create(name, rotationPolicy(policy, MustBeAbsent))
		if err != nil {
			t.Fatalf("Create(%q): %v", name, err)
		}
		if _, err := f.WriteAt([]byte{byte('a' + i)}, 0); err != nil {
			t.Fatalf("WriteAt(%q): %v", name, err)
		}
		ids[i] = f.Identity()
		if err := f.Close(); err != nil {
			t.Fatalf("Close(%q): %v", name, err)
		}
	}

	active, err := ns.Rotate(leaves, ids)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if got, err := active.Size(); err != nil || got != 0 {
		t.Fatalf("new active size = %d, %v; want 0", got, err)
	}
	for _, name := range leaves {
		state, err := ns.Inspect(name, rotationPolicy(policy, Required))
		if err != nil || !state.Present {
			t.Fatalf("Inspect(%q) = %+v, %v", name, state, err)
		}
	}
	for _, want := range []struct {
		name string
		data string
	}{{"state.1", "a"}, {"state.2", "b"}} {
		got, _, err := ns.ReadFile(want.name, rotationPolicy(policy, Required))
		if err != nil || string(got) != want.data {
			t.Fatalf("ReadFile(%q) = %q, %v; want %q", want.name, got, err, want.data)
		}
	}
	if _, err := ns.Inspect("state.delete", policy); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Inspect tombstone error = %v, want ErrUnsafePath", err)
	}
}
