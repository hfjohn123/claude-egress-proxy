//go:build linux && cep_testcontrol

package securefs

import (
	"io/fs"
	"os"
	"testing"
)

func mutableTestRoot(t *testing.T) MutableRoot {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func mutableFilePolicy(p Presence, max int64) FilePolicy {
	return FilePolicy{Presence: p, Kind: RegularFile, Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o600)), MaxBytes: max}
}
