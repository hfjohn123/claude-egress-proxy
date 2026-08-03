//go:build linux

package securefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestLinuxExactPermissionsRejectsGroupOtherAndSpecialBits catches a validator
// that masks permissive or special bits rather than requiring an exact mode.
func TestLinuxExactPermissionsRejectsGroupOtherAndSpecialBits(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := OpenRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if !errors.Is(err, ErrPermissions) {
		t.Fatalf("OpenRoot group-readable error = %v, want ErrPermissions", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := OpenRoot(filepath.Clean(dir), RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
}
