//go:build linux

package securefs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLinuxCleanupDoesNotDeleteReplacement catches the check-then-unlink race
// where a replacement is installed after identity validation.
func TestLinuxCleanupDoesNotDeleteReplacement(t *testing.T) {
	parent := t.TempDir()
	parentFD, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(parentFD)
	if err := os.Mkdir(filepath.Join(parent, "created"), 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Openat(parentFD, "created", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	st, err := linuxStat(fd)
	if err != nil {
		t.Fatal(err)
	}
	_ = unix.Close(fd)
	want := linuxIdentity(st)
	old := linuxCleanupBeforeExchange
	t.Cleanup(func() { linuxCleanupBeforeExchange = old })
	linuxCleanupBeforeExchange = func() {
		if err := os.Rename(filepath.Join(parent, "created"), filepath.Join(parent, "old")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(parent, "created"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cleanupCreatedLinux(parentFD, "created", want)
	fd, err = unix.Openat(parentFD, "created", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("replacement was removed: %v", err)
	}
	defer unix.Close(fd)
	got, err := linuxStat(fd)
	if err != nil {
		t.Fatal(err)
	}
	if linuxIdentity(got) == want {
		t.Fatal("replacement identity was not preserved")
	}
}

// TestWindowsPolicyAPIIsPresentOnLinux catches shared configuration code that
// cannot compile on Linux merely because it names a Windows policy constructor.
func TestWindowsPolicyAPIIsPresentOnLinux(t *testing.T) {
	if _, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544"}, 1); !errors.Is(err, ErrUnsupportedInspection) {
		t.Fatalf("Windows policy stub error = %v, want ErrUnsupportedInspection", err)
	}
}

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
