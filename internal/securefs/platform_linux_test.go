//go:build linux

package securefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxCreateRootAndFileApplyFinalOwnerAndMode(t *testing.T) {
	base := t.TempDir()
	parent, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	uid := uint32(os.Getuid())
	created, err := CreateRoot(parent, "state", RootPolicy{Access: LinuxExactPermissions(uid, fs.FileMode(0o700))})
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	var directory unix.Stat_t
	if err := unix.Stat(filepath.Join(base, "state"), &directory); err != nil {
		t.Fatal(err)
	}
	if directory.Uid != uid || fs.FileMode(directory.Mode).Perm() != 0o700 {
		t.Fatalf("directory uid/mode = %d/%#o", directory.Uid, fs.FileMode(directory.Mode).Perm())
	}
	boundary, err := CreateFileOnce(context.Background(), created, "config", []byte("bytes"), FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: LinuxExactPermissions(uid, fs.FileMode(0o600)), MaxBytes: 5})
	if err != nil || boundary != (CommitBoundary{NamespacePublished: true, TargetDurable: true}) {
		t.Fatalf("CreateFileOnce = %+v,%v", boundary, err)
	}
	state, err := created.Inspect("config", FilePolicy{Presence: Required, Kind: RegularFile, Access: LinuxExactPermissions(uid, fs.FileMode(0o600)), MaxBytes: 5})
	if err != nil || !state.Present {
		t.Fatalf("created state = %+v,%v", state, err)
	}
}

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

func TestLinuxCleanupDoesNotDeleteSwapAfterVerification(t *testing.T) {
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
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	old := linuxCleanupAfterTombVerify
	t.Cleanup(func() { linuxCleanupAfterTombVerify = old })
	linuxCleanupAfterTombVerify = func(parentFD int, tomb string) {
		if err := unix.Renameat(parentFD, tomb, parentFD, "old"); err != nil {
			t.Fatal(err)
		}
		if err := unix.Mkdirat(parentFD, tomb, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	cleanupCreatedLinux(parentFD, "created", linuxIdentity(st))
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("cleanup removed every directory after a swap")
	}
}

func TestLinuxCleanupRenameFailureLeavesTombstone(t *testing.T) {
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
	_ = unix.Close(fd)
	if err != nil {
		t.Fatal(err)
	}
	oldMaker, oldRename := linuxCleanupMakeTombstone, linuxRenameExchange
	t.Cleanup(func() { linuxCleanupMakeTombstone, linuxRenameExchange = oldMaker, oldRename })
	linuxCleanupMakeTombstone = func(int) (string, error) {
		if err := unix.Mkdirat(parentFD, "tomb", 0o700); err != nil {
			return "", err
		}
		return "tomb", nil
	}
	linuxRenameExchange = func(int, string, int, string, uint) error { return unix.EIO }
	cleanupCreatedLinux(parentFD, "created", linuxIdentity(st))
	if _, err := os.Stat(filepath.Join(parent, "created")); err != nil {
		t.Fatalf("created member removed after exchange failure: %v", err)
	}
	if _, err := os.Stat(filepath.Join(parent, "tomb")); err != nil {
		t.Fatalf("tombstone removed after exchange failure: %v", err)
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
	_, err = OpenRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()+1), fs.FileMode(0o700))})
	if !errors.Is(err, ErrPermissions) {
		t.Fatalf("OpenRoot wrong UID error = %v, want ErrPermissions", err)
	}
	if err := os.Chmod(dir, 0o700|fs.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	_, err = OpenRoot(dir, RootPolicy{Access: LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))})
	if !errors.Is(err, ErrPermissions) {
		t.Fatalf("OpenRoot special-bit error = %v, want ErrPermissions", err)
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
