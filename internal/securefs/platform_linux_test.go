//go:build linux

package securefs

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

func TestLinuxCreateRootMapsNamespaceIOFailuresToPlatformFailure(t *testing.T) {
	for _, injected := range []error{unix.ENOSPC, unix.EDQUOT, unix.EIO, unix.EFBIG} {
		t.Run(injected.Error(), func(t *testing.T) {
			old := linuxCreateDirectory
			t.Cleanup(func() { linuxCreateDirectory = old })
			linuxCreateDirectory = func(int, string, uint32) error { return injected }
			parent, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if _, err := CreateRoot(parent, "state", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrUnsupportedInspection) || errors.Is(err, ErrUnsafePath) {
				t.Fatalf("CreateRoot error = %v, want platform failure without ErrUnsafePath", err)
			}
		})
	}
	old := linuxCreateDirectory
	t.Cleanup(func() { linuxCreateDirectory = old })
	linuxCreateDirectory = func(int, string, uint32) error { return unix.EACCES }
	parent, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if _, err := CreateRoot(parent, "state", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrPermissions) {
		t.Fatalf("CreateRoot access error = %v, want ErrPermissions", err)
	}
}

func TestLinuxCreateFileOnceFailuresQuarantineCreatedLeafAwayFromRequestedName(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func()
		want      error
	}{
		{"write", func() {
			linuxCreateOnceWrite = func(int, []byte) (int, error) { return 0, unix.ENOSPC }
		}, ErrUnsupportedInspection},
		{"validation", func() {
			linuxCreateOnceFinalStat = func(int) (unix.Stat_t, error) { return unix.Stat_t{}, unix.EIO }
		}, ErrUnsupportedInspection},
		{"file fsync", func() {
			linuxCreateOnceFsync = func(int) error { return unix.EIO }
		}, ErrUnsupportedInspection},
		{"parent fsync", func() {
			calls := 0
			linuxCreateOnceFsync = func(int) error {
				calls++
				if calls == 2 {
					return unix.EIO
				}
				return nil
			}
		}, ErrUnsupportedInspection},
	} {
		t.Run(test.name, func(t *testing.T) {
			oldWrite, oldStat, oldFsync := linuxCreateOnceWrite, linuxCreateOnceFinalStat, linuxCreateOnceFsync
			t.Cleanup(func() {
				linuxCreateOnceWrite, linuxCreateOnceFinalStat, linuxCreateOnceFsync = oldWrite, oldStat, oldFsync
			})
			test.configure()
			base := t.TempDir()
			root, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
			boundary, err := CreateFileOnce(context.Background(), root, "failed", []byte("four"), policy)
			if !errors.Is(err, test.want) || boundary != (CommitBoundary{NamespacePublished: true}) {
				t.Fatalf("CreateFileOnce = %+v,%v, want %v", boundary, err, test.want)
			}
			state, err := root.Inspect("failed", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4})
			if err != nil || state.Present {
				t.Fatalf("failed leaf remained = %+v,%v", state, err)
			}
			entries, err := os.ReadDir(base)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), ".securefs-cleanup-file-") {
				t.Fatalf("cleanup quarantine = %v", entries)
			}
		})
	}
}

func TestLinuxCreateFileOnceCleanupNeverUnlinksSwapAfterFinalVerification(t *testing.T) {
	oldWrite, oldAfterFinal := linuxCreateOnceWrite, linuxCreateOnceCleanupAfterFinalVerify
	t.Cleanup(func() {
		linuxCreateOnceWrite, linuxCreateOnceCleanupAfterFinalVerify = oldWrite, oldAfterFinal
	})
	linuxCreateOnceWrite = func(int, []byte) (int, error) { return 0, unix.ENOSPC }
	base := t.TempDir()
	var tomb string
	linuxCreateOnceCleanupAfterFinalVerify = func(parentFD int, quarantine string) {
		tomb = quarantine
		if err := unix.Renameat(parentFD, quarantine, parentFD, "original"); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Openat(parentFD, quarantine, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(fd, []byte("replacement")); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	}
	root, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	if _, err := CreateFileOnce(context.Background(), root, "failed", []byte("four"), policy); !errors.Is(err, ErrUnsupportedInspection) {
		t.Fatalf("CreateFileOnce error = %v", err)
	}
	if tomb == "" {
		t.Fatal("final verification hook was not reached")
	}
	if _, err := os.Stat(filepath.Join(base, "failed")); !os.IsNotExist(err) {
		t.Fatalf("requested leaf was restored: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, tomb))
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q,%v", got, err)
	}
	if _, err := os.Stat(filepath.Join(base, "original")); err != nil {
		t.Fatalf("proved created identity lost: %v", err)
	}
}

func TestLinuxCreateFileOnceCleanupPreservesReplacementBeforeMove(t *testing.T) {
	oldWrite, oldBefore := linuxCreateOnceWrite, linuxCreateOnceCleanupBeforeMove
	t.Cleanup(func() {
		linuxCreateOnceWrite, linuxCreateOnceCleanupBeforeMove = oldWrite, oldBefore
	})
	linuxCreateOnceWrite = func(int, []byte) (int, error) { return 0, unix.ENOSPC }
	base := t.TempDir()
	linuxCreateOnceCleanupBeforeMove = func() {
		if err := os.Rename(filepath.Join(base, "failed"), filepath.Join(base, "original")); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "failed"), []byte("replacement"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	if _, err := CreateFileOnce(context.Background(), root, "failed", []byte("four"), policy); !errors.Is(err, ErrUnsupportedInspection) {
		t.Fatalf("CreateFileOnce error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, "failed"))
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q,%v", got, err)
	}
}

func TestLinuxCreateFileOnceCleanupPreservesSwapAfterVerification(t *testing.T) {
	oldWrite, oldAfter := linuxCreateOnceWrite, linuxCreateOnceCleanupAfterVerify
	t.Cleanup(func() {
		linuxCreateOnceWrite, linuxCreateOnceCleanupAfterVerify = oldWrite, oldAfter
	})
	linuxCreateOnceWrite = func(int, []byte) (int, error) { return 0, unix.ENOSPC }
	base := t.TempDir()
	linuxCreateOnceCleanupAfterVerify = func(parentFD int, tomb string) {
		if err := unix.Renameat(parentFD, tomb, parentFD, "original"); err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Openat(parentFD, tomb, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := unix.Write(fd, []byte("replacement")); err != nil {
			t.Fatal(err)
		}
		_ = unix.Close(fd)
	}
	root, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	if _, err := CreateFileOnce(context.Background(), root, "failed", []byte("four"), policy); !errors.Is(err, ErrUnsupportedInspection) {
		t.Fatalf("CreateFileOnce error = %v", err)
	}
	got, err := os.ReadFile(filepath.Join(base, "failed"))
	if err != nil || string(got) != "replacement" {
		t.Fatalf("replacement = %q,%v", got, err)
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
