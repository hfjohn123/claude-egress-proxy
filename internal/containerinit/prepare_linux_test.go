//go:build linux

package containerinit

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestPrepareCreatesExactOwnedPrivateStateRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state")
	uid, gid := os.Geteuid(), os.Getegid()
	if uid == 0 || gid == 0 {
		uid, gid = 65532, 65532
	}
	if err := Prepare(path, uid, gid); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("state info=%v err=%v", info, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != uid || int(stat.Gid) != gid {
		t.Fatalf("state ownership=%v want uid=%d gid=%d", info.Sys(), uid, gid)
	}
}

func TestPrepareRejectsSymlinkAndRelativePath(t *testing.T) {
	if err := Prepare("relative", os.Geteuid(), os.Getegid()); !errors.Is(err, ErrUnsafeStateRoot) {
		t.Fatalf("relative err=%v", err)
	}
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(link, os.Geteuid(), os.Getegid()); !errors.Is(err, ErrUnsafeStateRoot) {
		t.Fatalf("symlink err=%v", err)
	}
}
