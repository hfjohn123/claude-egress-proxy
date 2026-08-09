//go:build linux

package containerinit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
)

var ErrUnsafeStateRoot = errors.New("container state root is unsafe")

// Prepare creates or tightens one exact container state root before the
// unprivileged proxy process starts.
func Prepare(path string, uid, gid int) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || uid < 1 || gid < 1 {
		return ErrUnsafeStateRoot
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return ErrUnsafeStateRoot
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&fs.ModeSymlink != 0 {
		return ErrUnsafeStateRoot
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return ErrUnsafeStateRoot
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return ErrUnsafeStateRoot
	}
	info, err = os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrUnsafeStateRoot
	}
	return nil
}
