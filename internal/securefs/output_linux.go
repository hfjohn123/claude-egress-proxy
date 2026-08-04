//go:build linux

package securefs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

func platformPublishOutput(ctx context.Context, op platformRoot, rootPolicy RootPolicy, target string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	r, ok := op.(*linuxRoot)
	if !ok || r.recheck() != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := ctx.Err(); err != nil {
		return CommitBoundary{}, err
	}
	current, err := r.inspect(target, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if err != nil {
		return CommitBoundary{}, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	temp := fmt.Sprintf(".%s.%x.tmp", target, token)
	mode := uint32(0o600)
	if policy.Access.kind == permissionLinuxExact {
		mode = uint32(policy.Access.mode.Perm())
	}
	fd, err := unix.Openat(r.fd, temp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	keep := true
	defer func() {
		_ = unix.Close(fd)
		if keep {
			_ = unix.Unlinkat(r.fd, temp, 0)
		}
	}()
	st, e := linuxStat(fd)
	if e != nil || linuxCheck(st, RegularFile, policy.Access) != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	for wrote := 0; wrote < len(data); {
		n, we := unix.Write(fd, data[wrote:])
		if we != nil || n == 0 {
			return CommitBoundary{}, ErrUnsafePath
		}
		wrote += n
	}
	if unix.Fsync(fd) != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	if ctx.Err() != nil {
		return CommitBoundary{}, ctx.Err()
	}
	if current.Present {
		err = unix.Renameat(r.fd, temp, r.fd, target)
	} else {
		err = unix.Renameat2(r.fd, temp, r.fd, target, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return CommitBoundary{}, ErrAlreadyExists
		}
		return CommitBoundary{}, ErrUnsafePath
	}
	keep = false
	if unix.Fsync(r.fd) != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
	}
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}
