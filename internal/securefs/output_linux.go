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
	if !ok {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := linuxOutputRoot(r, rootPolicy); err != nil {
		return CommitBoundary{}, err
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
	if linuxOutputRoot(r, rootPolicy) != nil {
		return CommitBoundary{}, ErrIdentityChanged
	}
	fd, err := unix.Openat(r.fd, temp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	var tempID Identity
	defer func() { _ = unix.Close(fd) }()
	st, e := linuxStat(fd)
	if e == nil {
		tempID = linuxIdentity(st)
	}
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
	if linuxOutputRoot(r, rootPolicy) != nil || !linuxTempCurrent(fd, tempID, policy) {
		return CommitBoundary{}, ErrIdentityChanged
	}
	now, inspectErr := r.inspect(target, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if inspectErr != nil || now.Present != current.Present || now.Present && now.Identity != current.Identity {
		return CommitBoundary{}, ErrIdentityChanged
	}
	// renameat is pathname-based. The retained descriptor establishes the
	// intended identity; this is the final attachment check before mutation.
	// Failed writes leave the random temp name: check-then-unlink cleanup could
	// delete a subsequently swapped file.
	if err := linuxOutputCommitHook(ctx); err != nil || !linuxTempPathCurrent(r.fd, temp, tempID, policy) {
		return CommitBoundary{}, ErrIdentityChanged
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
	if unix.Fsync(r.fd) != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
	}
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}

func linuxOutputRoot(r *linuxRoot, policy RootPolicy) error {
	if r.recheck() != nil {
		return ErrIdentityChanged
	}
	st, err := linuxStat(r.fd)
	if err != nil || linuxIdentity(st) != r.id {
		return ErrIdentityChanged
	}
	return linuxCheck(st, Directory, policy.Access)
}
func linuxTempCurrent(fd int, id Identity, policy FilePolicy) bool {
	st, err := linuxStat(fd)
	return err == nil && linuxIdentity(st) == id && linuxCheck(st, RegularFile, policy.Access) == nil
}
func linuxTempPathCurrent(rootFD int, name string, id Identity, policy FilePolicy) bool {
	var st unix.Stat_t
	return unix.Fstatat(rootFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && linuxIdentity(st) == id && linuxCheck(st, RegularFile, policy.Access) == nil
}
