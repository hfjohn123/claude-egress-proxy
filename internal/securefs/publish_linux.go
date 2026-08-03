//go:build linux

package securefs

import (
	"context"
	"errors"
	"math"
	"time"

	"golang.org/x/sys/unix"
)

type linuxLockedFile struct {
	root       *linuxRoot
	rootPolicy RootPolicy
	name       string
	fd         int
	id         Identity
	policy     FilePolicy
	gate       *lockedGate
}

func platformWithExclusiveLock(ctx context.Context, op platformRoot, rootPolicy RootPolicy, name string, policy FilePolicy, fn func(LockedFile) error) error {
	r, ok := op.(*linuxRoot)
	if !ok {
		return ErrUnsafePath
	}
	if err := r.recheck(); err != nil {
		return err
	}
	fd, created, err := linuxOpenLock(r, name, policy)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	st, err := linuxStat(fd)
	if err != nil || linuxCheck(st, RegularFile, policy.Access) != nil {
		return ErrUnsafePath
	}
	if created {
		if err := unix.Fsync(fd); err != nil {
			return ErrUnsafePath
		}
		if err := unix.Fsync(r.fd); err != nil {
			return ErrUnsafePath
		}
	}
	if err := linuxLockContext(ctx, fd); err != nil {
		return err
	}
	defer unix.Flock(fd, unix.LOCK_UN)
	if err := r.recheck(); err != nil {
		return err
	}
	st, err = linuxStat(fd)
	if err != nil || linuxCheck(st, RegularFile, policy.Access) != nil {
		return ErrIdentityChanged
	}
	l := &linuxLockedFile{root: r, rootPolicy: rootPolicy, name: name, fd: fd, id: linuxIdentity(st), policy: policy, gate: newLockedGate()}
	defer l.gate.close()
	return fn(l)
}

func linuxOpenLock(r *linuxRoot, name string, policy FilePolicy) (int, bool, error) {
	fd, err := unix.Openat(r.fd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err == nil {
		return fd, false, nil
	}
	if !errors.Is(err, unix.ENOENT) {
		return -1, false, ErrUnsafePath
	}
	mode := uint32(0o600)
	if policy.Access.kind == permissionLinuxExact {
		mode = uint32(policy.Access.mode.Perm())
	}
	fd, err = unix.Openat(r.fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return linuxOpenLock(r, name, policy)
		}
		return -1, false, ErrUnsafePath
	}
	return fd, true, nil
}
func linuxLockContext(ctx context.Context, fd int) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return ErrUnsafePath
		}
		if err := waitForLockRetry(ctx, 5*time.Millisecond); err != nil {
			return err
		}
	}
}
func (l *linuxLockedFile) usable() error {
	if err := l.root.recheck(); err != nil {
		return err
	}
	rootStat, err := linuxStat(l.root.fd)
	if err != nil || linuxCheck(rootStat, Directory, l.rootPolicy.Access) != nil {
		return ErrPermissions
	}
	st, err := linuxStat(l.fd)
	if err != nil || linuxIdentity(st) != l.id {
		return ErrIdentityChanged
	}
	if err := linuxCheck(st, RegularFile, l.policy.Access); err != nil {
		return err
	}
	state, err := l.root.inspect(l.name, FilePolicy{Presence: Required, Kind: RegularFile, Access: l.policy.Access, MaxBytes: l.policy.MaxBytes})
	if err != nil || state.Identity != l.id {
		return ErrIdentityChanged
	}
	return nil
}
func (l *linuxLockedFile) Identity() Identity {
	if l.gate.begin() != nil {
		return Identity{}
	}
	defer l.gate.end()
	if l.usable() != nil {
		return Identity{}
	}
	return l.id
}
func (l *linuxLockedFile) RecheckIdentity() error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	return l.usable()
}
func (l *linuxLockedFile) Size() (int64, error) {
	if err := l.gate.begin(); err != nil {
		return 0, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return 0, err
	}
	st, err := linuxStat(l.fd)
	if err != nil {
		return 0, ErrUnsafePath
	}
	return st.Size, nil
}
func (l *linuxLockedFile) ReadAt(b []byte, off int64) (int, error) {
	if err := l.gate.begin(); err != nil {
		return 0, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, ErrUnsafePath
	}
	n, err := unix.Pread(l.fd, b, off)
	if err != nil {
		return n, err
	}
	return n, nil
}
func (l *linuxLockedFile) WriteAt(b []byte, off int64) (int, error) {
	if err := l.gate.begin(); err != nil {
		return 0, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return 0, err
	}
	if off < 0 || off > math.MaxInt64-int64(len(b)) {
		return 0, ErrUnsafePath
	}
	end := off + int64(len(b))
	if l.policy.MaxBytes > 0 && end > l.policy.MaxBytes {
		return 0, ErrTooLarge
	}
	n, err := unix.Pwrite(l.fd, b, off)
	if err != nil {
		return n, ErrUnsafePath
	}
	return n, nil
}
func (l *linuxLockedFile) Truncate(size int64) error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return err
	}
	if size < 0 {
		return ErrUnsafePath
	}
	if l.policy.MaxBytes > 0 && size > l.policy.MaxBytes {
		return ErrTooLarge
	}
	if err := unix.Ftruncate(l.fd, size); err != nil {
		return ErrUnsafePath
	}
	return nil
}
func (l *linuxLockedFile) Sync() error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return err
	}
	if err := unix.Fsync(l.fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}
func (l *linuxLockedFile) Inspect(name string, policy FilePolicy) (FileState, error) {
	if err := l.gate.begin(); err != nil {
		return FileState{}, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return FileState{}, err
	}
	if !validLeaf(name) || !validFilePolicy(policy) {
		return FileState{}, ErrUnsafePath
	}
	return l.root.inspect(name, policy)
}
func (l *linuxLockedFile) ReadFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if err := l.gate.begin(); err != nil {
		return nil, FileState{}, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return nil, FileState{}, err
	}
	if !validLeaf(name) || !validFilePolicy(policy) || policy.Kind != RegularFile || policy.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	return l.root.readFile(name, policy)
}

func (l *linuxLockedFile) CleanupReservedTemp(ctx context.Context, target, temp string, policy FilePolicy) error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validReservedNames(target, temp) || !validMutableFilePolicy(policy) {
		return ErrUnsafePath
	}
	state, err := l.root.inspect(temp, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if err != nil {
		return err
	}
	if !state.Present {
		return nil
	}
	fd, err := unix.Openat(l.root.fd, temp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIdentityChanged
	}
	st, statErr := linuxStat(fd)
	_ = unix.Close(fd)
	if statErr != nil || linuxIdentity(st) != state.Identity || linuxCheck(st, RegularFile, policy.Access) != nil {
		return ErrIdentityChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := unix.Unlinkat(l.root.fd, temp, 0); err != nil {
		return ErrUnsafePath
	}
	if err := unix.Fsync(l.root.fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}

func (l *linuxLockedFile) Publish(ctx context.Context, target, temp string, data []byte, policy FilePolicy, mode PublishMode, faults Faults) (CommitBoundary, error) {
	if err := l.gate.begin(); err != nil {
		return CommitBoundary{}, err
	}
	defer l.gate.end()
	var boundary CommitBoundary
	if err := l.usable(); err != nil {
		return boundary, err
	}
	if err := ctx.Err(); err != nil {
		return boundary, err
	}
	if !validReservedNames(target, temp) || !validMutableFilePolicy(policy) || (policy.MaxBytes > 0 && int64(len(data)) > policy.MaxBytes) || (mode != AbsentTarget && mode != PresentTarget) {
		return boundary, ErrUnsafePath
	}
	presence := MustBeAbsent
	if mode == PresentTarget {
		presence = Required
	}
	if _, err := l.root.inspect(target, FilePolicy{Presence: presence, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes}); err != nil {
		return boundary, err
	}
	if err := l.CleanupReservedTemp(ctx, target, temp, policy); err != nil {
		return boundary, err
	}
	if err := ctx.Err(); err != nil {
		return boundary, err
	}
	modeBits := uint32(0o600)
	if policy.Access.kind == permissionLinuxExact {
		modeBits = uint32(policy.Access.mode.Perm())
	}
	fd, err := unix.Openat(l.root.fd, temp, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, modeBits)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return boundary, ErrAlreadyExists
		}
		return boundary, ErrUnsafePath
	}
	defer unix.Close(fd)
	st, err := linuxStat(fd)
	if err != nil || linuxCheck(st, RegularFile, policy.Access) != nil {
		return boundary, ErrUnsafePath
	}
	if faults == nil {
		faults = NoFaults{}
	}
	if err := faults.hit(BeforeTempWrite); err != nil {
		return boundary, err
	}
	if err := ctx.Err(); err != nil {
		return boundary, err
	}
	for at := 0; at < len(data); {
		n, writeErr := unix.Write(fd, data[at:])
		if n > 0 {
			at += n
		}
		if writeErr != nil || n == 0 {
			return boundary, ErrUnsafePath
		}
	}
	if err := unix.Fsync(fd); err != nil {
		return boundary, ErrUnsafePath
	}
	if err := faults.hit(AfterTempFlush); err != nil {
		return boundary, err
	}
	if err := ctx.Err(); err != nil {
		return boundary, err
	}
	if mode == AbsentTarget {
		err = unix.Renameat2(l.root.fd, temp, l.root.fd, target, unix.RENAME_NOREPLACE)
	} else {
		err = unix.Renameat(l.root.fd, temp, l.root.fd, target)
	}
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return boundary, ErrAlreadyExists
		}
		return boundary, ErrUnsafePath
	}
	boundary.NamespacePublished = true
	if err := faults.hit(AfterPublication); err != nil {
		return boundary, err
	}
	if err := ctx.Err(); err != nil {
		return boundary, err
	}
	targetFD, err := unix.Openat(l.root.fd, target, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return boundary, ErrUnsafePath
	}
	targetStat, statErr := linuxStat(targetFD)
	if statErr != nil || linuxCheck(targetStat, RegularFile, policy.Access) != nil {
		_ = unix.Close(targetFD)
		return boundary, ErrUnsafePath
	}
	err = unix.Fsync(targetFD)
	_ = unix.Close(targetFD)
	if err != nil {
		return boundary, ErrUnsafePath
	}
	if err := unix.Fsync(l.root.fd); err != nil {
		return boundary, ErrUnsafePath
	}
	boundary.TargetDurable = true
	if err := faults.hit(AfterTargetDurability); err != nil {
		return boundary, err
	}
	return boundary, nil
}
