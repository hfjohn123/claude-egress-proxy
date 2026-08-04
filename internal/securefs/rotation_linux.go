//go:build linux

package securefs

import (
	"context"
	"errors"
	"math"
	"sync"

	"golang.org/x/sys/unix"
)

// linuxRotationNamespace keeps one advisory lock for the whole generation
// set. Its only mutable names are the three generations and the two approved
// coordination members created while the lock is held.
type linuxRotationNamespace struct {
	root       *mutableRoot
	op         *linuxRoot
	rootPolicy RootPolicy
	leaves     [3]string
	policy     FilePolicy
	lock       int
	tomb       *linuxRetainedFile

	mu       sync.Mutex
	mutation sync.Mutex
	closing  bool
	closed   bool
	active   int
	finished bool
}

type linuxRetainedFile struct {
	ns     *linuxRotationNamespace
	name   string
	fd     int
	id     Identity
	policy FilePolicy

	mu     sync.Mutex
	closed bool
	active int
}

func (r *mutableRoot) AcquireRotationNamespace(ctx context.Context, base string, leaves [3]string, policy FilePolicy) (RotationNamespace, error) {
	if ctx == nil || !validRotationNamespace(base, leaves, policy) {
		return nil, ErrUnsafePath
	}
	if err := r.lease(); err != nil {
		return nil, err
	}
	fail := func(err error) (RotationNamespace, error) { r.release(); return nil, err }
	op, ok := r.op.(*linuxRoot)
	if !ok || op.recheck() != nil {
		return fail(ErrIdentityChanged)
	}
	rootStat, err := linuxStat(op.fd)
	if err != nil || linuxCheck(rootStat, Directory, r.policy.Access) != nil {
		return fail(ErrPermissions)
	}

	lockPolicy := rotationPolicy(policy, Optional)
	lockPolicy.MaxBytes = 0
	lock, created, err := linuxOpenLock(op, base+".lock", lockPolicy)
	if err != nil {
		return fail(err)
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = unix.Close(lock)
		}
	}()
	lockStat, err := linuxStat(lock)
	if err != nil || linuxCheck(lockStat, RegularFile, lockPolicy.Access) != nil || lockStat.Size != 0 {
		return fail(ErrUnsafePath)
	}
	if created && (unix.Fsync(lock) != nil || unix.Fsync(op.fd) != nil) {
		return fail(ErrUnsafePath)
	}
	if err := linuxLockContext(ctx, lock); err != nil {
		return fail(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = unix.Flock(lock, unix.LOCK_UN)
		}
	}()
	if err := op.recheck(); err != nil {
		return fail(err)
	}
	tomb, err := openLinuxRotationFile(op, base+".delete", rotationPolicy(policy, Optional), true)
	if err != nil {
		return fail(err)
	}
	ns := &linuxRotationNamespace{root: r, op: op, rootPolicy: r.policy, leaves: leaves, policy: policy, lock: lock, tomb: tomb}
	tomb.ns = ns
	locked, closeLock = false, false
	return ns, nil
}

func openLinuxRotationFile(root *linuxRoot, name string, policy FilePolicy, create bool) (*linuxRetainedFile, error) {
	fd, err := unix.Openat(root.fd, name, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) || !create {
			if errors.Is(err, unix.ENOENT) {
				return nil, ErrNotFound
			}
			return nil, linuxPathOpenError(root.fd, name, err)
		}
		mode := uint32(0o600)
		if policy.Access.kind == permissionLinuxExact {
			mode = uint32(policy.Access.mode.Perm())
		}
		fd, err = unix.Openat(root.fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
		if err != nil {
			if errors.Is(err, unix.EEXIST) {
				return openLinuxRotationFile(root, name, policy, true)
			}
			return nil, linuxPathOpenError(root.fd, name, err)
		}
	}
	st, err := linuxStat(fd)
	if err != nil || linuxCheck(st, RegularFile, policy.Access) != nil || (policy.MaxBytes > 0 && st.Size > policy.MaxBytes) {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	return &linuxRetainedFile{name: name, fd: fd, id: linuxIdentity(st), policy: policy}, nil
}

func (n *linuxRotationNamespace) begin() error {
	n.mu.Lock()
	if n.closing || n.closed {
		n.mu.Unlock()
		return ErrClosed
	}
	n.active++
	n.mu.Unlock()
	if err := n.op.recheck(); err != nil {
		n.end()
		return err
	}
	rootStat, err := linuxStat(n.op.fd)
	if err != nil || linuxCheck(rootStat, Directory, n.rootPolicy.Access) != nil {
		n.end()
		return ErrPermissions
	}
	return nil
}

func (n *linuxRotationNamespace) end() {
	n.mu.Lock()
	n.active--
	finish := n.closing && n.active == 0 && !n.finished
	if finish {
		n.finished = true
	}
	n.mu.Unlock()
	if finish {
		n.finishClose()
	}
}

func (n *linuxRotationNamespace) finishClose() {
	if n.lock >= 0 {
		_ = unix.Flock(n.lock, unix.LOCK_UN)
		_ = unix.Close(n.lock)
		n.lock = -1
	}
	if n.tomb != nil {
		n.tomb.closeDetached()
	}
	n.root.release()
}

func (n *linuxRotationNamespace) RecheckIdentity() error {
	if err := n.begin(); err != nil {
		return err
	}
	defer n.end()
	return n.op.recheck()
}

// RepairTombstone clears only the identity-pinned discard slot.  The slot is
// checked as the attached .delete member before its retained descriptor is
// truncated and synced; it never names a member for mutation.
func (n *linuxRotationNamespace) RepairTombstone() error {
	if err := n.begin(); err != nil {
		return err
	}
	defer n.end()
	n.mutation.Lock()
	defer n.mutation.Unlock()
	n.mu.Lock()
	tomb := n.tomb
	n.mu.Unlock()
	if tomb == nil {
		return ErrIdentityChanged
	}
	state, err := n.op.inspect(tomb.name, rotationPolicy(n.policy, Required))
	if err != nil || !state.Present || state.Identity != tomb.id {
		return ErrIdentityChanged
	}
	return tomb.truncateAndSync(0)
}

func (n *linuxRotationNamespace) allowed(name string) bool {
	return name == n.leaves[0] || name == n.leaves[1] || name == n.leaves[2]
}

func (n *linuxRotationNamespace) Inspect(name string, policy FilePolicy) (FileState, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) {
		return FileState{}, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return FileState{}, err
	}
	defer n.end()
	return n.op.inspect(name, policy)
}

func (n *linuxRotationNamespace) ReadFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, FileState{}, err
	}
	defer n.end()
	return n.op.readFile(name, policy)
}

func (n *linuxRotationNamespace) Open(name string, policy FilePolicy) (RetainedFile, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != Required {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	f, err := openLinuxRotationFile(n.op, name, policy, false)
	if err != nil {
		return nil, err
	}
	state, err := n.op.inspect(name, policy)
	if err != nil || !state.Present || state.Identity != f.id {
		_ = unix.Close(f.fd)
		return nil, ErrIdentityChanged
	}
	f.ns = n
	return f, nil
}

func (n *linuxRotationNamespace) Create(name string, policy FilePolicy) (RetainedFile, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != MustBeAbsent {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	mode := uint32(0o600)
	if policy.Access.kind == permissionLinuxExact {
		mode = uint32(policy.Access.mode.Perm())
	}
	fd, err := unix.Openat(n.op.fd, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrAlreadyExists
		}
		return nil, linuxPathOpenError(n.op.fd, name, err)
	}
	st, err := linuxStat(fd)
	if err != nil || linuxCheck(st, RegularFile, policy.Access) != nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	return &linuxRetainedFile{ns: n, name: name, fd: fd, id: linuxIdentity(st), policy: policy}, nil
}

func (n *linuxRotationNamespace) Rotate(leaves [3]string, ids [3]Identity) (RetainedFile, error) {
	if leaves != n.leaves {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	n.mutation.Lock()
	defer n.mutation.Unlock()
	for i, name := range leaves {
		state, err := n.op.inspect(name, rotationPolicy(n.policy, Required))
		if err != nil || !state.Present || state.Identity != ids[i] {
			return nil, ErrIdentityChanged
		}
	}
	tombID := n.tomb.id
	if err := unix.Renameat2(n.op.fd, leaves[2], n.op.fd, n.leaves[0]+".delete", unix.RENAME_EXCHANGE); err != nil {
		return nil, ErrUnsafePath
	}
	discarded, err := openLinuxRotationFile(n.op, n.leaves[0]+".delete", rotationPolicy(n.policy, Required), false)
	if err != nil || discarded.id != ids[2] {
		if discarded != nil {
			_ = discarded.Close()
		}
		return nil, ErrIdentityChanged
	}
	discarded.ns = n
	if err := discarded.Truncate(0); err != nil {
		_ = discarded.Close()
		return nil, err
	}
	if err := linuxRotationExchange(n.op.fd, leaves[1], n.op.fd, leaves[2], unix.RENAME_EXCHANGE); err != nil {
		_ = discarded.Close()
		return nil, ErrUnsafePath
	}
	if state, err := n.op.inspect(leaves[2], rotationPolicy(n.policy, Required)); err != nil || state.Identity != ids[1] {
		_ = discarded.Close()
		return nil, ErrIdentityChanged
	}
	if err := linuxRotationExchange(n.op.fd, leaves[0], n.op.fd, leaves[1], unix.RENAME_EXCHANGE); err != nil {
		_ = discarded.Close()
		return nil, ErrUnsafePath
	}
	if state, err := n.op.inspect(leaves[1], rotationPolicy(n.policy, Required)); err != nil || state.Identity != ids[0] {
		_ = discarded.Close()
		return nil, ErrIdentityChanged
	}
	active, err := n.Open(leaves[0], rotationPolicy(n.policy, Required))
	if err != nil || active.Identity() != tombID {
		if active != nil {
			_ = active.Close()
		}
		_ = discarded.Close()
		return nil, ErrIdentityChanged
	}
	if err := active.Truncate(0); err != nil {
		_ = active.Close()
		_ = discarded.Close()
		return nil, err
	}
	n.mu.Lock()
	oldTomb := n.tomb
	n.tomb = discarded
	n.mu.Unlock()
	oldTomb.closeDetached()
	return active, nil
}

var linuxRotationExchange = unix.Renameat2

func (n *linuxRotationNamespace) Close() error {
	n.mu.Lock()
	if n.closing || n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closing, n.closed = true, true
	finish := n.active == 0 && !n.finished
	if finish {
		n.finished = true
	}
	n.mu.Unlock()
	if finish {
		n.finishClose()
	}
	return nil
}

func (f *linuxRetainedFile) begin() (int, error) {
	if err := f.ns.begin(); err != nil {
		return -1, err
	}
	f.mu.Lock()
	if f.closed || f.fd < 0 {
		f.mu.Unlock()
		f.ns.end()
		return -1, ErrClosed
	}
	f.active++
	fd := f.fd
	f.mu.Unlock()
	return fd, nil
}

func (f *linuxRetainedFile) end() {
	f.mu.Lock()
	f.active--
	closeNow := f.closed && f.active == 0 && f.fd >= 0
	fd := f.fd
	if closeNow {
		f.fd = -1
	}
	f.mu.Unlock()
	if closeNow {
		_ = unix.Close(fd)
	}
	f.ns.end()
}

func (f *linuxRetainedFile) usable(fd int) error {
	if err := f.ns.op.recheck(); err != nil {
		return err
	}
	st, err := linuxStat(fd)
	if err != nil || linuxIdentity(st) != f.id || linuxCheck(st, RegularFile, f.policy.Access) != nil {
		return ErrIdentityChanged
	}
	return nil
}

func (f *linuxRetainedFile) Identity() Identity {
	fd, err := f.begin()
	if err != nil {
		return Identity{}
	}
	defer f.end()
	if f.usable(fd) != nil {
		return Identity{}
	}
	return f.id
}

func (f *linuxRetainedFile) RecheckIdentity() error {
	fd, err := f.begin()
	if err != nil {
		return err
	}
	defer f.end()
	return f.usable(fd)
}

func (f *linuxRetainedFile) Size() (int64, error) {
	fd, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(fd); err != nil {
		return 0, err
	}
	st, err := linuxStat(fd)
	if err != nil {
		return 0, ErrUnsafePath
	}
	return st.Size, nil
}

func (f *linuxRetainedFile) ReadAt(b []byte, off int64) (int, error) {
	fd, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(fd); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, ErrUnsafePath
	}
	n, err := unix.Pread(fd, b, off)
	if err != nil {
		return n, ErrUnsafePath
	}
	return n, nil
}

func (f *linuxRetainedFile) WriteAt(b []byte, off int64) (int, error) {
	fd, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(fd); err != nil {
		return 0, err
	}
	if off < 0 || off > math.MaxInt64-int64(len(b)) {
		return 0, ErrUnsafePath
	}
	if f.policy.MaxBytes > 0 && off+int64(len(b)) > f.policy.MaxBytes {
		return 0, ErrTooLarge
	}
	n, err := unix.Pwrite(fd, b, off)
	if err != nil {
		return n, ErrUnsafePath
	}
	return n, nil
}

func (f *linuxRetainedFile) Truncate(size int64) error {
	fd, err := f.begin()
	if err != nil {
		return err
	}
	defer f.end()
	if err := f.usable(fd); err != nil {
		return err
	}
	if size < 0 {
		return ErrUnsafePath
	}
	if f.policy.MaxBytes > 0 && size > f.policy.MaxBytes {
		return ErrTooLarge
	}
	if err := unix.Ftruncate(fd, size); err != nil {
		return ErrUnsafePath
	}
	return nil
}

func (f *linuxRetainedFile) truncateAndSync(size int64) error {
	fd, err := f.begin()
	if err != nil {
		return err
	}
	defer f.end()
	if err := f.usable(fd); err != nil {
		return err
	}
	if size < 0 || (f.policy.MaxBytes > 0 && size > f.policy.MaxBytes) {
		return ErrUnsafePath
	}
	if err := unix.Ftruncate(fd, size); err != nil {
		return ErrUnsafePath
	}
	if err := unix.Fsync(fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}

func (f *linuxRetainedFile) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	closeNow := f.active == 0 && f.fd >= 0
	fd := f.fd
	if closeNow {
		f.fd = -1
	}
	f.mu.Unlock()
	if closeNow {
		_ = unix.Close(fd)
	}
	return nil
}

func (f *linuxRetainedFile) closeDetached() {
	_ = f.Close()
}

var _ RetainedFile = (*linuxRetainedFile)(nil)
var _ RotationNamespace = (*linuxRotationNamespace)(nil)
