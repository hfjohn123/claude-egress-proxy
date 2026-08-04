//go:build windows

package securefs

import (
	"context"
	"errors"
	"math"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsRotationNamespace pins the mutable root for the complete lifetime of
// its lock.  Close only closes handles that have no admitted syscall; an
// admitted syscall releases its own handle afterwards, preventing handle reuse
// races with a concurrent Close.
type windowsRotationNamespace struct {
	root       *mutableRoot
	op         *windowsRoot
	rootPolicy RootPolicy
	base       string
	leaves     [3]string
	policy     FilePolicy
	lock       windows.Handle
	tomb       *windowsRetainedFile

	mu       sync.Mutex
	closing  bool
	closed   bool
	active   int
	finished bool
}

type windowsRetainedFile struct {
	ns     *windowsRotationNamespace
	name   string
	fd     windows.Handle
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
	op, ok := r.op.(*windowsRoot)
	if !ok || op.recheck() != nil {
		return fail(ErrIdentityChanged)
	}
	rootInfo, err := winInfo(op.fd)
	if err != nil || winCheck(op.fd, rootInfo, Directory, r.policy.Access) != nil {
		return fail(ErrPermissions)
	}
	lockPolicy := rotationPolicy(policy, Optional)
	lockPolicy.MaxBytes = 0
	lock, created, err := winOpenLock(op, base+".lock", lockPolicy)
	if err != nil {
		return fail(err)
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = windows.CloseHandle(lock)
		}
	}()
	info, err := winInfo(lock)
	if err != nil || winCheck(lock, info, RegularFile, lockPolicy.Access) != nil || winFileSize(info) != 0 {
		return fail(ErrUnsafePath)
	}
	if created && windows.FlushFileBuffers(lock) != nil {
		return fail(ErrUnsafePath)
	}
	if err := winLockContext(ctx, lock); err != nil {
		return fail(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = windows.UnlockFileEx(lock, 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
		}
	}()
	if err := op.recheck(); err != nil {
		return fail(err)
	}
	tomb, err := openRotationFile(op, base+".delete", rotationPolicy(policy, Optional), true)
	if err != nil {
		return fail(err)
	}
	ns := &windowsRotationNamespace{root: r, op: op, rootPolicy: r.policy, base: base, leaves: leaves, policy: policy, lock: lock}
	tomb.ns = ns
	ns.tomb = tomb
	locked, closeLock = false, false
	return ns, nil
}

func winFileSize(info windows.ByHandleFileInformation) int64 {
	return int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow))
}

func openRotationFile(root *windowsRoot, name string, policy FilePolicy, create bool) (*windowsRetainedFile, error) {
	h, err := winOpenState(root.fd, name, false, policy)
	if err != nil {
		if !winNotFound(err) || !create {
			return nil, ErrUnsafePath
		}
		h, err = winOpenState(root.fd, name, true, policy)
		if err != nil {
			if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
				return openRotationFile(root, name, policy, true)
			}
			return nil, ErrUnsafePath
		}
	}
	info, err := winInfo(h)
	id, idErr := winIdentity(h, info)
	if err != nil || idErr != nil || winCheck(h, info, RegularFile, policy.Access) != nil || (policy.MaxBytes > 0 && winFileSize(info) > policy.MaxBytes) {
		_ = windows.CloseHandle(h)
		return nil, ErrUnsafePath
	}
	return &windowsRetainedFile{name: name, fd: h, id: id, policy: policy}, nil
}

func (n *windowsRotationNamespace) begin() error {
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
	rootInfo, err := winInfo(n.op.fd)
	if err != nil || winCheck(n.op.fd, rootInfo, Directory, n.rootPolicy.Access) != nil {
		n.end()
		return ErrPermissions
	}
	return nil
}
func (n *windowsRotationNamespace) end() {
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
func (n *windowsRotationNamespace) finishClose() {
	if n.lock != 0 {
		_ = windows.UnlockFileEx(n.lock, 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
		_ = windows.CloseHandle(n.lock)
		n.lock = 0
	}
	n.tomb.closeDetached()
	n.root.release()
}
func (n *windowsRotationNamespace) RecheckIdentity() error {
	if err := n.begin(); err != nil {
		return err
	}
	defer n.end()
	return n.op.recheck()
}
func (n *windowsRotationNamespace) allowed(name string) bool {
	return name == n.leaves[0] || name == n.leaves[1] || name == n.leaves[2]
}
func (n *windowsRotationNamespace) Inspect(name string, policy FilePolicy) (FileState, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) {
		return FileState{}, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return FileState{}, err
	}
	defer n.end()
	return n.op.inspect(name, policy)
}
func (n *windowsRotationNamespace) ReadFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, FileState{}, err
	}
	defer n.end()
	return n.op.readFile(name, policy)
}
func (n *windowsRotationNamespace) Open(name string, policy FilePolicy) (RetainedFile, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != Required {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	f, err := openRotationFile(n.op, name, policy, false)
	if err != nil {
		return nil, err
	}
	state, err := n.op.inspect(name, policy)
	if err != nil || !state.Present || state.Identity != f.id {
		_ = windows.CloseHandle(f.fd)
		return nil, ErrIdentityChanged
	}
	f.ns = n
	return f, nil
}
func (n *windowsRotationNamespace) Create(name string, policy FilePolicy) (RetainedFile, error) {
	if !n.allowed(name) || !validMutableEntryPolicy(policy) || policy.Presence != MustBeAbsent {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	h, err := winOpenState(n.op.fd, name, true, policy)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return nil, ErrAlreadyExists
		}
		return nil, ErrUnsafePath
	}
	info, err := winInfo(h)
	id, idErr := winIdentity(h, info)
	if err != nil || idErr != nil || winCheck(h, info, RegularFile, policy.Access) != nil {
		_ = windows.CloseHandle(h)
		return nil, ErrUnsafePath
	}
	return &windowsRetainedFile{ns: n, name: name, fd: h, id: id, policy: policy}, nil
}

func (n *windowsRotationNamespace) Rotate(leaves [3]string, ids [3]Identity) (RetainedFile, error) {
	if leaves != n.leaves {
		return nil, ErrUnsafePath
	}
	if err := n.begin(); err != nil {
		return nil, err
	}
	defer n.end()
	for i, name := range leaves {
		state, err := n.op.inspect(name, rotationPolicy(n.policy, Required))
		if err != nil || !state.Present || state.Identity != ids[i] {
			return nil, ErrIdentityChanged
		}
	}
	// Deletion and renames name the source only through its already-validated
	// handle; destination names are fixed members below the retained root.
	oldest, err := n.openExisting(leaves[2])
	if err != nil {
		return nil, err
	}
	if err := winMarkDelete(oldest.fd); err != nil {
		_ = oldest.Close()
		return nil, ErrUnsafePath
	}
	_ = oldest.Close()
	second, err := n.openExisting(leaves[1])
	if err != nil {
		return nil, err
	}
	if err := winRenameHandle(second.fd, n.op.fd, leaves[2]); err != nil {
		_ = second.Close()
		return nil, err
	}
	_ = second.Close()
	active, err := n.openExisting(leaves[0])
	if err != nil {
		return nil, err
	}
	if err := winRenameHandle(active.fd, n.op.fd, leaves[1]); err != nil {
		_ = active.Close()
		return nil, err
	}
	_ = active.Close()
	return n.Create(leaves[0], rotationPolicy(n.policy, MustBeAbsent))
}
func (n *windowsRotationNamespace) openExisting(name string) (*windowsRetainedFile, error) {
	p := rotationPolicy(n.policy, Required)
	f, err := openRotationFile(n.op, name, p, false)
	if err != nil {
		return nil, err
	}
	f.ns = n
	return f, nil
}
func (n *windowsRotationNamespace) Close() error {
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

func (f *windowsRetainedFile) begin() (windows.Handle, error) {
	if err := f.ns.begin(); err != nil {
		return 0, err
	}
	f.mu.Lock()
	if f.closed || f.fd == 0 {
		f.mu.Unlock()
		f.ns.end()
		return 0, ErrClosed
	}
	f.active++
	h := f.fd
	f.mu.Unlock()
	return h, nil
}
func (f *windowsRetainedFile) end() {
	f.mu.Lock()
	f.active--
	closeNow := f.closed && f.active == 0 && f.fd != 0
	h := f.fd
	if closeNow {
		f.fd = 0
	}
	f.mu.Unlock()
	if closeNow {
		_ = windows.CloseHandle(h)
	}
	f.ns.end()
}
func (f *windowsRetainedFile) usable(h windows.Handle) error {
	if err := f.ns.op.recheck(); err != nil {
		return err
	}
	info, err := winInfo(h)
	id, idErr := winIdentity(h, info)
	if err != nil || idErr != nil || id != f.id || winCheck(h, info, RegularFile, f.policy.Access) != nil {
		return ErrIdentityChanged
	}
	return nil
}
func (f *windowsRetainedFile) Identity() Identity {
	h, err := f.begin()
	if err != nil {
		return Identity{}
	}
	defer f.end()
	if f.usable(h) != nil {
		return Identity{}
	}
	return f.id
}
func (f *windowsRetainedFile) RecheckIdentity() error {
	h, err := f.begin()
	if err != nil {
		return err
	}
	defer f.end()
	return f.usable(h)
}
func (f *windowsRetainedFile) Size() (int64, error) {
	h, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(h); err != nil {
		return 0, err
	}
	i, err := winInfo(h)
	if err != nil {
		return 0, ErrUnsafePath
	}
	return winFileSize(i), nil
}
func (f *windowsRetainedFile) ReadAt(b []byte, off int64) (int, error) {
	h, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(h); err != nil || off < 0 {
		return 0, firstRotationError(err)
	}
	if _, err := winSeek(h, off); err != nil {
		return 0, ErrUnsafePath
	}
	var n uint32
	err = windows.ReadFile(h, b, &n, nil)
	if err != nil {
		return int(n), ErrUnsafePath
	}
	return int(n), nil
}
func (f *windowsRetainedFile) WriteAt(b []byte, off int64) (int, error) {
	h, err := f.begin()
	if err != nil {
		return 0, err
	}
	defer f.end()
	if err := f.usable(h); err != nil || off < 0 || off > math.MaxInt64-int64(len(b)) {
		return 0, firstRotationError(err)
	}
	if f.policy.MaxBytes > 0 && off+int64(len(b)) > f.policy.MaxBytes {
		return 0, ErrTooLarge
	}
	if _, err := winSeek(h, off); err != nil {
		return 0, ErrUnsafePath
	}
	var n uint32
	err = windows.WriteFile(h, b, &n, nil)
	if err != nil {
		return int(n), ErrUnsafePath
	}
	return int(n), nil
}
func firstRotationError(err error) error {
	if err != nil {
		return err
	}
	return ErrUnsafePath
}
func (f *windowsRetainedFile) Truncate(size int64) error {
	h, err := f.begin()
	if err != nil {
		return err
	}
	defer f.end()
	if err := f.usable(h); err != nil {
		return err
	}
	if size < 0 {
		return ErrUnsafePath
	}
	if f.policy.MaxBytes > 0 && size > f.policy.MaxBytes {
		return ErrTooLarge
	}
	if _, err := winSeek(h, size); err != nil {
		return ErrUnsafePath
	}
	if err := windows.SetEndOfFile(h); err != nil {
		return ErrUnsafePath
	}
	return nil
}
func (f *windowsRetainedFile) Close() error {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return nil
	}
	f.closed = true
	closeNow := f.active == 0 && f.fd != 0
	h := f.fd
	if closeNow {
		f.fd = 0
	}
	f.mu.Unlock()
	if closeNow {
		_ = windows.CloseHandle(h)
	}
	return nil
}
func (f *windowsRetainedFile) closeDetached() {
	f.mu.Lock()
	if f.closed {
		f.mu.Unlock()
		return
	}
	f.closed = true
	closeNow := f.active == 0 && f.fd != 0
	h := f.fd
	if closeNow {
		f.fd = 0
	}
	f.mu.Unlock()
	if closeNow {
		_ = windows.CloseHandle(h)
	}
}

type winRotationRenameInformation struct {
	ReplaceIfExists uint32
	RootDirectory   windows.Handle
	FileNameLength  uint32
	FileName        [1]uint16
}

func winRenameHandle(h, parent windows.Handle, name string) error {
	u, err := windows.UTF16FromString(name)
	if err != nil {
		return ErrUnsafePath
	}
	var zero winRotationRenameInformation
	n := len(u) - 1
	buf := make([]byte, int(unsafe.Offsetof(zero.FileName))+n*2)
	info := (*winRotationRenameInformation)(unsafe.Pointer(&buf[0]))
	info.RootDirectory = parent
	info.FileNameLength = uint32(n * 2)
	copy((*[windows.MAX_LONG_PATH]uint16)(unsafe.Pointer(&info.FileName[0]))[:n:n], u[:n])
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(h, &iosb, &buf[0], uint32(len(buf)), windows.FileRenameInformation); err != nil {
		return ErrUnsafePath
	}
	return nil
}
