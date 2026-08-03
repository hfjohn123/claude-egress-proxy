//go:build windows

package securefs

import (
	"context"
	"errors"
	"math"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"golang.org/x/sys/windows"
)

type windowsLockedFile struct {
	root       *windowsRoot
	rootPolicy RootPolicy
	fd         windows.Handle
	id         Identity
	policy     FilePolicy
	gate       *lockedGate
}

func platformWithExclusiveLock(ctx context.Context, op platformRoot, rootPolicy RootPolicy, name string, policy FilePolicy, fn func(LockedFile) error) error {
	r, ok := op.(*windowsRoot)
	if !ok {
		return ErrUnsafePath
	}
	if err := r.recheck(); err != nil {
		return err
	}
	h, created, err := winOpenLock(r, name, policy)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	if err != nil || winCheck(h, info, RegularFile, policy.Access) != nil {
		return ErrUnsafePath
	}
	if created && windows.FlushFileBuffers(h) != nil {
		return ErrUnsafePath
	}
	if err := winLockContext(ctx, h); err != nil {
		return err
	}
	defer windows.UnlockFileEx(h, 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
	if err := r.recheck(); err != nil {
		return err
	}
	info, err = winInfo(h)
	id, idErr := winIdentity(h, info)
	if err != nil || idErr != nil {
		return ErrIdentityChanged
	}
	l := &windowsLockedFile{root: r, rootPolicy: rootPolicy, fd: h, id: id, policy: policy, gate: newLockedGate()}
	defer l.gate.close()
	return fn(l)
}

func winOpenLock(r *windowsRoot, name string, policy FilePolicy) (windows.Handle, bool, error) {
	h, err := winOpenState(r.fd, name, false, policy)
	if err == nil {
		return h, false, nil
	}
	if !winNotFound(err) {
		return 0, false, ErrUnsafePath
	}
	h, err = winOpenState(r.fd, name, true, policy)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return winOpenLock(r, name, policy)
		}
		return 0, false, ErrUnsafePath
	}
	return h, true, nil
}
func winOpenState(parent windows.Handle, name string, create bool, policy FilePolicy) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if create && policy.Access.kind == permissionWindowsRestricted {
		sd, err := winRestrictedSecurityDescriptor(policy.Access)
		if err != nil {
			return 0, err
		}
		oa.SecurityDescriptor = sd
	}
	var h windows.Handle
	var io windows.IO_STATUS_BLOCK
	disp := uint32(windows.FILE_OPEN)
	if create {
		disp = windows.FILE_CREATE
	}
	err = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.FILE_READ_ATTRIBUTES|windows.DELETE, &oa, &io, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disp, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return h, err
}
func winLockContext(ctx context.Context, h windows.Handle) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, math.MaxUint32, math.MaxUint32, &windows.Overlapped{})
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return ErrUnsafePath
		}
		if err := waitForLockRetry(ctx, 5*time.Millisecond); err != nil {
			return err
		}
	}
}
func (l *windowsLockedFile) usable() error {
	if err := l.root.recheck(); err != nil {
		return err
	}
	rootInfo, err := winInfo(l.root.fd)
	if err != nil || winCheck(l.root.fd, rootInfo, Directory, l.rootPolicy.Access) != nil {
		return ErrPermissions
	}
	info, err := winInfo(l.fd)
	if err != nil {
		return ErrUnsafePath
	}
	id, e := winIdentity(l.fd, info)
	if e != nil || id != l.id {
		return ErrIdentityChanged
	}
	return winCheck(l.fd, info, RegularFile, l.policy.Access)
}
func (l *windowsLockedFile) Identity() Identity {
	if l.gate.begin() != nil {
		return Identity{}
	}
	defer l.gate.end()
	if l.usable() != nil {
		return Identity{}
	}
	return l.id
}
func (l *windowsLockedFile) RecheckIdentity() error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	return l.usable()
}
func (l *windowsLockedFile) Size() (int64, error) {
	if err := l.gate.begin(); err != nil {
		return 0, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return 0, err
	}
	i, e := winInfo(l.fd)
	if e != nil {
		return 0, ErrUnsafePath
	}
	return int64(uint64(i.FileSizeHigh)<<32 | uint64(i.FileSizeLow)), nil
}
func (l *windowsLockedFile) ReadAt(b []byte, off int64) (int, error) {
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
	if _, err := winSeek(l.fd, off); err != nil {
		return 0, ErrUnsafePath
	}
	var n uint32
	err := windows.ReadFile(l.fd, b, &n, nil)
	if err != nil {
		return int(n), ErrUnsafePath
	}
	return int(n), nil
}
func (l *windowsLockedFile) WriteAt(b []byte, off int64) (int, error) {
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
	if l.policy.MaxBytes > 0 && off+int64(len(b)) > l.policy.MaxBytes {
		return 0, ErrTooLarge
	}
	if _, err := winSeek(l.fd, off); err != nil {
		return 0, ErrUnsafePath
	}
	var n uint32
	err := windows.WriteFile(l.fd, b, &n, nil)
	if err != nil {
		return int(n), ErrUnsafePath
	}
	return int(n), nil
}
func winSeek(h windows.Handle, off int64) (int64, error) {
	hi := int32(off >> 32)
	lo, e := windows.SetFilePointer(h, int32(off), &hi, windows.FILE_BEGIN)
	if e != nil {
		return 0, e
	}
	return int64(uint64(uint32(hi))<<32 | uint64(lo)), nil
}
func (l *windowsLockedFile) Truncate(n int64) error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return err
	}
	if n < 0 {
		return ErrUnsafePath
	}
	if l.policy.MaxBytes > 0 && n > l.policy.MaxBytes {
		return ErrTooLarge
	}
	if _, err := winSeek(l.fd, n); err != nil {
		return ErrUnsafePath
	}
	if err := windows.SetEndOfFile(l.fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}
func (l *windowsLockedFile) Sync() error {
	if err := l.gate.begin(); err != nil {
		return err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return err
	}
	if err := windows.FlushFileBuffers(l.fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}
func (l *windowsLockedFile) Inspect(n string, p FilePolicy) (FileState, error) {
	if err := l.gate.begin(); err != nil {
		return FileState{}, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return FileState{}, err
	}
	if !validLeaf(n) || !validFilePolicy(p) {
		return FileState{}, ErrUnsafePath
	}
	return l.root.inspect(n, p)
}
func (l *windowsLockedFile) ReadFile(n string, p FilePolicy) ([]byte, FileState, error) {
	if err := l.gate.begin(); err != nil {
		return nil, FileState{}, err
	}
	defer l.gate.end()
	if err := l.usable(); err != nil {
		return nil, FileState{}, err
	}
	if !validLeaf(n) || !validFilePolicy(p) || p.Kind != RegularFile || p.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	return l.root.readFile(n, p)
}
func (l *windowsLockedFile) CleanupReservedTemp(ctx context.Context, target, temp string, p FilePolicy) error {
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
	if !validReservedNames(target, temp) || !validFilePolicy(p) || p.Kind != RegularFile {
		return ErrUnsafePath
	}
	s, e := l.root.inspect(temp, FilePolicy{Presence: Optional, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes})
	if e != nil || !s.Present {
		return e
	}
	h, e := winOpenState(l.root.fd, temp, false, p)
	if e != nil {
		return ErrIdentityChanged
	}
	defer windows.CloseHandle(h)
	i, e := winInfo(h)
	id, idErr := winIdentity(h, i)
	if e != nil || idErr != nil || id != s.Identity || winCheck(h, i, RegularFile, p.Access) != nil {
		return ErrIdentityChanged
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	winDeleteCreated(h)
	return nil
}

func (l *windowsLockedFile) Publish(ctx context.Context, target, temp string, data []byte, p FilePolicy, mode PublishMode, f Faults) (CommitBoundary, error) {
	if err := l.gate.begin(); err != nil {
		return CommitBoundary{}, err
	}
	defer l.gate.end()
	var b CommitBoundary
	if err := l.usable(); err != nil {
		return b, err
	}
	if err := ctx.Err(); err != nil {
		return b, err
	}
	if !validReservedNames(target, temp) || !validFilePolicy(p) || p.Kind != RegularFile || (p.MaxBytes > 0 && int64(len(data)) > p.MaxBytes) || (mode != AbsentTarget && mode != PresentTarget) {
		return b, ErrUnsafePath
	}
	presence := MustBeAbsent
	if mode == PresentTarget {
		presence = Required
	}
	if _, err := l.root.inspect(target, FilePolicy{Presence: presence, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes}); err != nil {
		return b, err
	}
	if err := l.CleanupReservedTemp(ctx, target, temp, p); err != nil {
		return b, err
	}
	h, err := winOpenState(l.root.fd, temp, true, p)
	if err != nil {
		return b, ErrUnsafePath
	}
	defer func() {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}()
	if f == nil {
		f = NoFaults{}
	}
	if err := f.hit(BeforeTempWrite); err != nil {
		return b, err
	}
	if err := ctx.Err(); err != nil {
		return b, err
	}
	var wrote uint32
	if err := windows.WriteFile(h, data, &wrote, nil); err != nil || int(wrote) != len(data) {
		return b, ErrUnsafePath
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return b, ErrUnsafePath
	}
	if err := f.hit(AfterTempFlush); err != nil {
		return b, err
	}
	if err := ctx.Err(); err != nil {
		return b, err
	}
	// ReplaceFileW can reject an open replacement handle even when it was
	// created with delete sharing, so release our validated temp only after its
	// bytes and metadata have been flushed. The exact reserved pathname remains
	// available for the allowed pre-publication remnant on later failure.
	_ = windows.CloseHandle(h)
	h = 0
	if mode == PresentTarget {
		err = l.winReplace(ctx, temp, target)
	} else {
		err = l.winMove(temp, target)
	}
	if err != nil {
		return b, err
	}
	b.NamespacePublished = true
	if mode == AbsentTarget {
		// MOVEFILE_WRITE_THROUGH is the complete absent-target durability
		// sequence; there is no later target flush boundary on this branch.
		b.TargetDurable = true
	}
	if err := f.hit(AfterPublication); err != nil {
		return b, err
	}
	if err := ctx.Err(); err != nil {
		return b, err
	}
	if mode == AbsentTarget {
		if err := f.hit(AfterTargetDurability); err != nil {
			return b, err
		}
		return b, nil
	}
	th, err := winOpenState(l.root.fd, target, false, p)
	if err != nil {
		return b, ErrUnsafePath
	}
	err = windows.FlushFileBuffers(th)
	windows.CloseHandle(th)
	if err != nil {
		return b, ErrUnsafePath
	}
	b.TargetDurable = true
	if err := f.hit(AfterTargetDurability); err != nil {
		return b, err
	}
	return b, nil
}
func (l *windowsLockedFile) winPath(name string) (string, error) {
	if l.root.path == "" {
		return "", ErrUnsafePath
	}
	return filepath.Join(l.root.path, name), nil
}
func (l *windowsLockedFile) winMove(temp, target string) error {
	a, e := l.winPath(temp)
	if e != nil {
		return e
	}
	b, e := l.winPath(target)
	if e != nil {
		return e
	}
	pa, _ := windows.UTF16PtrFromString(a)
	pb, _ := windows.UTF16PtrFromString(b)
	if e = windows.MoveFileEx(pa, pb, windows.MOVEFILE_WRITE_THROUGH); e != nil {
		if errors.Is(e, windows.ERROR_FILE_EXISTS) {
			return ErrAlreadyExists
		}
		return ErrUnsafePath
	}
	return nil
}

func (l *windowsLockedFile) winReplace(ctx context.Context, temp, target string) error {
	a, e := l.winPath(temp)
	if e != nil {
		return e
	}
	b, e := l.winPath(target)
	if e != nil {
		return e
	}
	pa, _ := windows.UTF16PtrFromString(a)
	pb, _ := windows.UTF16PtrFromString(b)
	deadline := timebase.Real{}.NewTimer(200 * time.Millisecond)
	defer deadline.Stop()
	for attempt, delay := 0, 10*time.Millisecond; attempt < 5; attempt, delay = attempt+1, delay*2 {
		replaceFile := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")
		r, _, callErr := replaceFile.Call(uintptr(unsafe.Pointer(pb)), uintptr(unsafe.Pointer(pa)), 0, 0, 0, 0)
		if r != 0 {
			return nil
		}
		if callErr != windows.ERROR_SHARING_VIOLATION {
			return ErrUnsafePath
		}
		if attempt == 4 {
			return ErrUnsafePath
		}
		retry := timebase.Real{}.NewTimer(delay)
		select {
		case <-ctx.Done():
			retry.Stop()
			return ctx.Err()
		case <-deadline.C():
			retry.Stop()
			return context.DeadlineExceeded
		case <-retry.C():
		}
		retry.Stop()
	}
	return ErrUnsafePath
}
