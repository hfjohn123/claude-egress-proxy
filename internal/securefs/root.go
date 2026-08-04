// Package securefs validates state paths through retained operating-system
// handles. It deliberately never includes filesystem details in errors.
package securefs

import (
	"context"
	"errors"
	"io/fs"
	"sync"
	"time"
)

var (
	ErrUnsafePath            = errors.New("unsafe path")
	ErrIdentityChanged       = errors.New("identity changed")
	ErrPermissions           = errors.New("permissions rejected")
	ErrUnsupportedInspection = errors.New("unsupported inspection")
	ErrNotFound              = errors.New("not found")
	ErrAlreadyExists         = errors.New("already exists")
	ErrTooLarge              = errors.New("file too large")
	ErrClosed                = errors.New("root closed")
)

type pathSecurityError struct{}

func (pathSecurityError) Error() string { return ErrUnsafePath.Error() }
func (pathSecurityError) Unwrap() error { return ErrUnsafePath }
func pathSecurityFailure() error        { return pathSecurityError{} }
func IsPathSecurityFailure(err error) bool {
	var target pathSecurityError
	return errors.As(err, &target)
}

type Presence uint8

const (
	Required Presence = iota
	Optional
	MustBeAbsent
)

type EntryKind uint8

const (
	RegularFile EntryKind = iota
	Directory
)

// Identity is an opaque, comparable platform object identity. Its fields are
// private so paths and user-facing labels cannot become identities.
type Identity struct {
	platform uint8
	data     [24]byte
}

type RootPolicy struct {
	Access           PermissionPolicy
	ExcludedAncestor Identity
}

type FilePolicy struct {
	Presence Presence
	Kind     EntryKind
	Access   PermissionPolicy
	MaxBytes int64
}

type FileState struct {
	Present  bool
	Identity Identity
	Kind     EntryKind
	Size     int64
	ModTime  time.Time
}

type ReadRoot interface {
	Identity() Identity
	RecheckIdentity() error
	Inspect(name string, policy FilePolicy) (FileState, error)
	ReadFile(name string, policy FilePolicy) ([]byte, FileState, error)
}

type Root interface {
	ReadRoot
	Close() error
}

// RetainedFile is an identity-pinned regular file held by a rotation
// namespace.  It deliberately exposes only offset I/O so callers cannot
// accidentally retain a pathname-dependent file object.
type RetainedFile interface {
	Identity() Identity
	RecheckIdentity() error
	Size() (int64, error)
	ReadAt([]byte, int64) (int, error)
	WriteAt([]byte, int64) (int, error)
	Truncate(int64) error
	Close() error
}

// RotationNamespace holds the per-log OS lock and restricts mutations to the
// three approved generation leaves.
type RotationNamespace interface {
	RecheckIdentity() error
	RepairTombstone() error
	Inspect(string, FilePolicy) (FileState, error)
	ReadFile(string, FilePolicy) ([]byte, FileState, error)
	Open(string, FilePolicy) (RetainedFile, error)
	Create(string, FilePolicy) (RetainedFile, error)
	Rotate([3]string, [3]Identity) (RetainedFile, error)
	Close() error
}

type CreateCapableRoot interface {
	Root
	createCapability()
}

// MutableRoot retains a validated directory with the rights necessary to
// create, replace, and remove its explicitly named state files. Mutations are
// intentionally available only through a held OS lock callback.
type MutableRoot interface {
	Root
	WithExclusiveLock(context.Context, string, FilePolicy, func(LockedFile) error) error
	AcquireRotationNamespace(context.Context, string, [3]string, FilePolicy) (RotationNamespace, error)
}

type permissionKind uint8

const (
	permissionInvalid permissionKind = iota
	permissionIdentityOnly
	permissionLinuxExact
	permissionWindowsRestricted
)

type WindowsGrant struct {
	SID    string
	Access uint32
}

// PermissionPolicy has no open/zero value. It can only be obtained through a
// constructor so callers cannot accidentally accept ambient filesystem ACLs.
type PermissionPolicy struct {
	kind   permissionKind
	uid    uint32
	mode   fs.FileMode
	grants []WindowsGrant
}

func IdentityOnlyPermissions() PermissionPolicy {
	return PermissionPolicy{kind: permissionIdentityOnly}
}

func LinuxExactPermissions(uid uint32, mode fs.FileMode) PermissionPolicy {
	return PermissionPolicy{kind: permissionLinuxExact, uid: uid, mode: mode}
}

// WindowsRestrictedPermissions is available on every target so shared config
// code has a stable API. Non-Windows platforms return ErrUnsupportedInspection.
func WindowsRestrictedPermissions(allowedSIDs []string, requiredAccess uint32) (PermissionPolicy, error) {
	return newWindowsPolicy(allowedSIDs, requiredAccess)
}

func WindowsExactPermissions(grants []WindowsGrant) (PermissionPolicy, error) {
	return newWindowsExactPolicy(grants)
}

func PermissionsEqual(a, b PermissionPolicy) bool {
	if a.kind != b.kind || a.uid != b.uid || a.mode != b.mode || len(a.grants) != len(b.grants) {
		return false
	}
	for i := range a.grants {
		if a.grants[i] != b.grants[i] {
			return false
		}
	}
	return true
}

type platformRoot interface {
	identity() Identity
	recheck() error
	inspect(name string, policy FilePolicy) (FileState, error)
	readFile(name string, policy FilePolicy) ([]byte, FileState, error)
	close() error
}

type root struct {
	mu     sync.RWMutex
	closed bool
	op     platformRoot
}

type createRoot struct {
	*root
	policy RootPolicy
}

func (*createRoot) createCapability() {}

// mutableRoot uses operation leases instead of a root-wide RWMutex. Close
// first closes admission, then waits for the complete lock callback (including
// publication) before releasing the retained directory handles.
type mutableRoot struct {
	mu      sync.Mutex
	cond    *sync.Cond
	closing bool
	closed  bool
	active  int
	op      platformRoot
	policy  RootPolicy
}

func OpenRoot(path string, policy RootPolicy) (Root, error) {
	if !validRootPolicy(policy) || !platformCleanAbsolute(path) {
		return nil, ErrUnsafePath
	}
	op, err := platformOpenRoot(path, policy)
	if err != nil {
		return nil, err
	}
	return &root{op: op}, nil
}

func OpenMutableRoot(path string, policy RootPolicy) (MutableRoot, error) {
	if !validMutableRootPolicy(policy) || !platformCleanAbsolute(path) {
		return nil, ErrUnsafePath
	}
	op, err := platformOpenMutableRoot(path, policy)
	if err != nil {
		return nil, err
	}
	r := &mutableRoot{op: op, policy: policy}
	r.cond = sync.NewCond(&r.mu)
	return r, nil
}

func OpenCreateCapableRoot(path string, policy RootPolicy) (CreateCapableRoot, error) {
	if !validRootPolicy(policy) || !platformCleanAbsolute(path) {
		return nil, ErrUnsafePath
	}
	op, err := platformOpenCreateCapableRoot(path, policy)
	if err != nil {
		return nil, err
	}
	return &createRoot{root: &root{op: op}, policy: policy}, nil
}

func CreateRoot(parent CreateCapableRoot, name string, policy RootPolicy) (CreateCapableRoot, error) {
	cp, ok := parent.(*createRoot)
	if !ok || !validRootPolicy(policy) || !validLeaf(name) {
		return nil, ErrUnsafePath
	}
	p := cp.root
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrClosed
	}
	if err := p.op.recheck(); err != nil {
		return nil, err
	}
	op, err := platformCreateRoot(p.op, name, cp.policy, policy)
	if err != nil {
		return nil, err
	}
	return &createRoot{root: &root{op: op}, policy: policy}, nil
}

func CreateFileOnce(ctx context.Context, parent CreateCapableRoot, name string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	cp, ok := parent.(*createRoot)
	if !ok || ctx == nil || !validLeaf(name) || !validFilePolicy(policy) || policy.Presence != MustBeAbsent || policy.Kind != RegularFile {
		return CommitBoundary{}, ErrUnsafePath
	}
	if int64(len(data)) > policy.MaxBytes {
		return CommitBoundary{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return CommitBoundary{}, err
	}
	r := cp.root
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return CommitBoundary{}, ErrClosed
	}
	if err := r.op.recheck(); err != nil {
		return CommitBoundary{}, err
	}
	return platformCreateFileOnce(ctx, r.op, cp.policy, name, data, policy)
}

func ValidateOutput(path string, checkout Identity, parentPolicy RootPolicy, outputPolicy FilePolicy) (parent Root, name string, state FileState, err error) {
	if !validFilePolicy(outputPolicy) || !platformCleanAbsolute(path) {
		return nil, "", FileState{}, ErrUnsafePath
	}
	parentPath, name, err := platformSplitOutput(path)
	if err != nil {
		return nil, "", FileState{}, err
	}
	parentPolicy.ExcludedAncestor = checkout
	parent, err = OpenRoot(parentPath, parentPolicy)
	if err != nil {
		return nil, "", FileState{}, err
	}
	state, err = parent.Inspect(name, outputPolicy)
	if err != nil {
		_ = parent.Close()
		return nil, "", FileState{}, err
	}
	return parent, name, state, nil
}

func ValidateMutableOutput(path string, checkout Identity, parentPolicy RootPolicy, outputPolicy FilePolicy) (parent MutableRoot, name string, state FileState, err error) {
	if !validFilePolicy(outputPolicy) || !platformCleanAbsolute(path) {
		return nil, "", FileState{}, ErrUnsafePath
	}
	parentPath, name, err := platformSplitOutput(path)
	if err != nil {
		return nil, "", FileState{}, err
	}
	parentPolicy.ExcludedAncestor = checkout
	parent, err = OpenMutableRoot(parentPath, parentPolicy)
	if err != nil {
		return nil, "", FileState{}, err
	}
	state, err = parent.Inspect(name, outputPolicy)
	if err != nil {
		_ = parent.Close()
		return nil, "", FileState{}, err
	}
	return parent, name, state, nil
}

func (r *root) Identity() Identity {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.op.identity()
}

func (r *root) RecheckIdentity() error {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return ErrClosed
	}
	return r.op.recheck()
}

func (r *root) Inspect(name string, policy FilePolicy) (FileState, error) {
	if !validLeaf(name) || !validFilePolicy(policy) {
		return FileState{}, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return FileState{}, ErrClosed
	}
	return r.op.inspect(name, policy)
}

func (r *root) ReadFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if !validLeaf(name) || !validFilePolicy(policy) || policy.Kind != RegularFile || policy.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, FileState{}, ErrClosed
	}
	return r.op.readFile(name, policy)
}

func (r *root) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.op.close()
}

func (r *mutableRoot) lease() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing || r.closed {
		return ErrClosed
	}
	r.active++
	return nil
}
func (r *mutableRoot) release() {
	r.mu.Lock()
	r.active--
	if r.active == 0 {
		r.cond.Broadcast()
	}
	r.mu.Unlock()
}
func (r *mutableRoot) Identity() Identity {
	if r.lease() != nil {
		return Identity{}
	}
	defer r.release()
	return r.op.identity()
}
func (r *mutableRoot) RecheckIdentity() error {
	if err := r.lease(); err != nil {
		return err
	}
	defer r.release()
	return r.op.recheck()
}
func (r *mutableRoot) Inspect(name string, policy FilePolicy) (FileState, error) {
	if !validLeaf(name) || !validFilePolicy(policy) {
		return FileState{}, ErrUnsafePath
	}
	if err := r.lease(); err != nil {
		return FileState{}, err
	}
	defer r.release()
	return r.op.inspect(name, policy)
}
func (r *mutableRoot) ReadFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if !validLeaf(name) || !validFilePolicy(policy) || policy.Kind != RegularFile || policy.Presence != Required {
		return nil, FileState{}, ErrUnsafePath
	}
	if err := r.lease(); err != nil {
		return nil, FileState{}, err
	}
	defer r.release()
	return r.op.readFile(name, policy)
}
func (r *mutableRoot) WithExclusiveLock(ctx context.Context, name string, policy FilePolicy, fn func(LockedFile) error) error {
	if ctx == nil || fn == nil || !validLockPolicy(policy) || !validLeaf(name) {
		return ErrUnsafePath
	}
	if err := r.lease(); err != nil {
		return err
	}
	defer r.release()
	if err := r.op.recheck(); err != nil {
		return err
	}
	return platformWithExclusiveLock(ctx, r.op, r.policy, name, policy, fn)
}
func (r *mutableRoot) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closing = true
	for r.active != 0 {
		r.cond.Wait()
	}
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	err := r.op.close()
	r.mu.Unlock()
	return err
}
