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

type Root interface {
	Identity() Identity
	RecheckIdentity() error
	Inspect(name string, policy FilePolicy) (FileState, error)
	ReadFile(name string, policy FilePolicy) ([]byte, FileState, error)
	Close() error
}

// MutableRoot retains a validated directory with the rights necessary to
// create, replace, and remove its explicitly named state files. Mutations are
// intentionally available only through a held OS lock callback.
type MutableRoot interface {
	Root
	WithExclusiveLock(context.Context, string, FilePolicy, func(LockedFile) error) error
}

type permissionKind uint8

const (
	permissionInvalid permissionKind = iota
	permissionIdentityOnly
	permissionLinuxExact
	permissionWindowsRestricted
)

// PermissionPolicy has no open/zero value. It can only be obtained through a
// constructor so callers cannot accidentally accept ambient filesystem ACLs.
type PermissionPolicy struct {
	kind permissionKind
	uid  uint32
	mode fs.FileMode
	sids []string
	mask uint32
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

func CreateRoot(parent Root, name string, policy RootPolicy) (Root, error) {
	p, ok := parent.(*root)
	if !ok || !validRootPolicy(policy) || !validLeaf(name) {
		return nil, ErrUnsafePath
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.closed {
		return nil, ErrClosed
	}
	if err := p.op.recheck(); err != nil {
		return nil, err
	}
	op, err := platformCreateRoot(p.op, name, policy)
	if err != nil {
		return nil, err
	}
	return &root{op: op}, nil
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
