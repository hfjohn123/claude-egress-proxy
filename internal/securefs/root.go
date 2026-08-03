// Package securefs validates state paths through retained operating-system
// handles. It deliberately never includes filesystem details in errors.
package securefs

import (
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
