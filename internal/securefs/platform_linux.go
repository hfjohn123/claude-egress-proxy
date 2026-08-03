//go:build linux

package securefs

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const linuxIdentityTag = 1

type linuxRoot struct {
	fd       int
	parentFD int
	leaf     string
	id       Identity
}

func platformCleanAbsolute(path string) bool {
	return path != "" && !strings.ContainsRune(path, '\x00') && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func platformSplitOutput(path string) (string, string, error) {
	parent, name := filepath.Dir(path), filepath.Base(path)
	if !validLeaf(name) || !platformCleanAbsolute(parent) {
		return "", "", ErrUnsafePath
	}
	return parent, name, nil
}

func platformOpenRoot(path string, policy RootPolicy) (platformRoot, error) {
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	rootStat, err := linuxStat(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	if policy.ExcludedAncestor != (Identity{}) && linuxIdentity(rootStat) == policy.ExcludedAncestor {
		_ = unix.Close(fd)
		return nil, ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) == 1 && parts[0] == "" {
		st, err := linuxStat(fd)
		if err != nil {
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		if err := linuxCheck(st, Directory, policy.Access); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if policy.ExcludedAncestor != (Identity{}) && linuxIdentity(st) == policy.ExcludedAncestor {
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		parent, err := unix.Dup(fd)
		if err != nil {
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		return &linuxRoot{fd: fd, parentFD: parent, leaf: ".", id: linuxIdentity(st)}, nil
	}
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		st, err := linuxStat(next)
		if err != nil || !linuxIsKind(st, Directory) {
			_ = unix.Close(next)
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		id := linuxIdentity(st)
		if policy.ExcludedAncestor != (Identity{}) && id == policy.ExcludedAncestor {
			_ = unix.Close(next)
			_ = unix.Close(fd)
			return nil, ErrUnsafePath
		}
		if i == len(parts)-1 {
			if err := linuxCheck(st, Directory, policy.Access); err != nil {
				_ = unix.Close(next)
				_ = unix.Close(fd)
				return nil, err
			}
			return &linuxRoot{fd: next, parentFD: fd, leaf: part, id: id}, nil
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil, ErrUnsafePath
}

func platformOpenMutableRoot(path string, policy RootPolicy) (platformRoot, error) {
	return platformOpenRoot(path, policy)
}

func platformCreateRoot(parent platformRoot, name string, policy RootPolicy) (platformRoot, error) {
	p, ok := parent.(*linuxRoot)
	if !ok {
		return nil, ErrUnsafePath
	}
	mode := uint32(0o700)
	if policy.Access.kind == permissionLinuxExact {
		mode = uint32(policy.Access.mode.Perm())
	}
	if err := unix.Mkdirat(p.fd, name, mode); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrAlreadyExists
		}
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(p.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	st, err := linuxStat(fd)
	if err == nil {
		err = linuxCheck(st, Directory, policy.Access)
	}
	if err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, linuxIdentity(st))
		return nil, err
	}
	parentFD, err := unix.Dup(p.fd)
	if err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, linuxIdentity(st))
		return nil, ErrUnsafePath
	}
	return &linuxRoot{fd: fd, parentFD: parentFD, leaf: name, id: linuxIdentity(st)}, nil
}

// Narrow deterministic seams cover the two rename boundaries. Production
// leaves them at their syscall implementations/nil hooks.
var (
	linuxCleanupBeforeExchange  func()
	linuxCleanupAfterTombVerify func(parentFD int, tomb string)
	linuxCleanupMakeTombstone   = linuxCleanupTombstone
	linuxRenameExchange         = unix.Renameat2
)

func cleanupCreatedLinux(parentFD int, name string, want Identity) {
	tomb, err := linuxCleanupMakeTombstone(parentFD)
	if err != nil {
		return
	}
	if linuxCleanupBeforeExchange != nil {
		linuxCleanupBeforeExchange()
	}
	if err := linuxRenameExchange(parentFD, name, parentFD, tomb, unix.RENAME_EXCHANGE); err != nil {
		// The exchange did not establish which pathname holds which identity;
		// leave both members rather than delete a possibly swapped entry.
		return
	}
	fd, err := unix.Openat(parentFD, tomb, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return
	}
	st, statErr := linuxStat(fd)
	_ = unix.Close(fd)
	if statErr != nil || linuxIdentity(st) != want {
		// Do not delete the entry now occupying tomb: it is an unverified
		// replacement. Exchange it back and tolerate a leftover tombstone.
		_ = linuxRenameExchange(parentFD, name, parentFD, tomb, unix.RENAME_EXCHANGE)
		return
	}
	if linuxCleanupAfterTombVerify != nil {
		linuxCleanupAfterTombVerify(parentFD, tomb)
	}
	// Linux has no handle-targeted directory unlink. The exchange has moved the
	// verified object away from the requested member; return failure with that
	// private remnant rather than issue any racy pathname deletion.
}

func linuxCleanupTombstone(parentFD int) (string, error) {
	var random [8]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	name := ".securefs-cleanup-" + hex.EncodeToString(random[:])
	for i := 0; i < 64; i++ {
		candidate := name + string(rune('a'+i%26))
		err := unix.Mkdirat(parentFD, candidate, 0o700)
		if err == nil {
			return candidate, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", err
		}
	}
	return "", unix.EEXIST
}

func (r *linuxRoot) identity() Identity { return r.id }

func (r *linuxRoot) recheck() error {
	fd, err := unix.Openat(r.parentFD, r.leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrIdentityChanged
	}
	defer unix.Close(fd)
	st, err := linuxStat(fd)
	if err != nil || linuxIdentity(st) != r.id {
		return ErrIdentityChanged
	}
	return nil
}

func (r *linuxRoot) inspect(name string, policy FilePolicy) (FileState, error) {
	if err := r.recheck(); err != nil {
		return FileState{}, err
	}
	fd, err := unix.Openat(r.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			switch policy.Presence {
			case Optional, MustBeAbsent:
				return FileState{Kind: policy.Kind}, nil
			case Required:
				return FileState{}, ErrNotFound
			}
		}
		return FileState{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	st, err := linuxStat(fd)
	if err != nil {
		return FileState{}, ErrUnsafePath
	}
	if policy.Presence == MustBeAbsent {
		return FileState{}, ErrAlreadyExists
	}
	if err := linuxCheck(st, policy.Kind, policy.Access); err != nil {
		return FileState{}, err
	}
	return linuxState(st, policy.Kind), nil
}

func (r *linuxRoot) readFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if err := r.recheck(); err != nil {
		return nil, FileState{}, err
	}
	fd, err := unix.Openat(r.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, FileState{}, ErrNotFound
		}
		return nil, FileState{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	st, err := linuxStat(fd)
	if err != nil {
		return nil, FileState{}, ErrUnsafePath
	}
	if err := linuxCheck(st, RegularFile, policy.Access); err != nil {
		return nil, FileState{}, err
	}
	state := linuxState(st, RegularFile)
	if policy.MaxBytes > 0 && state.Size > policy.MaxBytes {
		return nil, FileState{}, ErrTooLarge
	}
	buf := make([]byte, 0)
	tmp := make([]byte, 32*1024)
	for {
		chunk := boundedReadChunk(policy.MaxBytes, int64(len(buf)), len(tmp))
		if chunk == 0 {
			return nil, FileState{}, ErrTooLarge
		}
		n, readErr := unix.Read(fd, tmp[:chunk])
		if n > 0 {
			if policy.MaxBytes > 0 && int64(len(buf)+n) > policy.MaxBytes {
				return nil, FileState{}, ErrTooLarge
			}
			buf = append(buf, tmp[:n]...)
		}
		if readErr != nil {
			return nil, FileState{}, ErrUnsafePath
		}
		if n == 0 {
			break
		}
	}
	return buf, state, nil
}

func (r *linuxRoot) close() error { _ = unix.Close(r.fd); _ = unix.Close(r.parentFD); return nil }

func linuxStat(fd int) (unix.Stat_t, error) { var st unix.Stat_t; return st, unix.Fstat(fd, &st) }
func linuxIdentity(st unix.Stat_t) Identity {
	var id Identity
	id.platform = linuxIdentityTag
	binary.LittleEndian.PutUint64(id.data[:8], uint64(st.Dev))
	binary.LittleEndian.PutUint64(id.data[8:16], st.Ino)
	return id
}
func linuxIsKind(st unix.Stat_t, kind EntryKind) bool {
	if kind == Directory {
		return st.Mode&unix.S_IFMT == unix.S_IFDIR
	}
	return st.Mode&unix.S_IFMT == unix.S_IFREG
}
func linuxCheck(st unix.Stat_t, kind EntryKind, policy PermissionPolicy) error {
	if !linuxIsKind(st, kind) {
		return ErrUnsafePath
	}
	if policy.kind == permissionIdentityOnly {
		return nil
	}
	if policy.kind != permissionLinuxExact {
		return ErrUnsupportedInspection
	}
	var wantSpecial uint32
	if policy.mode&fs.ModeSetuid != 0 {
		wantSpecial |= unix.S_ISUID
	}
	if policy.mode&fs.ModeSetgid != 0 {
		wantSpecial |= unix.S_ISGID
	}
	if policy.mode&fs.ModeSticky != 0 {
		wantSpecial |= unix.S_ISVTX
	}
	if st.Uid != policy.uid || fs.FileMode(st.Mode).Perm() != policy.mode.Perm() || st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != wantSpecial {
		return ErrPermissions
	}
	return nil
}
func linuxState(st unix.Stat_t, kind EntryKind) FileState {
	return FileState{Present: true, Identity: linuxIdentity(st), Kind: kind, Size: st.Size, ModTime: time.Unix(st.Mtim.Sec, st.Mtim.Nsec)}
}
func newWindowsPolicy(_ []string, _ uint32) (PermissionPolicy, error) {
	return PermissionPolicy{}, ErrUnsupportedInspection
}
