//go:build linux

package securefs

import (
	"context"
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
		return nil, pathSecurityFailure()
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
			return nil, pathSecurityFailure()
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
			classified := linuxPathOpenError(fd, part, err)
			_ = unix.Close(fd)
			return nil, classified
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
			return nil, pathSecurityFailure()
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

func platformOpenCreateCapableRoot(path string, policy RootPolicy) (platformRoot, error) {
	return platformOpenRoot(path, policy)
}

var linuxCreateDirectory = unix.Mkdirat

func platformCreateRoot(parent platformRoot, name string, parentPolicy, policy RootPolicy) (platformRoot, error) {
	p, ok := parent.(*linuxRoot)
	if !ok {
		return nil, ErrUnsafePath
	}
	parentStat, err := linuxStat(p.fd)
	if err != nil {
		return nil, ErrUnsupportedInspection
	}
	if err := linuxCheck(parentStat, Directory, parentPolicy.Access); err != nil {
		return nil, err
	}
	if err := linuxCreateDirectory(p.fd, name, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, ErrAlreadyExists
		}
		if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) || errors.Is(err, unix.EIO) || errors.Is(err, unix.EFBIG) {
			return nil, ErrUnsupportedInspection
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
			return nil, ErrPermissions
		}
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(p.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafePath
	}
	createdStat, createdStatErr := linuxStat(fd)
	if createdStatErr != nil {
		_ = unix.Close(fd)
		return nil, ErrUnsupportedInspection
	}
	createdIdentity := linuxIdentity(createdStat)
	if policy.Access.kind == permissionLinuxExact {
		if err = unix.Fchown(fd, int(policy.Access.uid), -1); err != nil {
			err = ErrPermissions
		} else if err = unix.Fchmod(fd, uint32(policy.Access.mode.Perm())); err != nil {
			err = ErrPermissions
		}
	}
	st, statErr := linuxStat(fd)
	if err == nil {
		err = statErr
	}
	if err == nil {
		err = linuxCheck(st, Directory, policy.Access)
	}
	if err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, createdIdentity)
		return nil, err
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, createdIdentity)
		return nil, ErrUnsupportedInspection
	}
	if err := unix.Fsync(p.fd); err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, createdIdentity)
		return nil, ErrUnsupportedInspection
	}
	parentFD, err := unix.Dup(p.fd)
	if err != nil {
		_ = unix.Close(fd)
		cleanupCreatedLinux(p.fd, name, createdIdentity)
		return nil, ErrUnsafePath
	}
	return &linuxRoot{fd: fd, parentFD: parentFD, leaf: name, id: linuxIdentity(st)}, nil
}

func platformCreateFileOnce(ctx context.Context, parent platformRoot, parentPolicy RootPolicy, name string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	p, ok := parent.(*linuxRoot)
	if !ok {
		return CommitBoundary{}, ErrUnsafePath
	}
	parentStat, err := linuxStat(p.fd)
	if err != nil {
		return CommitBoundary{}, ErrUnsupportedInspection
	}
	if err := linuxCheck(parentStat, Directory, parentPolicy.Access); err != nil {
		return CommitBoundary{}, err
	}
	createMode := uint32(0o600)
	if policy.Access.kind == permissionLinuxExact {
		createMode = uint32(policy.Access.mode.Perm())
	}
	fd, err := unix.Openat(p.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, createMode)
	if err != nil {
		if errors.Is(err, unix.EEXIST) {
			return CommitBoundary{}, ErrAlreadyExists
		}
		if errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT) || errors.Is(err, unix.EIO) || errors.Is(err, unix.EFBIG) {
			return CommitBoundary{}, ErrUnsupportedInspection
		}
		if errors.Is(err, unix.EACCES) || errors.Is(err, unix.EPERM) || errors.Is(err, unix.EROFS) {
			return CommitBoundary{}, ErrPermissions
		}
		return CommitBoundary{}, ErrUnsafePath
	}
	defer unix.Close(fd)
	createdStat, err := linuxStat(fd)
	if err != nil {
		// Without the created identity, cleanup cannot safely select a leaf.
		return CommitBoundary{NamespacePublished: true}, ErrUnsupportedInspection
	}
	createdIdentity := linuxIdentity(createdStat)
	fail := func(err error) (CommitBoundary, error) {
		cleanupCreatedLinuxFile(p.fd, name, createdIdentity)
		return CommitBoundary{NamespacePublished: true}, err
	}
	if policy.Access.kind == permissionLinuxExact {
		if err := unix.Fchown(fd, int(policy.Access.uid), -1); err != nil {
			return fail(ErrPermissions)
		}
		if err := unix.Fchmod(fd, uint32(policy.Access.mode.Perm())); err != nil {
			return fail(ErrPermissions)
		}
	}
	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		n, err := linuxCreateOnceWrite(fd, data[written:])
		if err != nil || n <= 0 {
			return fail(ErrUnsupportedInspection)
		}
		written += n
	}
	st, err := linuxCreateOnceFinalStat(fd)
	if err != nil {
		return fail(ErrUnsupportedInspection)
	}
	if err := linuxCheck(st, RegularFile, policy.Access); err != nil {
		return fail(err)
	}
	if err := linuxCreateOnceFsync(fd); err != nil {
		return fail(ErrUnsupportedInspection)
	}
	if err := linuxCreateOnceFsync(p.fd); err != nil {
		return fail(ErrUnsupportedInspection)
	}
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}

var (
	linuxCreateOnceWrite                   = unix.Write
	linuxCreateOnceFinalStat               = linuxStat
	linuxCreateOnceFsync                   = unix.Fsync
	linuxCreateOnceCleanupBeforeMove       func()
	linuxCreateOnceCleanupAfterVerify      func(parentFD int, tomb string)
	linuxCreateOnceCleanupAfterFinalVerify func(parentFD int, tomb string)
	linuxCreateOnceRename                  = unix.Renameat2
)

// cleanupCreatedLinuxFile atomically quarantines the requested member, proves
// the moved identity, and restores any mismatch. It intentionally does not
// unlink the quarantine because Linux has no handle-targeted unlink operation.
func cleanupCreatedLinuxFile(parentFD int, name string, want Identity) {
	if linuxCreateOnceCleanupBeforeMove != nil {
		linuxCreateOnceCleanupBeforeMove()
	}
	for i := 0; i < 64; i++ {
		tomb, err := linuxCleanupFileName()
		if err != nil {
			return
		}
		err = linuxCreateOnceRename(parentFD, name, parentFD, tomb, unix.RENAME_NOREPLACE)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return
		}
		if !linuxRegularFileHasIdentity(parentFD, tomb, want) {
			restoreLinuxCleanupFile(parentFD, tomb, name)
			return
		}
		if linuxCreateOnceCleanupAfterVerify != nil {
			linuxCreateOnceCleanupAfterVerify(parentFD, tomb)
		}
		if !linuxRegularFileHasIdentity(parentFD, tomb, want) {
			restoreLinuxCleanupFile(parentFD, tomb, name)
			return
		}
		if linuxCreateOnceCleanupAfterFinalVerify != nil {
			linuxCreateOnceCleanupAfterFinalVerify(parentFD, tomb)
		}
		// Linux unlinkat removes a pathname, not a retained file identity.
		// The rename already made the requested leaf recoverably absent; keep
		// the proved created identity quarantined rather than risk deleting a
		// replacement installed after the final verification.
		return
	}
}

func linuxRegularFileHasIdentity(parentFD int, name string, want Identity) bool {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return false
	}
	st, statErr := linuxStat(fd)
	_ = unix.Close(fd)
	return statErr == nil && linuxIsKind(st, RegularFile) && linuxIdentity(st) == want
}

func restoreLinuxCleanupFile(parentFD int, tomb, name string) {
	_ = linuxCreateOnceRename(parentFD, tomb, parentFD, name, unix.RENAME_NOREPLACE)
}

func linuxCleanupFileName() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".securefs-cleanup-file-" + hex.EncodeToString(random[:]), nil
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
		return FileState{}, linuxPathOpenError(r.fd, name, err)
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
		return nil, FileState{}, linuxPathOpenError(r.fd, name, err)
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
func linuxPathOpenError(parentFD int, name string, openErr error) error {
	if errors.Is(openErr, unix.ELOOP) {
		return pathSecurityFailure()
	}
	var st unix.Stat_t
	if unix.Fstatat(parentFD, name, &st, unix.AT_SYMLINK_NOFOLLOW) == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return pathSecurityFailure()
	}
	return ErrUnsafePath
}
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
func newWindowsExactPolicy(_ []WindowsGrant) (PermissionPolicy, error) {
	return PermissionPolicy{}, ErrUnsupportedInspection
}
