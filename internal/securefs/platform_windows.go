//go:build windows

package securefs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const windowsIdentityTag = 2

type windowsRoot struct {
	fd                 windows.Handle
	parent             windows.Handle
	leaf               string
	path               string
	volumeRoot         string
	id                 Identity
	pins               []windows.Handle
	inspectInfoForTest func(string, windows.ByHandleFileInformation) windows.ByHandleFileInformation
}

type windowsFileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

func platformCleanAbsolute(path string) bool {
	if path == "" || strings.ContainsRune(path, '\x00') || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return false
	}
	if strings.HasPrefix(path, `\\`) || strings.HasPrefix(path, `//`) || strings.HasPrefix(path, `\\?\`) || strings.HasPrefix(path, `\\.\`) {
		return false
	}
	volume := filepath.VolumeName(path)
	return len(volume) == 2 && volume[1] == ':' && !strings.Contains(path[len(volume):], ":")
}

func platformSplitOutput(path string) (string, string, error) {
	parent, name := filepath.Dir(path), filepath.Base(path)
	if !validLeaf(name) || !platformCleanAbsolute(parent) {
		return "", "", ErrUnsafePath
	}
	return parent, name, nil
}

func newWindowsPolicy(allowedSIDs []string, requiredAccess uint32) (PermissionPolicy, error) {
	if len(allowedSIDs) == 0 || requiredAccess == 0 {
		return PermissionPolicy{}, ErrPermissions
	}
	grants := make([]WindowsGrant, len(allowedSIDs))
	for i, sid := range allowedSIDs {
		grants[i] = WindowsGrant{SID: sid, Access: requiredAccess}
	}
	return newWindowsExactPolicy(grants)
}

func newWindowsExactPolicy(grants []WindowsGrant) (PermissionPolicy, error) {
	if len(grants) == 0 {
		return PermissionPolicy{}, ErrPermissions
	}
	seen := make(map[string]struct{}, len(grants))
	copyGrants := make([]WindowsGrant, 0, len(grants))
	for _, grant := range grants {
		text := grant.SID
		if text == "" || grant.Access == 0 {
			return PermissionPolicy{}, ErrPermissions
		}
		ptr, err := windows.UTF16PtrFromString(text)
		if err != nil {
			return PermissionPolicy{}, ErrPermissions
		}
		var sid *windows.SID
		if err := windows.ConvertStringSidToSid(ptr, &sid); err != nil || sid == nil || !sid.IsValid() || sid.String() != text {
			return PermissionPolicy{}, ErrPermissions
		}
		canonical := sid.String()
		if _, ok := seen[canonical]; ok {
			return PermissionPolicy{}, ErrPermissions
		}
		seen[canonical] = struct{}{}
		copyGrants = append(copyGrants, WindowsGrant{SID: canonical, Access: grant.Access})
	}
	return PermissionPolicy{kind: permissionWindowsRestricted, grants: copyGrants}, nil
}

func platformOpenRoot(path string, policy RootPolicy) (platformRoot, error) {
	return platformOpenRootWithPins(path, policy, false)
}
func platformOpenMutableRoot(path string, policy RootPolicy) (platformRoot, error) {
	return platformOpenRootWithPins(path, policy, true)
}
func platformOpenCreateCapableRoot(path string, policy RootPolicy) (platformRoot, error) {
	return platformOpenRootWithPins(path, policy, true)
}
func platformOpenRootWithPins(path string, policy RootPolicy, mutable bool) (platformRoot, error) {
	volume := filepath.VolumeName(path)
	rootPath := volume + `\`
	fd, err := winOpenAbsolute(rootPath)
	if err != nil {
		return nil, ErrUnsafePath
	}
	rootInfo, err := winInfo(fd)
	if err != nil {
		_ = windows.CloseHandle(fd)
		return nil, ErrUnsafePath
	}
	rootID, err := winIdentity(fd, rootInfo)
	if err != nil {
		_ = windows.CloseHandle(fd)
		return nil, ErrUnsupportedInspection
	}
	if policy.ExcludedAncestor != (Identity{}) && rootID == policy.ExcludedAncestor {
		_ = windows.CloseHandle(fd)
		return nil, pathSecurityFailure()
	}
	var pins []windows.Handle
	pinsTransferred := false
	defer func() {
		if !pinsTransferred {
			closeWindowsPins(pins)
		}
	}()
	if mutable {
		pin, pinErr := winOpenAbsolutePinned(rootPath)
		if pinErr != nil {
			_ = windows.CloseHandle(fd)
			return nil, ErrUnsafePath
		}
		pinInfo, pinErr := winInfo(pin)
		pinID, idErr := winIdentity(pin, pinInfo)
		if pinErr != nil || idErr != nil || pinID != rootID {
			_ = windows.CloseHandle(pin)
			_ = windows.CloseHandle(fd)
			return nil, ErrIdentityChanged
		}
		pins = append(pins, pin)
	}
	parts := strings.FieldsFunc(strings.TrimPrefix(path[len(volume):], `\`), func(r rune) bool { return r == '\\' || r == '/' })
	if len(parts) == 0 {
		info, err := winInfo(fd)
		if err != nil {
			_ = windows.CloseHandle(fd)
			return nil, ErrUnsafePath
		}
		if err := winCheck(fd, info, Directory, policy.Access); err != nil {
			_ = windows.CloseHandle(fd)
			return nil, err
		}
		id, identityErr := winIdentity(fd, info)
		if identityErr != nil {
			_ = windows.CloseHandle(fd)
			return nil, ErrUnsupportedInspection
		}
		if policy.ExcludedAncestor != (Identity{}) && id == policy.ExcludedAncestor {
			_ = windows.CloseHandle(fd)
			return nil, pathSecurityFailure()
		}
		pinsTransferred = true
		return &windowsRoot{fd: fd, volumeRoot: rootPath, path: rootPath, id: id, pins: pins}, nil
	}
	for i, part := range parts {
		createCapable := mutable && i == len(parts)-1
		next, err := winOpenAtDirectory(fd, part, createCapable, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
		if err != nil {
			_ = windows.CloseHandle(fd)
			return nil, winPathOpenError(err)
		}
		info, err := winInfo(next)
		if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = windows.CloseHandle(next)
			_ = windows.CloseHandle(fd)
			if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
				return nil, pathSecurityFailure()
			}
			return nil, ErrUnsafePath
		}
		id, identityErr := winIdentity(next, info)
		if identityErr != nil {
			_ = windows.CloseHandle(next)
			_ = windows.CloseHandle(fd)
			return nil, ErrUnsupportedInspection
		}
		if policy.ExcludedAncestor != (Identity{}) && id == policy.ExcludedAncestor {
			_ = windows.CloseHandle(next)
			_ = windows.CloseHandle(fd)
			return nil, pathSecurityFailure()
		}
		if mutable {
			pin, pinErr := winOpenAtDirectory(fd, part, createCapable, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
			if pinErr != nil {
				_ = windows.CloseHandle(next)
				_ = windows.CloseHandle(fd)
				closeWindowsPins(pins)
				return nil, ErrUnsafePath
			}
			pinInfo, pinErr := winInfo(pin)
			pinID, idErr := winIdentity(pin, pinInfo)
			if pinErr != nil || idErr != nil || pinID != id {
				_ = windows.CloseHandle(pin)
				_ = windows.CloseHandle(next)
				_ = windows.CloseHandle(fd)
				closeWindowsPins(pins)
				return nil, ErrIdentityChanged
			}
			pins = append(pins, pin)
		}
		if i == len(parts)-1 {
			if err := winCheck(next, info, Directory, policy.Access); err != nil {
				_ = windows.CloseHandle(next)
				_ = windows.CloseHandle(fd)
				return nil, err
			}
			pinsTransferred = true
			return &windowsRoot{fd: next, parent: fd, leaf: part, path: path, id: id, pins: pins}, nil
		}
		_ = windows.CloseHandle(fd)
		fd = next
	}
	return nil, ErrUnsafePath
}

func platformCreateRoot(parent platformRoot, name string, parentPolicy, policy RootPolicy) (platformRoot, error) {
	p, ok := parent.(*windowsRoot)
	if !ok {
		return nil, ErrUnsafePath
	}
	parentInfo, parentErr := winInfo(p.fd)
	if parentErr != nil {
		return nil, ErrUnsupportedInspection
	}
	if err := winCheck(p.fd, parentInfo, Directory, parentPolicy.Access); err != nil {
		return nil, err
	}
	h, err := winCreateDirectory(p.fd, name, policy.Access)
	if err != nil {
		if existing, openErr := winOpenAtDirectory(p.fd, name, false, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE); openErr == nil {
			_ = windows.CloseHandle(existing)
			return nil, ErrAlreadyExists
		}
		return nil, ErrUnsafePath
	}
	info, err := winInfo(h)
	if err == nil {
		err = winCheck(h, info, Directory, policy.Access)
	}
	if err != nil {
		winDeleteCreated(h)
		_ = windows.CloseHandle(h)
		return nil, err
	}
	id, err := winIdentity(h, info)
	if err != nil {
		winDeleteCreated(h)
		_ = windows.CloseHandle(h)
		return nil, ErrUnsupportedInspection
	}
	var parentHandle windows.Handle
	if err := winDuplicateParent(windows.CurrentProcess(), p.fd, windows.CurrentProcess(), &parentHandle, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		winDeleteCreated(h)
		_ = windows.CloseHandle(h)
		return nil, ErrUnsafePath
	}
	pins := make([]windows.Handle, 0, len(p.pins))
	for _, source := range p.pins {
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), source, windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			closeWindowsPins(pins)
			_ = windows.CloseHandle(parentHandle)
			winDeleteCreated(h)
			_ = windows.CloseHandle(h)
			return nil, ErrUnsafePath
		}
		pins = append(pins, duplicate)
	}
	return &windowsRoot{fd: h, parent: parentHandle, leaf: name, path: filepath.Join(p.path, name), id: id, pins: pins}, nil
}

func platformCreateFileOnce(ctx context.Context, parent platformRoot, parentPolicy RootPolicy, name string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	p, ok := parent.(*windowsRoot)
	if !ok {
		return CommitBoundary{}, ErrUnsafePath
	}
	parentInfo, parentErr := winInfo(p.fd)
	if parentErr != nil {
		return CommitBoundary{}, ErrUnsupportedInspection
	}
	if err := winCheck(p.fd, parentInfo, Directory, parentPolicy.Access); err != nil {
		return CommitBoundary{}, err
	}
	h, err := winCreateFileOnce(p.fd, name, policy.Access)
	if err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) || errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return CommitBoundary{}, ErrAlreadyExists
		}
		return CommitBoundary{}, ErrUnsafePath
	}
	defer windows.CloseHandle(h)
	durable := false
	defer func() {
		if !durable {
			_ = winMarkDelete(h)
		}
	}()
	for written := 0; written < len(data); {
		if err := ctx.Err(); err != nil {
			return CommitBoundary{NamespacePublished: true}, err
		}
		var n uint32
		if err := windows.WriteFile(h, data[written:], &n, nil); err != nil || n == 0 {
			return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
		}
		written += int(n)
	}
	info, err := winInfo(h)
	if err != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsupportedInspection
	}
	if err := winCheck(h, info, RegularFile, policy.Access); err != nil {
		return CommitBoundary{NamespacePublished: true}, err
	}
	if err := winCreateOnceFlush(h); err != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsupportedInspection
	}
	durable = true
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}

func (r *windowsRoot) identity() Identity { return r.id }

func (r *windowsRoot) recheck() error {
	if r.volumeRoot != "" {
		h, err := winOpenAbsolute(r.volumeRoot)
		if err != nil {
			return ErrIdentityChanged
		}
		defer windows.CloseHandle(h)
		info, err := winInfo(h)
		id, identityErr := winIdentity(h, info)
		if err != nil || identityErr != nil || id != r.id {
			return ErrIdentityChanged
		}
		return nil
	}
	h, err := winOpenAtDirectory(r.parent, r.leaf, false, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
	if err != nil {
		return ErrIdentityChanged
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	id, identityErr := winIdentity(h, info)
	if err != nil || identityErr != nil || id != r.id {
		return ErrIdentityChanged
	}
	return nil
}

func (r *windowsRoot) inspect(name string, policy FilePolicy) (FileState, error) {
	if err := r.recheck(); err != nil {
		return FileState{}, err
	}
	h, err := winOpenAt(r.fd, name, false)
	if err != nil {
		if winNotFound(err) {
			switch policy.Presence {
			case Optional, MustBeAbsent:
				return FileState{Kind: policy.Kind}, nil
			default:
				return FileState{}, ErrNotFound
			}
		}
		return FileState{}, winPathOpenError(err)
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	if r.inspectInfoForTest != nil {
		info = r.inspectInfoForTest(name, info)
	}
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		if err == nil && info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return FileState{}, pathSecurityFailure()
		}
		return FileState{}, ErrUnsafePath
	}
	if policy.Presence == MustBeAbsent {
		return FileState{}, ErrAlreadyExists
	}
	if err := winCheck(h, info, policy.Kind, policy.Access); err != nil {
		return FileState{}, err
	}
	return winState(h, info, policy.Kind)
}

func (r *windowsRoot) readFile(name string, policy FilePolicy) ([]byte, FileState, error) {
	if err := r.recheck(); err != nil {
		return nil, FileState{}, err
	}
	h, err := winOpenAt(r.fd, name, false)
	if err != nil {
		if winNotFound(err) {
			return nil, FileState{}, ErrNotFound
		}
		return nil, FileState{}, winPathOpenError(err)
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, FileState{}, ErrUnsafePath
	}
	if err := winCheck(h, info, RegularFile, policy.Access); err != nil {
		return nil, FileState{}, err
	}
	state, err := winState(h, info, RegularFile)
	if err != nil {
		return nil, FileState{}, ErrUnsupportedInspection
	}
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
		var n uint32
		err := windows.ReadFile(h, tmp[:chunk], &n, nil)
		if n > 0 {
			if policy.MaxBytes > 0 && int64(len(buf))+int64(n) > policy.MaxBytes {
				return nil, FileState{}, ErrTooLarge
			}
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			return nil, FileState{}, ErrUnsafePath
		}
		if n == 0 {
			break
		}
	}
	return buf, state, nil
}

func (r *windowsRoot) close() error {
	_ = windows.CloseHandle(r.fd)
	if r.parent != 0 {
		_ = windows.CloseHandle(r.parent)
	}
	closeWindowsPins(r.pins)
	return nil
}
func closeWindowsPins(pins []windows.Handle) {
	for _, h := range pins {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
	}
}

func winOpenAbsolute(path string) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return 0, err
	}
	return winOpenDirectory(nil, name, false, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}
func winOpenAbsolutePinned(path string) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return 0, err
	}
	return winOpenDirectory(nil, name, false, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}
func winOpenAt(parent windows.Handle, name string, create bool) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	return winOpen(&parent, n, create)
}
func winOpenAtPinned(parent windows.Handle, name string) (windows.Handle, error) {
	return winOpenAtDirectory(parent, name, false, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

func winOpenAtDirectory(parent windows.Handle, name string, createCapable bool, share uint32) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	return winOpenDirectory(&parent, n, createCapable, share)
}
func winOpenDirectory(parent *windows.Handle, name *windows.NTUnicodeString, createCapable bool, share uint32) (windows.Handle, error) {
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if parent != nil {
		oa.RootDirectory = *parent
	}
	access := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if createCapable {
		access |= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES
	}
	var h windows.Handle
	var io windows.IO_STATUS_BLOCK
	err := windows.NtCreateFile(&h, access, &oa, &io, nil, 0, share, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return h, err
}
func winOpen(parent *windows.Handle, name *windows.NTUnicodeString, create bool) (windows.Handle, error) {
	return winOpenWithShare(parent, name, create, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}
func winOpenWithShare(parent *windows.Handle, name *windows.NTUnicodeString, create bool, share uint32) (windows.Handle, error) {
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), ObjectName: name, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if parent != nil {
		oa.RootDirectory = *parent
	}
	var h windows.Handle
	var io windows.IO_STATUS_BLOCK
	disposition := uint32(windows.FILE_OPEN)
	if create {
		disposition = windows.FILE_CREATE
	}
	err := windows.NtCreateFile(&h, windows.FILE_GENERIC_READ|windows.FILE_READ_ATTRIBUTES, &oa, &io, nil, 0, share, disposition, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	return h, err
}
func winCreateDirectoryAt(parent windows.Handle, name string, policy PermissionPolicy) (windows.Handle, error) {
	return winOpenAtCreate(parent, name, policy)
}
func winOpenAtCreate(parent windows.Handle, name string, policy PermissionPolicy) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if policy.kind == permissionWindowsRestricted {
		sd, err := winRestrictedSecurityDescriptor(policy)
		if err != nil {
			return 0, err
		}
		oa.SecurityDescriptor = sd
	}
	var h windows.Handle
	var io windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_ATTRIBUTES|windows.DELETE, &oa, &io, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	return h, err
}
func winCreateFileOnce(parent windows.Handle, name string, policy PermissionPolicy) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	oa := windows.OBJECT_ATTRIBUTES{Length: uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})), RootDirectory: parent, ObjectName: n, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	if policy.kind == permissionWindowsRestricted {
		sd, err := winRestrictedSecurityDescriptor(policy)
		if err != nil {
			return 0, err
		}
		oa.SecurityDescriptor = sd
	}
	var h windows.Handle
	var io windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, windows.FILE_WRITE_DATA|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE|windows.DELETE, &oa, &io, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_WRITE_THROUGH, 0, 0)
	return h, err
}
func winInfo(h windows.Handle) (windows.ByHandleFileInformation, error) {
	var info windows.ByHandleFileInformation
	return info, windows.GetFileInformationByHandle(h, &info)
}
func winIdentity(h windows.Handle, _ windows.ByHandleFileInformation) (Identity, error) {
	var details windowsFileIDInfo
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&details)), uint32(unsafe.Sizeof(details))); err != nil {
		return Identity{}, err
	}
	return windowsIdentityFromFileID(details), nil
}
func windowsIdentityFromFileID(details windowsFileIDInfo) Identity {
	var id Identity
	id.platform = windowsIdentityTag
	binary.LittleEndian.PutUint64(id.data[:8], details.VolumeSerialNumber)
	copy(id.data[8:], details.FileID[:])
	return id
}
func winCheck(h windows.Handle, info windows.ByHandleFileInformation, kind EntryKind, policy PermissionPolicy) error {
	if err := validateWindowsKind(info, kind); err != nil {
		return err
	}
	if policy.kind == permissionIdentityOnly {
		return nil
	}
	if policy.kind != permissionWindowsRestricted {
		return ErrUnsupportedInspection
	}
	return winCheckACL(h, policy)
}

func validateWindowsKind(info windows.ByHandleFileInformation, kind EntryKind) error {
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return pathSecurityFailure()
	}
	if (kind == Directory) != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return ErrUnsafePath
	}
	return nil
}

type winACLRule struct {
	aceType, aceFlags uint8
	sid               string
	mask              uint32
}

func winCheckACL(h windows.Handle, policy PermissionPolicy) error {
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return ErrUnsupportedInspection
	}
	control, _, err := sd.Control()
	if err != nil {
		return ErrUnsupportedInspection
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return validateWindowsACL(policy, control&windows.SE_DACL_PROTECTED != 0, false, nil)
	}
	rules := make([]winACLRule, 0, dacl.AceCount)
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			return ErrUnsupportedInspection
		}
		rule := winACLRule{aceType: ace.Header.AceType, aceFlags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		if rule.aceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			rules = append(rules, rule)
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsValid() {
			return ErrUnsupportedInspection
		}
		rule.sid = sid.String()
		rules = append(rules, rule)
	}
	return validateWindowsACL(policy, control&windows.SE_DACL_PROTECTED != 0, true, rules)
}

func validateWindowsACL(policy PermissionPolicy, protected, present bool, rules []winACLRule) error {
	if !protected || !present {
		return ErrPermissions
	}
	allowed := make(map[string]uint32, len(policy.grants))
	for _, grant := range policy.grants {
		allowed[grant.SID] = 0
	}
	for _, rule := range rules {
		if rule.aceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return ErrUnsupportedInspection
		}
		if rule.aceFlags&windows.VALID_INHERIT_FLAGS != 0 {
			return ErrPermissions
		}
		if _, ok := allowed[rule.sid]; !ok {
			return ErrPermissions
		}
		allowed[rule.sid] |= rule.mask
	}
	for _, grant := range policy.grants {
		if allowed[grant.SID] != grant.Access {
			return ErrPermissions
		}
	}
	return nil
}
func winRestrictedSecurityDescriptor(policy PermissionPolicy) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "D:P"
	for _, grant := range policy.grants {
		sddl += fmt.Sprintf("(A;;0x%X;;;%s)", grant.Access, grant.SID)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil || sd == nil {
		return nil, ErrUnsupportedInspection
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return nil, ErrUnsupportedInspection
	}
	_ = dacl
	return sd, nil
}

var (
	winCreateDirectory     = winCreateDirectoryAt
	winDuplicateParent     = windows.DuplicateHandle
	winDeleteCreatedHandle = winDeleteCreatedNow
	winCreateOnceFlush     = windows.FlushFileBuffers
)

func winDeleteCreated(h windows.Handle) { winDeleteCreatedHandle(h) }
func winDeleteCreatedNow(h windows.Handle) {
	_ = winMarkDelete(h)
}
func winMarkDelete(h windows.Handle) error {
	var io windows.IO_STATUS_BLOCK
	deleteFlag := byte(1)
	return windows.NtSetInformationFile(h, &io, &deleteFlag, 1, windows.FileDispositionInformation)
}
func winState(h windows.Handle, info windows.ByHandleFileInformation, kind EntryKind) (FileState, error) {
	id, err := winIdentity(h, info)
	if err != nil {
		return FileState{}, err
	}
	return FileState{Present: true, Identity: id, Kind: kind, Size: int64(uint64(info.FileSizeHigh)<<32 | uint64(info.FileSizeLow)), ModTime: time.Unix(0, info.LastWriteTime.Nanoseconds())}, nil
}
func winNotFound(err error) bool {
	return errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) || errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}
func winPathOpenError(err error) error {
	if errors.Is(err, windows.STATUS_REPARSE_POINT_ENCOUNTERED) || errors.Is(err, windows.STATUS_DIRECTORY_IS_A_REPARSE_POINT) || errors.Is(err, windows.ERROR_REPARSE_POINT_ENCOUNTERED) {
		return pathSecurityFailure()
	}
	return ErrUnsafePath
}
