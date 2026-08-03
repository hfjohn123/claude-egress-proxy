//go:build windows

package securefs

import (
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

// Retained roots must later be reopened for identity rechecks. These rights
// are added to each allowed SID at creation, while policy.mask remains the
// caller's required minimum for validation.
const windowsRetainedRootAccess = windows.FILE_GENERIC_READ

type windowsRoot struct {
	fd         windows.Handle
	parent     windows.Handle
	leaf       string
	volumeRoot string
	id         Identity
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
	seen := make(map[string]struct{}, len(allowedSIDs))
	copySIDs := make([]string, 0, len(allowedSIDs))
	for _, text := range allowedSIDs {
		if text == "" {
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
		copySIDs = append(copySIDs, canonical)
	}
	return PermissionPolicy{kind: permissionWindowsRestricted, sids: copySIDs, mask: requiredAccess}, nil
}

func platformOpenRoot(path string, policy RootPolicy) (platformRoot, error) {
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
		return nil, ErrUnsafePath
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
			return nil, ErrUnsafePath
		}
		return &windowsRoot{fd: fd, volumeRoot: rootPath, id: id}, nil
	}
	for i, part := range parts {
		next, err := winOpenAt(fd, part, false)
		if err != nil {
			_ = windows.CloseHandle(fd)
			return nil, ErrUnsafePath
		}
		info, err := winInfo(next)
		if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			_ = windows.CloseHandle(next)
			_ = windows.CloseHandle(fd)
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
			return nil, ErrUnsafePath
		}
		if i == len(parts)-1 {
			if err := winCheck(next, info, Directory, policy.Access); err != nil {
				_ = windows.CloseHandle(next)
				_ = windows.CloseHandle(fd)
				return nil, err
			}
			return &windowsRoot{fd: next, parent: fd, leaf: part, id: id}, nil
		}
		_ = windows.CloseHandle(fd)
		fd = next
	}
	return nil, ErrUnsafePath
}

func platformCreateRoot(parent platformRoot, name string, policy RootPolicy) (platformRoot, error) {
	p, ok := parent.(*windowsRoot)
	if !ok {
		return nil, ErrUnsafePath
	}
	h, err := winCreateDirectory(p.fd, name, policy.Access)
	if err != nil {
		if existing, openErr := winOpenAt(p.fd, name, false); openErr == nil {
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
	return &windowsRoot{fd: h, parent: parentHandle, leaf: name, id: id}, nil
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
	h, err := winOpenAt(r.parent, r.leaf, false)
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
		return FileState{}, ErrUnsafePath
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	if err != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
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
		return nil, FileState{}, ErrUnsafePath
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
	return nil
}

func winOpenAbsolute(path string) (windows.Handle, error) {
	name, err := windows.NewNTUnicodeString(`\??\` + path)
	if err != nil {
		return 0, err
	}
	return winOpen(nil, name, false)
}
func winOpenAt(parent windows.Handle, name string, create bool) (windows.Handle, error) {
	n, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	return winOpen(&parent, n, create)
}
func winOpen(parent *windows.Handle, name *windows.NTUnicodeString, create bool) (windows.Handle, error) {
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
	err := windows.NtCreateFile(&h, windows.FILE_GENERIC_READ|windows.FILE_READ_ATTRIBUTES, &oa, &io, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
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
	err = windows.NtCreateFile(&h, windows.FILE_GENERIC_READ|windows.FILE_READ_ATTRIBUTES|windows.DELETE, &oa, &io, nil, 0, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
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
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || (kind == Directory) != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
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
	allowed := make(map[string]uint32, len(policy.sids))
	for _, sid := range policy.sids {
		allowed[sid] = 0
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
	for _, mask := range allowed {
		if mask&policy.mask != policy.mask {
			return ErrPermissions
		}
	}
	return nil
}
func winRestrictedSecurityDescriptor(policy PermissionPolicy) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := "D:P"
	for _, sid := range policy.sids {
		sddl += fmt.Sprintf("(A;;0x%X;;;%s)", policy.mask|windowsRetainedRootAccess, sid)
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
)

func winDeleteCreated(h windows.Handle) { winDeleteCreatedHandle(h) }
func winDeleteCreatedNow(h windows.Handle) {
	var io windows.IO_STATUS_BLOCK
	deleteFlag := byte(1)
	_ = windows.NtSetInformationFile(h, &io, (*byte)(unsafe.Pointer(&deleteFlag)), 1, windows.FileDispositionInfo)
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
