//go:build windows

package securefs

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/windows"
)

// TestWindowsIdentityUsesAllFileIDInfoBytes catches a legacy 32-bit volume
// serial or padded identity rather than the specified 64-bit volume + 16-byte ID.
func TestWindowsIdentityUsesAllFileIDInfoBytes(t *testing.T) {
	info := windowsFileIDInfo{VolumeSerialNumber: 0x1122334455667788, FileID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}}
	id := windowsIdentityFromFileID(info)
	if got := binary.LittleEndian.Uint64(id.data[:8]); got != 0x1122334455667788 {
		t.Fatalf("volume serial = %#x, want full 64-bit serial", got)
	}
	if got := id.data[8:]; string(got) != string(info.FileID[:]) {
		t.Fatalf("file ID bytes = %x, want %x", got, info.FileID)
	}
}

// TestWindowsACLPolicyRejectsUnsafeInputs catches an ACL policy constructor
// that accepts empty, duplicate, malformed, or zero-access security rules.
func TestWindowsACLPolicyRejectsUnsafeInputs(t *testing.T) {
	for _, test := range [][]string{{}, {"not-a-sid"}, {"S-1-5-32-544", "S-1-5-32-544"}} {
		if _, err := WindowsRestrictedPermissions(test, 1); !errors.Is(err, ErrPermissions) {
			t.Fatalf("WindowsRestrictedPermissions(%q) error = %v, want ErrPermissions", test, err)
		}
	}
	if _, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544"}, 0); !errors.Is(err, ErrPermissions) {
		t.Fatalf("zero access error = %v, want ErrPermissions", err)
	}
}

func TestWindowsExactPermissionsRequireExactPerPrincipalMasks(t *testing.T) {
	const fileAllAccess = uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	p, err := WindowsExactPermissions([]WindowsGrant{{SID: "S-1-5-32-544", Access: fileAllAccess}, {SID: "S-1-5-18", Access: windows.FILE_GENERIC_READ}})
	if err != nil {
		t.Fatal(err)
	}
	good := []winACLRule{{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-32-544", mask: fileAllAccess}, {aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-18", mask: windows.FILE_GENERIC_READ}}
	if err := validateWindowsACL(p, true, true, good); err != nil {
		t.Fatalf("exact ACL = %v", err)
	}
	good[1].mask |= windows.FILE_WRITE_DATA
	if err := validateWindowsACL(p, true, true, good); !errors.Is(err, ErrPermissions) {
		t.Fatalf("extra effective access = %v", err)
	}
	if _, err := WindowsExactPermissions([]WindowsGrant{{SID: "S-1-5-18", Access: 1}, {SID: "S-1-5-18", Access: 2}}); !errors.Is(err, ErrPermissions) {
		t.Fatalf("duplicate SID = %v", err)
	}
}

func TestWindowsCreateFileOnceAppliesExactDACL(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	const fileAllAccess = uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	policy, err := WindowsExactPermissions([]WindowsGrant{{SID: user.User.Sid.String(), Access: fileAllAccess}})
	if err != nil {
		t.Fatal(err)
	}
	root, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	filePolicy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: policy, MaxBytes: 4}
	boundary, err := CreateFileOnce(context.Background(), root, "exact", []byte("four"), filePolicy)
	if err != nil || boundary != (CommitBoundary{NamespacePublished: true, TargetDurable: true}) {
		t.Fatalf("CreateFileOnce = %+v,%v", boundary, err)
	}
	if _, err := root.Inspect("exact", FilePolicy{Presence: Required, Kind: RegularFile, Access: policy, MaxBytes: 4}); err != nil {
		t.Fatalf("exact ACL inspection = %v", err)
	}
}

func TestWindowsCreateFileOnceRequiresFlushAndRemovesFailedIdentity(t *testing.T) {
	old := winCreateOnceFlush
	t.Cleanup(func() { winCreateOnceFlush = old })
	winCreateOnceFlush = func(windows.Handle) error { return windows.ERROR_ACCESS_DENIED }
	root, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	boundary, err := CreateFileOnce(context.Background(), root, "failed", []byte("four"), policy)
	if !errors.Is(err, ErrUnsupportedInspection) || boundary != (CommitBoundary{NamespacePublished: true}) {
		t.Fatalf("flush failure = %+v,%v", boundary, err)
	}
	state, err := root.Inspect("failed", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4})
	if err != nil || state.Present {
		t.Fatalf("failed identity remained = %+v,%v", state, err)
	}
}

func TestWindowsCreateFileOnceMapsDiskFullWriteAndRemovesCreatedHandle(t *testing.T) {
	old := winCreateOnceWrite
	t.Cleanup(func() { winCreateOnceWrite = old })
	winCreateOnceWrite = func(windows.Handle, []byte, *uint32, *windows.Overlapped) error {
		return windows.ERROR_DISK_FULL
	}
	root, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	boundary, err := CreateFileOnce(context.Background(), root, "disk-full", []byte("four"), policy)
	if !errors.Is(err, ErrUnsupportedInspection) || boundary != (CommitBoundary{NamespacePublished: true}) {
		t.Fatalf("write failure = %+v,%v", boundary, err)
	}
	state, err := root.Inspect("disk-full", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4})
	if err != nil || state.Present {
		t.Fatalf("failed identity remained = %+v,%v", state, err)
	}
}

func TestWindowsCreateFileOnceMapsDiskFullCreateToIO(t *testing.T) {
	old := winCreateFileOnce
	t.Cleanup(func() { winCreateFileOnce = old })
	winCreateFileOnce = func(windows.Handle, string, PermissionPolicy) (windows.Handle, error) {
		return 0, windows.ERROR_DISK_FULL
	}
	root, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := FilePolicy{Presence: MustBeAbsent, Kind: RegularFile, Access: IdentityOnlyPermissions(), MaxBytes: 4}
	boundary, err := CreateFileOnce(context.Background(), root, "disk-full-create", []byte("four"), policy)
	if !errors.Is(err, ErrUnsupportedInspection) || boundary != (CommitBoundary{}) {
		t.Fatalf("create failure = %+v,%v", boundary, err)
	}
}

// TestWindowsCreateRootAppliesRestrictedDACLAtCreation catches directory
// creation that accepts a restricted policy but never installs its DACL.
func TestWindowsCreateRootAppliesRestrictedDACLAtCreation(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_TRAVERSE|windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_ATTRIBUTES)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	created, err := CreateRoot(parent, "restricted", RootPolicy{Access: policy})
	if err != nil {
		t.Fatalf("CreateRoot restricted DACL = %v", err)
	}
	defer created.Close()
	if err := created.RecheckIdentity(); err != nil {
		t.Fatalf("restricted root RecheckIdentity = %v", err)
	}
	state, err := created.Inspect("absent", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if err != nil || state.Present {
		t.Fatalf("restricted root Inspect = (%+v, %v)", state, err)
	}
}

func TestWindowsADSLeafIsUnsafe(t *testing.T) {
	root, err := OpenRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	_, err = root.Inspect("state:secret", FilePolicy{Presence: Optional, Kind: RegularFile, Access: IdentityOnlyPermissions()})
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("ADS leaf error = %v, want ErrUnsafePath", err)
	}
}

func TestWindowsACLValidatorRejectsUnsafeDescriptors(t *testing.T) {
	policy, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544", "S-1-5-18"}, windows.FILE_LIST_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	allowAdmin := winACLRule{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-32-544", mask: windows.FILE_LIST_DIRECTORY}
	allowSystem := winACLRule{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-18", mask: windows.FILE_LIST_DIRECTORY}
	for _, test := range []struct {
		name               string
		protected, present bool
		rules              []winACLRule
		want               error
	}{
		{"missing DACL", true, false, nil, ErrPermissions},
		{"unprotected", false, true, []winACLRule{allowAdmin}, ErrPermissions},
		{"foreign SID", true, true, []winACLRule{{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-1-0", mask: windows.FILE_LIST_DIRECTORY}}, ErrPermissions},
		{"deny ACE", true, true, []winACLRule{{aceType: windows.ACCESS_DENIED_ACE_TYPE}}, ErrUnsupportedInspection},
		{"insufficient per SID", true, true, []winACLRule{allowAdmin, {aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-18", mask: 0}}, ErrPermissions},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateWindowsACL(policy, test.protected, test.present, test.rules); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	for _, flag := range []uint8{windows.OBJECT_INHERIT_ACE, windows.CONTAINER_INHERIT_ACE, windows.NO_PROPAGATE_INHERIT_ACE, windows.INHERIT_ONLY_ACE, windows.INHERITED_ACE} {
		rules := []winACLRule{allowAdmin, allowSystem}
		rules[0].aceFlags = flag
		if err := validateWindowsACL(policy, true, true, rules); !errors.Is(err, ErrPermissions) {
			t.Fatalf("inheritance flag %#x error = %v, want ErrPermissions", flag, err)
		}
	}
	unionPolicy, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544", "S-1-5-18"}, windows.FILE_LIST_DIRECTORY|windows.FILE_WRITE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	unionRules := []winACLRule{
		{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-32-544", mask: windows.FILE_LIST_DIRECTORY},
		{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-32-544", mask: windows.FILE_WRITE_DATA},
		{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-18", mask: windows.FILE_LIST_DIRECTORY},
		{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, sid: "S-1-5-18", mask: windows.FILE_WRITE_DATA},
	}
	if err := validateWindowsACL(unionPolicy, true, true, unionRules); err != nil {
		t.Fatalf("per-SID multi-ACE union rejected: %v", err)
	}
}

func TestWindowsReparseAttributeIsUnsafe(t *testing.T) {
	if err := validateWindowsKind(windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT}, Directory); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("reparse info error = %v, want ErrUnsafePath", err)
	}
}

func TestWindowsPostCreateFailureTargetsCreatedHandle(t *testing.T) {
	parent, err := OpenCreateCapableRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	oldCreate, oldDuplicate, oldDelete := winCreateDirectory, winDuplicateParent, winDeleteCreatedHandle
	t.Cleanup(func() {
		winCreateDirectory, winDuplicateParent, winDeleteCreatedHandle = oldCreate, oldDuplicate, oldDelete
	})
	var created windows.Handle
	winCreateDirectory = func(parent windows.Handle, name string, policy PermissionPolicy) (windows.Handle, error) {
		handle, err := oldCreate(parent, name, policy)
		created = handle
		return handle, err
	}
	var deleted windows.Handle
	winDuplicateParent = func(windows.Handle, windows.Handle, windows.Handle, *windows.Handle, uint32, bool, uint32) error {
		return windows.ERROR_ACCESS_DENIED
	}
	winDeleteCreatedHandle = func(handle windows.Handle) { deleted = handle }
	if _, err := CreateRoot(parent, "post-create-failure", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("CreateRoot error = %v, want ErrUnsafePath", err)
	}
	if created == 0 || deleted != created {
		t.Fatalf("deletion handle = %v, created handle = %v; want exact created handle", deleted, created)
	}
}
