//go:build windows

package securefs

import (
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
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_LIST_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	parent, err := OpenRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
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
		if err := validateWindowsACL(policy, true, true, []winACLRule{{aceType: windows.ACCESS_ALLOWED_ACE_TYPE, aceFlags: flag, sid: "S-1-5-32-544", mask: windows.FILE_LIST_DIRECTORY}}); !errors.Is(err, ErrPermissions) {
			t.Fatalf("inheritance flag %#x error = %v, want ErrPermissions", flag, err)
		}
	}
}

func TestWindowsReparseAttributeIsUnsafe(t *testing.T) {
	if err := validateWindowsKind(windows.ByHandleFileInformation{FileAttributes: windows.FILE_ATTRIBUTE_DIRECTORY | windows.FILE_ATTRIBUTE_REPARSE_POINT}, Directory); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("reparse info error = %v, want ErrUnsafePath", err)
	}
}

func TestWindowsPostCreateFailureTargetsCreatedHandle(t *testing.T) {
	parent, err := OpenRoot(t.TempDir(), RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	oldDuplicate, oldDelete := winDuplicateParent, winDeleteCreatedHandle
	t.Cleanup(func() { winDuplicateParent, winDeleteCreatedHandle = oldDuplicate, oldDelete })
	deleted := false
	winDuplicateParent = func(windows.Handle, windows.Handle, windows.Handle, *windows.Handle, uint32, bool, uint32) error {
		return windows.ERROR_ACCESS_DENIED
	}
	winDeleteCreatedHandle = func(windows.Handle) { deleted = true }
	if _, err := CreateRoot(parent, "post-create-failure", RootPolicy{Access: IdentityOnlyPermissions()}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("CreateRoot error = %v, want ErrUnsafePath", err)
	}
	if !deleted {
		t.Fatal("post-create failure did not target created handle for deletion")
	}
}
