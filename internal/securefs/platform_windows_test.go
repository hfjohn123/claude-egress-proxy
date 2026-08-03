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
	policy, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544"}, windows.FILE_LIST_DIRECTORY)
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
