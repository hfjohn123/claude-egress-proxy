//go:build windows && cep_testcontrol

package securefs

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func mutableTestRoot(t *testing.T) MutableRoot {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_LIST_DIRECTORY|0x0002|0x0040)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	parent, err := OpenRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	created, err := CreateRoot(parent, "restricted", RootPolicy{Access: policy})
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(filepath.Join(base, "restricted"), RootPolicy{Access: policy})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}
func mutableFilePolicy(p Presence, max int64) FilePolicy {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		panic(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		panic(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE)
	if err != nil {
		panic(err)
	}
	return FilePolicy{Presence: p, Kind: RegularFile, Access: policy, MaxBytes: max}
}
