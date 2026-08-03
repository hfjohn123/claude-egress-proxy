//go:build windows && cep_testcontrol

package securefs

import (
	"os"
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

// TestMutableRootPinsWindowsNamespace catches path-based publication escaping
// through a renamed selected root or a renamed higher ancestor.
func TestMutableRootPinsWindowsNamespace(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	rootPolicy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_LIST_DIRECTORY|0x0002|0x0040)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := OpenRoot(ancestor, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	created, err := CreateRoot(parent, "state", RootPolicy{Access: rootPolicy})
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	_ = parent.Close()
	path := filepath.Join(ancestor, "state")
	r, err := OpenMutableRoot(path, RootPolicy{Access: rootPolicy})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Rename(path, filepath.Join(ancestor, "moved-state")); err == nil {
		t.Fatal("selected-root rename succeeded while mutable root pinned")
	}
	if err := os.Rename(ancestor, filepath.Join(base, "moved-ancestor")); err == nil {
		t.Fatal("ancestor rename succeeded while mutable root pinned")
	}
}

// TestFailedMutableOpenReleasesTraversalPins catches an error path retaining a
// no-delete-share pin after a later path component is rejected.
func TestFailedMutableOpenReleasesTraversalPins(t *testing.T) {
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
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(ancestor, "not-a-directory")
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMutableRoot(bad, RootPolicy{Access: policy}); err == nil {
		t.Fatal("mutable open of regular file succeeded")
	}
	if err := os.Rename(ancestor, filepath.Join(base, "renamed")); err != nil {
		t.Fatalf("failed mutable open leaked ancestor pin: %v", err)
	}
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
