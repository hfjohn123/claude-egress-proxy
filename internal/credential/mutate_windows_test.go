//go:build windows

package credential

import (
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"golang.org/x/sys/windows"
)

func credentialMutableTestRoot(t *testing.T) (securefs.MutableRoot, securefs.FilePolicy) {
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
	access := uint32(windows.FILE_GENERIC_READ | windows.FILE_TRAVERSE | windows.FILE_WRITE_ATTRIBUTES | 0x0002 | 0x0004 | 0x0040)
	p, err := securefs.WindowsRestrictedPermissions([]string{user.User.Sid.String()}, access)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	parent, err := securefs.OpenCreateCapableRoot(base, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	child, err := securefs.CreateRoot(parent, "state", securefs.RootPolicy{Access: p})
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	root, err := securefs.OpenMutableRoot(filepath.Join(base, "state"), securefs.RootPolicy{Access: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	fileAccess, err := securefs.WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE)
	if err != nil {
		t.Fatal(err)
	}
	return root, securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: fileAccess, MaxBytes: int64(contract.V1().StoreBytes)}
}
