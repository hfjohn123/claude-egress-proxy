//go:build windows

package app

import (
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"golang.org/x/sys/windows"
)

func TestInstalledConfigLockSerializesIndependentWindowsRoots(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	rootAccess, err := securefs.WindowsRestrictedPermissions(
		[]string{user.User.Sid.String()},
		windows.FILE_GENERIC_READ|windows.FILE_TRAVERSE|windows.FILE_WRITE_ATTRIBUTES|0x0002|0x0004|0x0040,
	)
	if err != nil {
		t.Fatal(err)
	}
	fileAccess, err := securefs.WindowsRestrictedPermissions(
		[]string{user.User.Sid.String()},
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE,
	)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	parent, err := securefs.OpenCreateCapableRoot(base, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	created, err := securefs.CreateRoot(parent, "restricted", securefs.RootPolicy{Access: rootAccess})
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}

	policies := config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: rootAccess},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: fileAccess, MaxBytes: 1},
	}
	filesystem := installedConfigFilesystem{
		securityPolicies:      func() (config.SecurityPolicies, error) { return policies, nil },
		checkoutIdentity:      func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: securefs.ValidateMutableOutput,
	}
	assertRealInstalledConfigLockSerializes(t, filepath.Join(base, "restricted", "config.yaml"), filesystem)
}
