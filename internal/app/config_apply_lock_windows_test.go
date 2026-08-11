//go:build windows

package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"golang.org/x/sys/windows"
)

func TestConfigApplyLockNameHasNoDistinctWindowsAlias(t *testing.T) {
	base := t.TempDir()
	control := filepath.Join(base, "config-apply-characterization.lock")
	if err := os.WriteFile(control, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	controlShort := windowsShortPath(t, control)
	if sameConfigApplyPath(controlShort, control) {
		t.Skip("volume does not generate distinct 8.3 aliases")
	}

	lockPath := filepath.Join(base, configApplyLockName)
	if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	shortName := filepath.Base(windowsShortPath(t, lockPath))
	if !configDirectoryLeafReserved(shortName) {
		t.Fatalf("lock name %q has unreserved alias %q", configApplyLockName, shortName)
	}
}

func windowsShortPath(t *testing.T, path string) string {
	t.Helper()
	longPath, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 32768)
	length, err := windows.GetShortPathName(longPath, &buffer[0], uint32(len(buffer)))
	if err != nil {
		t.Fatal(err)
	}
	if length == 0 || length >= uint32(len(buffer)) {
		t.Fatalf("invalid short-path length %d", length)
	}
	return windows.UTF16ToString(buffer[:length])
}

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
