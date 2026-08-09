//go:build linux

package credential

import (
	"io/fs"
	"os"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func credentialMutableTestRoot(t *testing.T) (securefs.MutableRoot, securefs.FilePolicy) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	directoryPermissions := securefs.LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))
	filePermissions := securefs.LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o600))
	root, err := securefs.OpenMutableRoot(directory, securefs.RootPolicy{Access: directoryPermissions})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: filePermissions, MaxBytes: int64(contract.V1().StoreBytes)}
}
