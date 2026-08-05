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
	p := securefs.LinuxExactPermissions(uint32(os.Getuid()), fs.FileMode(0o700))
	root, err := securefs.OpenMutableRoot(t.TempDir(), securefs.RootPolicy{Access: p})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root, securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().StoreBytes)}
}
