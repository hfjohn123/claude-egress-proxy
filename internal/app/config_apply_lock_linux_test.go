//go:build linux

package app

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestInstalledConfigLockSerializesIndependentLinuxRoots(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Getuid())
	policies := config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: securefs.LinuxExactPermissions(uid, fs.FileMode(0o700))},
		ConfigFile: securefs.FilePolicy{
			Presence: securefs.Optional,
			Kind:     securefs.RegularFile,
			Access:   securefs.LinuxExactPermissions(uid, fs.FileMode(0o600)),
			MaxBytes: 1,
		},
	}
	filesystem := installedConfigFilesystem{
		securityPolicies:      func() (config.SecurityPolicies, error) { return policies, nil },
		checkoutIdentity:      func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: securefs.ValidateMutableOutput,
	}
	assertRealInstalledConfigLockSerializes(t, filepath.Join(directory, "config.yaml"), filesystem)
}
