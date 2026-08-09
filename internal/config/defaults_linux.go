//go:build linux

package config

import (
	"io/fs"
	"os/user"
	"strconv"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func PlatformDefaults() (DefaultPaths, error) {
	return DefaultPaths{Config: "/etc/claude-egress-proxy/config.yaml", StateRoot: "/var/lib/claude-egress-proxy"}, nil
}
func PlatformSecurityPolicies() (SecurityPolicies, error) {
	u, err := user.Lookup("claude-egress-proxy")
	if err != nil {
		return SecurityPolicies{}, ErrPlatform
	}
	uid64, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return SecurityPolicies{}, ErrPlatform
	}
	uid := uint32(uid64)
	rootDir := securefs.LinuxExactPermissions(0, fs.FileMode(0o755))
	configFile := securefs.LinuxExactPermissions(0, fs.FileMode(0o644))
	stateDir := securefs.LinuxExactPermissions(uid, fs.FileMode(0o700))
	stateFile := securefs.LinuxExactPermissions(uid, fs.FileMode(0o600))
	return SecurityPolicies{ConfigContainer: securefs.RootPolicy{Access: rootDir}, ConfigDirectory: securefs.RootPolicy{Access: rootDir}, ConfigFile: securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: configFile, MaxBytes: int64(contract.V1().ConfigBytes)}, StateContainer: securefs.RootPolicy{Access: rootDir}, StateDirectory: securefs.RootPolicy{Access: stateDir}, StateFile: securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: stateFile, MaxBytes: int64(contract.V1().StoreBytes)}}, nil
}
