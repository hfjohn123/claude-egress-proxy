//go:build windows

package config

import (
	"path/filepath"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"golang.org/x/sys/windows"
)

var programDataKnownFolder = func() (string, error) {
	return windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
}

func PlatformDefaults() (DefaultPaths, error) {
	base, err := programDataKnownFolder()
	if err != nil || base == "" {
		return DefaultPaths{}, ErrPlatform
	}
	dir := filepath.Join(base, "ClaudeEgressProxy")
	return DefaultPaths{Config: filepath.Join(dir, "config.yaml"), StateRoot: dir}, nil
}

func PlatformSecurityPolicies() (SecurityPolicies, error) {
	service, _, _, err := windows.LookupSID("", "claude-egress-proxy")
	if err != nil || service == nil || !service.IsValid() {
		return SecurityPolicies{}, ErrPlatform
	}
	admin := "S-1-5-32-544"
	serviceSID := service.String()
	const fileAllAccess = uint32(windows.STANDARD_RIGHTS_REQUIRED | windows.SYNCHRONIZE | 0x1ff)
	directoryMask := uint32(windows.FILE_LIST_DIRECTORY | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_READ_ATTRIBUTES | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_TRAVERSE | windows.READ_CONTROL | windows.SYNCHRONIZE)
	dir, err := securefs.WindowsExactPermissions([]securefs.WindowsGrant{{SID: admin, Access: fileAllAccess}, {SID: serviceSID, Access: directoryMask}})
	if err != nil {
		return SecurityPolicies{}, ErrPlatform
	}
	configFile, err := securefs.WindowsExactPermissions([]securefs.WindowsGrant{{SID: admin, Access: fileAllAccess}, {SID: serviceSID, Access: windows.FILE_GENERIC_READ}})
	if err != nil {
		return SecurityPolicies{}, ErrPlatform
	}
	return SecurityPolicies{ConfigContainer: securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()}, ConfigDirectory: securefs.RootPolicy{Access: dir}, ConfigFile: securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: configFile, MaxBytes: int64(contract.V1().ConfigBytes)}, StateContainer: securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()}, StateDirectory: securefs.RootPolicy{Access: dir}}, nil
}
