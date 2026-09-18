package app

import (
	"io/fs"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestAdminTokenUsesStateFilePolicy(t *testing.T) {
	configAccess := securefs.IdentityOnlyPermissions()
	stateAccess := securefs.LinuxExactPermissions(42, fs.FileMode(0o600))
	policies := config.SecurityPolicies{
		ConfigFile: securefs.FilePolicy{Access: configAccess},
		StateFile:  securefs.FilePolicy{Access: stateAccess},
	}

	got := adminTokenArtifactPolicy(policies)
	if !securefs.PermissionsEqual(got.Access, stateAccess) {
		t.Fatal("admin token policy did not preserve StateFile access policy")
	}
	if got.Presence != securefs.Optional || got.Kind != securefs.RegularFile || got.MaxBytes != int64(contract.V1().StoreBytes) {
		t.Fatalf("admin token policy shape = %+v", got)
	}
}
