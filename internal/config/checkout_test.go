package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestCheckoutIdentityUsesSourceRootAboveBinAndSiblingOutputs(t *testing.T) {
	checkout := t.TempDir()
	for _, dir := range []string{filepath.Join(checkout, "internal", "config"), filepath.Join(checkout, "bin"), filepath.Join(checkout, "state"), filepath.Join(checkout, "cmd", "generated")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(checkout, "internal", "config", "checkout.go")
	executable := filepath.Join(checkout, "bin", "claude-egress-proxy.exe")
	id, err := checkoutIdentityFromPaths(source, executable)
	if err != nil {
		t.Fatal(err)
	}
	policy := securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions(), ExcludedAncestor: id}
	for _, outputParent := range []string{filepath.Join(checkout, "state"), filepath.Join(checkout, "cmd", "generated")} {
		if root, err := securefs.OpenRoot(outputParent, policy); !errors.Is(err, securefs.ErrUnsafePath) {
			if root != nil {
				_ = root.Close()
			}
			t.Fatalf("OpenRoot(%q) error = %v, want checkout exclusion", outputParent, err)
		}
	}
}

func TestCheckoutIdentityFallsBackForTrimmedOrMissingSourceMetadata(t *testing.T) {
	install := t.TempDir()
	executable := filepath.Join(install, "claude-egress-proxy.exe")
	for _, source := range []string{"github.com/hfjohn123/claude-egress-proxy/internal/config/checkout.go", filepath.Join(t.TempDir(), "missing", "internal", "config", "checkout.go")} {
		id, err := checkoutIdentityFromPaths(source, executable)
		if err != nil {
			t.Fatalf("checkoutIdentityFromPaths(%q) = %v", source, err)
		}
		root, err := securefs.OpenRoot(install, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
		if err != nil {
			t.Fatal(err)
		}
		want := root.Identity()
		_ = root.Close()
		if id != want {
			t.Fatalf("fallback identity differs from executable directory")
		}
	}
}

func TestCheckoutIdentityFailsClosedWithoutReliableAnchor(t *testing.T) {
	if _, err := checkoutIdentityFromPaths("internal/config/checkout.go", "claude-egress-proxy.exe"); err == nil {
		t.Fatal("relative source and executable produced an anchor")
	}
}
