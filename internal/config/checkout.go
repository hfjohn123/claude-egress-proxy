package config

import (
	"os"
	"path/filepath"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func checkoutIdentity() (securefs.Identity, error) {
	executable, err := os.Executable()
	if err != nil {
		return securefs.Identity{}, err
	}
	root, err := securefs.OpenRoot(filepath.Dir(executable), securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		return securefs.Identity{}, err
	}
	defer root.Close()
	return root.Identity(), nil
}

func CheckoutIdentity() (securefs.Identity, error) { return checkoutIdentity() }
