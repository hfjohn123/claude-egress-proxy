package app

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/hfjohn123/claude-egress-proxy/internal/admintoken"
	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

// NewAdminTokenHandler constructs the explicit admin-token rotate command.
// It is kept injectable until the serve/startup dependency graph owns the
// state root (the command itself never shares credential state).
func NewAdminTokenHandler() Handler {
	return newAdminTokenHandler(adminTokenDependencies{
		defaults: config.PlatformDefaults,
		load:     func(path string) (adminTokenLoaded, error) { return config.Load(path, config.ValidatePure) },
		security: config.PlatformSecurityPolicies,
		checkout: config.CheckoutIdentity,
	})
}

type adminTokenLoaded interface {
	Config() config.Config
	Close() error
}
type adminTokenDependencies struct {
	defaults func() (config.DefaultPaths, error)
	load     func(string) (adminTokenLoaded, error)
	security func() (config.SecurityPolicies, error)
	checkout func() (securefs.Identity, error)
}

func newAdminTokenHandler(deps adminTokenDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.defaults == nil || deps.load == nil || deps.security == nil || deps.checkout == nil {
			return initFailure(contract.D010)
		}
		path := invocation.ConfigPath
		if path == "" {
			d, err := deps.defaults()
			if err != nil {
				return initFailure(contract.D010)
			}
			path = d.Config
		}
		loaded, err := deps.load(path)
		if err != nil {
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		policies, err := deps.security()
		if err != nil {
			return initFailure(contract.D010)
		}
		checkout, err := deps.checkout()
		if err != nil {
			return initFailure(contract.D004)
		}
		rootPolicy := policies.StateDirectory
		rootPolicy.ExcludedAncestor = checkout
		root, err := securefs.OpenMutableRoot(loaded.Config().StateRootPath(), rootPolicy)
		if err != nil {
			return initFailure(adminTokenCode(err))
		}
		defer root.Close()
		p := policies.ConfigFile
		p.Presence, p.Kind, p.MaxBytes = securefs.Optional, securefs.RegularFile, int64(contract.V1().StoreBytes)
		store, err := admintoken.OpenStore(root, loaded.Config().InstanceID(), p)
		if err != nil {
			return initFailure(contract.D006)
		}
		secret, err := store.Rotate(ctx)
		if err != nil {
			return initFailure(contract.D006)
		}
		return Result{ExitCode: 0, Stdout: []byte("secret=" + base64.RawURLEncoding.EncodeToString(secret[:]) + "\nstate=rotated\n"), OutputFailed: []byte("admin-token error: output_failed\n")}
	}
}

func adminTokenCode(err error) contract.DiagnosticCode {
	if errors.Is(err, securefs.ErrUnsupportedInspection) {
		return contract.D010
	}
	if errors.Is(err, securefs.ErrPermissions) || errors.Is(err, securefs.ErrIdentityChanged) || errors.Is(err, securefs.ErrUnsafePath) || securefs.IsPathSecurityFailure(err) {
		return contract.D004
	}
	return contract.D006
}
