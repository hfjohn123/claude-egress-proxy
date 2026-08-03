// Package app dispatches a parsed invocation to the injected command handlers.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

type Result struct {
	ExitCode                     int
	Stdout, Stderr, OutputFailed []byte
}

type Handler func(context.Context, cli.Invocation) Result

type Dependencies struct {
	Serve, Init, Credential, AdminToken         Handler
	PAC, CheckConfig, CheckHealth, CheckNetwork Handler
	Service                                     Handler
}

type InitDependencies struct {
	Entropy  io.Reader
	Defaults func() (config.DefaultPaths, error)
	Security func() (config.SecurityPolicies, error)
	Checkout securefs.Identity
}

func NewInitHandler(deps InitDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.Entropy == nil || deps.Defaults == nil || deps.Security == nil {
			return initFailure(contract.D010)
		}
		defaults, err := deps.Defaults()
		if err != nil {
			return initFailure(contract.D010)
		}
		policies, err := deps.Security()
		if err != nil {
			return initFailure(contract.D010)
		}
		configPath := invocation.ConfigPath
		if configPath == "" {
			configPath = defaults.Config
		}
		statePath := invocation.StateRoot
		if statePath == "" {
			statePath = defaults.StateRoot
		}
		configDir := filepath.Dir(configPath)
		same := configDir == statePath || runtime.GOOS == "windows" && strings.EqualFold(configDir, statePath)
		if !same && runtime.GOOS == "windows" {
			same, err = sameWindowsDirectorySelection(configDir, statePath, policies.ConfigContainer, policies.StateContainer, deps.Checkout)
			if err != nil {
				return initFailure(initPathCode(err))
			}
		}
		if same && !securefs.PermissionsEqual(policies.ConfigDirectory.Access, policies.StateDirectory.Access) {
			return initFailure(contract.D004)
		}
		configRoot, err := ensureCreateRoot(configDir, policies.ConfigContainer, policies.ConfigDirectory, deps.Checkout)
		if err != nil {
			return initFailure(initPathCode(err))
		}
		defer configRoot.Close()
		absent := policies.ConfigFile
		absent.Presence = securefs.MustBeAbsent
		absent.Kind = securefs.RegularFile
		if _, err := configRoot.Inspect(filepath.Base(configPath), absent); err != nil {
			if errors.Is(err, securefs.ErrAlreadyExists) {
				return initFailure(contract.D001)
			}
			return initFailure(initPathCode(err))
		}
		var stateRoot securefs.CreateCapableRoot
		if same {
			stateRoot = configRoot
		} else {
			stateRoot, err = ensureCreateRoot(statePath, policies.StateContainer, policies.StateDirectory, deps.Checkout)
			if err != nil {
				return initFailure(initPathCode(err))
			}
			defer stateRoot.Close()
			if stateRoot.Identity() == configRoot.Identity() && !securefs.PermissionsEqual(policies.ConfigDirectory.Access, policies.StateDirectory.Access) {
				return initFailure(contract.D004)
			}
		}
		if err := stateRoot.RecheckIdentity(); err != nil {
			return initFailure(contract.D004)
		}
		if err := configRoot.RecheckIdentity(); err != nil {
			return initFailure(contract.D004)
		}
		if _, err := configRoot.Inspect(filepath.Base(configPath), absent); err != nil {
			if errors.Is(err, securefs.ErrAlreadyExists) {
				return initFailure(contract.D001)
			}
			return initFailure(initPathCode(err))
		}
		var id [16]byte
		if _, err := io.ReadFull(deps.Entropy, id[:]); err != nil {
			return initFailure(contract.D010)
		}
		data := config.RenderExample(id, statePath)
		boundary, err := securefs.CreateFileOnce(ctx, configRoot, filepath.Base(configPath), data, absent)
		if err != nil {
			if errors.Is(err, securefs.ErrAlreadyExists) {
				return initFailure(contract.D001)
			}
			if errors.Is(err, securefs.ErrPermissions) || errors.Is(err, securefs.ErrIdentityChanged) || errors.Is(err, securefs.ErrUnsafePath) {
				return initFailure(contract.D004)
			}
			return initFailure(contract.D010)
		}
		if !boundary.NamespacePublished || !boundary.TargetDurable {
			return initFailure(contract.D010)
		}
		return Result{ExitCode: 0}
	}
}

func sameWindowsDirectorySelection(a, b string, aPolicy, bPolicy securefs.RootPolicy, checkout securefs.Identity) (bool, error) {
	if !strings.EqualFold(filepath.Base(a), filepath.Base(b)) {
		return false, nil
	}
	aPolicy.ExcludedAncestor = checkout
	bPolicy.ExcludedAncestor = checkout
	aroot, err := securefs.OpenCreateCapableRoot(filepath.Dir(a), aPolicy)
	if err != nil {
		return false, err
	}
	defer aroot.Close()
	broot, err := securefs.OpenCreateCapableRoot(filepath.Dir(b), bPolicy)
	if err != nil {
		return false, err
	}
	defer broot.Close()
	return aroot.Identity() == broot.Identity(), nil
}

func ensureCreateRoot(path string, containerPolicy, directoryPolicy securefs.RootPolicy, checkout securefs.Identity) (securefs.CreateCapableRoot, error) {
	parentPath, name := filepath.Dir(path), filepath.Base(path)
	containerPolicy.ExcludedAncestor = checkout
	parent, err := securefs.OpenCreateCapableRoot(parentPath, containerPolicy)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	state, err := parent.Inspect(name, securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.Directory, Access: directoryPolicy.Access})
	if err != nil {
		return nil, err
	}
	if state.Present {
		directoryPolicy.ExcludedAncestor = checkout
		opened, err := securefs.OpenCreateCapableRoot(path, directoryPolicy)
		if err != nil {
			return nil, err
		}
		if opened.Identity() != state.Identity {
			_ = opened.Close()
			return nil, securefs.ErrIdentityChanged
		}
		return opened, nil
	}
	created, err := securefs.CreateRoot(parent, name, directoryPolicy)
	if errors.Is(err, securefs.ErrAlreadyExists) {
		directoryPolicy.ExcludedAncestor = checkout
		return securefs.OpenCreateCapableRoot(path, directoryPolicy)
	}
	return created, err
}
func initPathCode(err error) contract.DiagnosticCode {
	if errors.Is(err, securefs.ErrUnsupportedInspection) {
		return contract.D010
	}
	if errors.Is(err, securefs.ErrAlreadyExists) || errors.Is(err, securefs.ErrNotFound) {
		return contract.D001
	}
	return contract.D004
}
func initFailure(code contract.DiagnosticCode) Result {
	return Result{ExitCode: 1, Stderr: contract.Fatal(code)}
}

func ProductionDependencies() Dependencies {
	checkout, err := config.CheckoutIdentity()
	if err != nil {
		return Dependencies{Init: func(context.Context, cli.Invocation) Result { return initFailure(contract.D004) }}
	}
	return Dependencies{Init: NewInitHandler(InitDependencies{Entropy: rand.Reader, Defaults: config.PlatformDefaults, Security: config.PlatformSecurityPolicies, Checkout: checkout})}
}

func (d Dependencies) handler(command cli.Command) Handler {
	switch command {
	case cli.Serve:
		return d.Serve
	case cli.Init:
		return d.Init
	case cli.CredentialAdd, cli.CredentialRevoke, cli.CredentialPurge, cli.CredentialList:
		return d.Credential
	case cli.AdminTokenRotate:
		return d.AdminToken
	case cli.PAC:
		return d.PAC
	case cli.CheckConfig:
		return d.CheckConfig
	case cli.CheckHealth:
		return d.CheckHealth
	case cli.CheckNetwork:
		return d.CheckNetwork
	case cli.Service:
		return d.Service
	default:
		panic("invalid parsed command")
	}
}
