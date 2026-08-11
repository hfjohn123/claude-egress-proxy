// Package app dispatches a parsed invocation to the injected command handlers.
package app

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	checkpkg "github.com/hfjohn123/claude-egress-proxy/internal/check"
	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/pac"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
)

type Result struct {
	ExitCode                     int
	Stdout, Stderr, OutputFailed []byte
}

type Handler func(context.Context, cli.Invocation) Result

type Dependencies struct {
	Serve, Init, Credential, AdminToken Handler
	PAC, ConfigApply, CheckConfig       Handler
	CheckHealth, CheckNetwork           Handler
	Service                             Handler
}

type InitDependencies struct {
	Entropy  io.Reader
	Defaults func() (config.DefaultPaths, error)
	Security func() (config.SecurityPolicies, error)
	Prepare  func(context.Context) (service.Undo, error)
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
		var undo service.Undo
		prepared := false
		if deps.Prepare != nil {
			undo, err = deps.Prepare(ctx)
			if err != nil {
				return initFailure(contract.D010)
			}
			defer func() {
				if !prepared && undo != nil {
					_ = undo(context.WithoutCancel(ctx))
				}
			}()
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
			return initDirectoryFailure(err)
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
				return initDirectoryFailure(err)
			}
			defer stateRoot.Close()
			if stateRoot.Identity() == configRoot.Identity() && !securefs.PermissionsEqual(policies.ConfigDirectory.Access, policies.StateDirectory.Access) {
				return initFailure(contract.D004)
			}
		}
		if err := rejectReservedRuntimeArtifacts(stateRoot); err != nil {
			return initFailure(initPathCode(err))
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
			return initFailure(initCreateFileCode(err))
		}
		if !boundary.NamespacePublished || !boundary.TargetDurable {
			return initFailure(contract.D010)
		}
		prepared = true
		return Result{ExitCode: 0}
	}
}

func initCreateFileCode(err error) contract.DiagnosticCode {
	if errors.Is(err, securefs.ErrPermissions) || errors.Is(err, securefs.ErrIdentityChanged) || errors.Is(err, securefs.ErrUnsafePath) {
		return contract.D004
	}
	return contract.D010
}

func initDirectoryFailure(err error) Result {
	return initFailure(initPathCode(err))
}

var reservedRuntimeArtifacts = [...]string{
	"credentials.json", "credentials.lock", "credentials.json.new",
	"admin-token.json", "admin-token.lock", "admin-token.json.new",
}

func rejectReservedRuntimeArtifacts(root securefs.ReadRoot) error {
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.IdentityOnlyPermissions()}
	for _, name := range reservedRuntimeArtifacts {
		state, err := root.Inspect(name, policy)
		if err != nil {
			return err
		}
		if state.Present {
			return securefs.ErrAlreadyExists
		}
	}
	return nil
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
		return Dependencies{Serve: NewServeHandler(), Init: func(context.Context, cli.Invocation) Result { return initFailure(contract.D004) }, Credential: NewCredentialHandler(), PAC: NewPACHandler(), CheckConfig: NewCheckConfigHandler(), CheckHealth: NewHealthHandler(), CheckNetwork: NewNetworkHandler(), Service: NewServiceHandler()}
	}
	return Dependencies{Serve: NewServeHandler(), Init: NewInitHandler(InitDependencies{Entropy: rand.Reader, Defaults: config.PlatformDefaults, Security: config.PlatformSecurityPolicies, Prepare: func(ctx context.Context) (service.Undo, error) {
		return service.Prepare(ctx, service.NewPlatform(), service.Install)
	}, Checkout: checkout}), Credential: NewCredentialHandler(), AdminToken: NewAdminTokenHandler(), PAC: NewPACHandler(), CheckConfig: NewCheckConfigHandler(), CheckHealth: NewHealthHandler(), CheckNetwork: NewNetworkHandler(), Service: NewServiceHandler()}
}

func NewHealthHandler() Handler { return newHealthHandler(checkpkg.Health) }

func newHealthHandler(probe func(context.Context, string) error) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if probe == nil {
			return Result{ExitCode: 1, Stderr: []byte("health probe failed\n")}
		}
		err := probe(ctx, invocation.HealthAddress)
		if errors.Is(err, checkpkg.ErrInvalidHealthAddress) {
			return Result{ExitCode: 2, Stderr: cli.UsageCheckHealth}
		}
		if err != nil {
			return Result{ExitCode: 1, Stderr: []byte("health probe failed\n")}
		}
		return Result{}
	}
}

type serviceDependencies struct {
	defaults func() (config.DefaultPaths, error)
	load     func(string, config.ValidationMode) (serviceLoaded, error)
	platform func() service.Platform
}

type serviceLoaded interface {
	StateRootPath() string
	Close() error
}

// NewServiceHandler constructs the privileged service command adapter.
func NewServiceHandler() Handler {
	return newServiceHandler(serviceDependencies{
		defaults: config.PlatformDefaults,
		load: func(path string, mode config.ValidationMode) (serviceLoaded, error) {
			return config.Load(path, mode)
		},
		platform: service.NewPlatform,
	})
}

func newServiceHandler(deps serviceDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.defaults == nil || deps.load == nil || deps.platform == nil {
			return initFailure(contract.D010)
		}
		path := invocation.ConfigPath
		if path == "" {
			defaults, err := deps.defaults()
			if err != nil {
				return initFailure(contract.D010)
			}
			path = defaults.Config
		}
		var action service.Action
		switch invocation.ServiceAction {
		case cli.ServiceInstall:
			action = service.Install
		case cli.ServiceUninstall:
			action = service.Uninstall
		case cli.ServiceStart:
			action = service.Start
		case cli.ServiceStop:
			action = service.Stop
		default:
			return initFailure(contract.D003)
		}
		platform := deps.platform()
		undo, err := service.Prepare(ctx, platform, action)
		if err != nil {
			return initFailure(contract.D010)
		}
		committed := false
		defer func() {
			if !committed && undo != nil {
				_ = undo(context.WithoutCancel(ctx))
			}
		}()
		loaded, err := deps.load(path, config.ValidateOperational)
		if err != nil {
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		selection := service.Selection{ConfigPath: path, StateRoot: loaded.StateRootPath()}
		if err := service.Execute(ctx, platform, action, selection); err != nil {
			if errors.Is(err, service.ErrUnsupported) {
				return initFailure(contract.D010)
			}
			return initFailure(contract.D001)
		}
		committed = true
		return Result{}
	}
}

func NewPACHandler() Handler {
	return newPACHandler(pacDependencies{
		defaults:   config.PlatformDefaults,
		load:       func(path string) (pacLoaded, error) { return config.Load(path, config.ValidatePure) },
		policyLoad: policy.Load, render: pac.Render, publish: publishPAC,
	})
}

type checkConfigDependencies struct {
	defaults func() (config.DefaultPaths, error)
	load     func(string, config.ValidationMode) (pacLoaded, error)
}

// NewCheckConfigHandler validates the selected immutable configuration and
// releases its retained filesystem handles before returning.
func NewCheckConfigHandler() Handler {
	return newCheckConfigHandler(checkConfigDependencies{
		defaults: config.PlatformDefaults,
		load:     func(path string, mode config.ValidationMode) (pacLoaded, error) { return config.Load(path, mode) },
	})
}

func newCheckConfigHandler(deps checkConfigDependencies) Handler {
	return func(_ context.Context, invocation cli.Invocation) Result {
		path := invocation.ConfigPath
		if path == "" {
			defaults, err := deps.defaults()
			if err != nil {
				return initFailure(contract.D010)
			}
			path = defaults.Config
		}
		loaded, err := deps.load(path, config.ValidateOperational)
		if err != nil {
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		return Result{Stdout: checkConfigDiagnostics(loaded.Config())}
	}
}

func checkConfigDiagnostics(configuration config.Config) []byte {
	var blocks []string
	if configuration.TLS().Mode() == config.TLSInsecureLoopback {
		blocks = append(blocks, "INSECURE LOOPBACK TEST MODE: Basic proxy credentials are sent in plaintext on\nthis host. Use only a fresh disposable local-test credential; never reuse a\ncredential from a TLS deployment.")
	}
	if configuration.Destination().DangerousCustomSuffixes() {
		suffixes := configuration.Destination().Suffixes()
		for i, suffix := range suffixes {
			normalized, err := policy.NormalizeHostname(suffix)
			if err != nil {
				return nil
			}
			suffixes[i] = normalized
		}
		sort.Strings(suffixes)
		var warning strings.Builder
		warning.WriteString("WARNING: dangerous_custom_suffixes is enabled.\nEach listed suffix permits CONNECT to the suffix itself and every subdomain:")
		for _, suffix := range suffixes {
			warning.WriteString("\n- ")
			warning.WriteString(suffix)
		}
		blocks = append(blocks, warning.String())
	}
	if len(blocks) == 0 {
		return nil
	}
	return []byte(strings.Join(blocks, "\n\n") + "\n")
}

type pacLoaded interface {
	Config() config.Config
	Close() error
}
type pacDependencies struct {
	defaults   func() (config.DefaultPaths, error)
	load       func(string) (pacLoaded, error)
	policyLoad func(string, policy.CustomRules) (policy.Policy, error)
	render     func(policy.Policy, pac.ProxyEndpoint, pac.Visibility) ([]byte, error)
	publish    func(context.Context, cli.Invocation, []byte) error
}

func newPACHandler(deps pacDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		path := invocation.ConfigPath
		if path == "" {
			defaults, err := deps.defaults()
			if err != nil {
				return initFailure(contract.D010)
			}
			path = defaults.Config
		}
		loaded, err := deps.load(path)
		if err != nil {
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		cfg := loaded.Config()
		destination := cfg.Destination()
		profileName := "code"
		if destination.Profile() == config.ProfileWebDesktop {
			profileName = "web-desktop"
		} else if destination.Profile() == config.ProfileAll {
			profileName = "all"
		}
		p, err := deps.policyLoad(profileName, policy.CustomRules{ExactHosts: destination.ExactHosts(), Suffixes: destination.Suffixes(), DangerousCustomSuffixes: destination.DangerousCustomSuffixes()})
		if err != nil {
			return initFailure(contract.D003)
		}
		addresses := cfg.PublicListener().Addresses()
		if len(addresses) == 0 {
			return initFailure(contract.D003)
		}
		var endpoint pac.ProxyEndpoint
		if cfg.TLS().Mode() == config.TLSInsecureLoopback {
			for _, a := range addresses {
				if a.Addr().String() == "127.0.0.1" {
					endpoint, err = pac.LoopbackEndpoint(a.Addr(), a.Port())
					break
				}
			}
			if err != nil || endpoint == (pac.ProxyEndpoint{}) {
				return initFailure(contract.D003)
			}
		} else {
			endpoint, err = pac.RemoteEndpoint(cfg.TLS().Hostname(), addresses[0].Port())
			if err != nil {
				return initFailure(contract.D003)
			}
		}
		body, err := deps.render(p, endpoint, pac.VisibilityLocal)
		if err != nil {
			return initFailure(contract.D003)
		}
		if err := deps.publish(ctx, invocation, body); err != nil {
			return initFailure(pacPathCode(err))
		}
		return Result{ExitCode: 0}
	}
}

func publishPAC(ctx context.Context, invocation cli.Invocation, body []byte) error {
	policies, err := config.PlatformSecurityPolicies()
	if err != nil {
		return err
	}
	output := policies.ConfigFile
	output.Presence = securefs.Optional
	output.Kind = securefs.RegularFile
	output.MaxBytes = int64(contract.V1().PACBytes)
	checkout, err := config.CheckoutIdentity()
	if err != nil {
		return securefs.ErrIdentityChanged
	}
	parent, name, _, err := securefs.ValidateMutableOutput(invocation.PACOutput, checkout, policies.ConfigDirectory, output)
	if err != nil {
		return err
	}
	defer parent.Close()
	boundary, err := parent.PublishOutput(ctx, name, body, output)
	if err != nil {
		return err
	}
	if !boundary.NamespacePublished || !boundary.TargetDurable {
		return securefs.ErrUnsupportedInspection
	}
	return nil
}

func configCode(err error) contract.DiagnosticCode {
	var typed interface {
		DiagnosticCode() contract.DiagnosticCode
	}
	if errors.As(err, &typed) {
		return typed.DiagnosticCode()
	}
	return contract.D001
}
func pacPathCode(err error) contract.DiagnosticCode {
	if errors.Is(err, securefs.ErrUnsupportedInspection) {
		return contract.D010
	}
	if errors.Is(err, securefs.ErrPermissions) || errors.Is(err, securefs.ErrIdentityChanged) || securefs.IsPathSecurityFailure(err) || errors.Is(err, securefs.ErrUnsafePath) {
		return contract.D004
	}
	return contract.D010
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
	case cli.ConfigApply:
		return d.ConfigApply
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
