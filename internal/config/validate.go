package config

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admintoken"
	"github.com/hfjohn123/claude-egress-proxy/internal/certmgr"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
)

var (
	ErrRead                  = errors.New("configuration read")
	ErrSyntax                = errors.New("configuration syntax")
	ErrUnknownField          = errors.New("unknown configuration field")
	ErrValue                 = errors.New("configuration value")
	ErrPathSecurity          = errors.New("configuration path security")
	ErrPlatform              = errors.New("configuration platform")
	ErrValidationUnavailable = errors.New("configuration validation unavailable")
)

type Error struct {
	cause error
	code  contract.DiagnosticCode
}

func (e *Error) Error() string                              { return fmt.Sprintf("configuration error %03d", e.code) }
func (e *Error) Unwrap() error                              { return e.cause }
func (e *Error) DiagnosticCode() contract.DiagnosticCode    { return e.code }
func typed(cause error, code contract.DiagnosticCode) error { return &Error{cause: cause, code: code} }

type DefaultPaths struct{ Config, StateRoot string }
type SecurityPolicies struct {
	ConfigContainer, ConfigDirectory securefs.RootPolicy
	ConfigFile                       securefs.FilePolicy
	StateContainer, StateDirectory   securefs.RootPolicy
	StateFile                        securefs.FilePolicy
}
type Loader struct {
	CheckoutIdentity securefs.Identity
	Policies         SecurityPolicies
}

type Loaded struct {
	mu             sync.RWMutex
	closed         bool
	config         Config
	configPath     string
	configIdentity securefs.Identity
	statePath      string
	stateIdentity  securefs.Identity
	configParent   securefs.Root
	stateRoot      securefs.Root
	mode           ValidationMode
}
type borrowedRoot struct{ owner *Loaded }

func (l *Loaded) Config() Config                       { l.mu.RLock(); defer l.mu.RUnlock(); return cloneConfig(l.config) }
func (l *Loaded) ConfigPath() string                   { return l.configPath }
func (l *Loaded) ConfigIdentity() securefs.Identity    { return l.configIdentity }
func (l *Loaded) StateRootPath() string                { return l.statePath }
func (l *Loaded) StateRootIdentity() securefs.Identity { return l.stateIdentity }
func (l *Loaded) StateRoot() securefs.ReadRoot         { return &borrowedRoot{owner: l} }
func (l *Loaded) ValidationMode() ValidationMode       { return l.mode }
func (l *Loaded) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	err1 := l.configParent.Close()
	err2 := l.stateRoot.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
func (b *borrowedRoot) Identity() securefs.Identity {
	b.owner.mu.RLock()
	defer b.owner.mu.RUnlock()
	if b.owner.closed {
		return securefs.Identity{}
	}
	return b.owner.stateRoot.Identity()
}
func (b *borrowedRoot) RecheckIdentity() error {
	b.owner.mu.RLock()
	defer b.owner.mu.RUnlock()
	if b.owner.closed {
		return securefs.ErrClosed
	}
	return b.owner.stateRoot.RecheckIdentity()
}
func (b *borrowedRoot) Inspect(n string, p securefs.FilePolicy) (securefs.FileState, error) {
	b.owner.mu.RLock()
	defer b.owner.mu.RUnlock()
	if b.owner.closed {
		return securefs.FileState{}, securefs.ErrClosed
	}
	return b.owner.stateRoot.Inspect(n, p)
}
func (b *borrowedRoot) ReadFile(n string, p securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	b.owner.mu.RLock()
	defer b.owner.mu.RUnlock()
	if b.owner.closed {
		return nil, securefs.FileState{}, securefs.ErrClosed
	}
	return b.owner.stateRoot.ReadFile(n, p)
}

func Load(path string, mode ValidationMode) (*Loaded, error) {
	if mode != ValidatePure && mode != ValidateOperational && mode != ValidatePreServe {
		return nil, typed(ErrValue, contract.D003)
	}
	policies, err := PlatformSecurityPolicies()
	if err != nil {
		return nil, typed(ErrPlatform, contract.D010)
	}
	checkout, err := checkoutIdentity()
	if err != nil {
		return nil, typed(ErrPathSecurity, contract.D004)
	}
	return (Loader{CheckoutIdentity: checkout, Policies: policies}).Load(path, mode)
}

func (loader Loader) Load(path string, mode ValidationMode) (*Loaded, error) {
	switch mode {
	case ValidatePure, ValidateOperational, ValidatePreServe:
	default:
		return nil, typed(ErrValue, contract.D003)
	}
	policy := loader.Policies.ConfigFile
	policy.Presence = securefs.Required
	policy.Kind = securefs.RegularFile
	policy.MaxBytes = int64(contract.V1().ConfigBytes)
	parentPolicy := loader.Policies.ConfigDirectory
	parentPolicy.ExcludedAncestor = loader.CheckoutIdentity
	parent, _, state, err := securefs.ValidateOutput(path, loader.CheckoutIdentity, parentPolicy, policy)
	if err != nil {
		return nil, mapConfigRead(err)
	}
	data, readState, err := parent.ReadFile(filepath.Base(path), policy)
	if err != nil {
		_ = parent.Close()
		return nil, mapConfigRead(err)
	}
	if readState.Identity != state.Identity {
		_ = parent.Close()
		return nil, typed(ErrPathSecurity, contract.D004)
	}
	cfg, err := Decode(data)
	if err != nil {
		_ = parent.Close()
		if errors.Is(err, ErrValue) {
			return nil, typed(ErrValue, contract.D003)
		}
		return nil, typed(ErrSyntax, contract.D002)
	}
	rootPolicy := loader.Policies.StateDirectory
	rootPolicy.ExcludedAncestor = loader.CheckoutIdentity
	stateRoot, err := securefs.OpenRoot(cfg.StateRootPath(), rootPolicy)
	if err != nil {
		_ = parent.Close()
		if errors.Is(err, securefs.ErrUnsupportedInspection) {
			return nil, typed(ErrPlatform, contract.D010)
		}
		return nil, typed(ErrPathSecurity, contract.D004)
	}
	loaded := &Loaded{config: cfg, configPath: path, configIdentity: state.Identity, statePath: cfg.StateRootPath(), stateIdentity: stateRoot.Identity(), configParent: parent, stateRoot: stateRoot, mode: mode}
	if mode != ValidatePure {
		if err := validateOperational(loaded, loader.Policies); err != nil {
			_ = loaded.Close()
			return nil, err
		}
	}
	return loaded, nil
}

func validateOperational(loaded *Loaded, policies SecurityPolicies) error {
	cfg := loaded.Config()
	identityPolicy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.IdentityOnlyPermissions(), MaxBytes: int64(contract.V1().StoreBytes)}
	storeState, storeErr := loaded.StateRoot().Inspect("credentials.json", identityPolicy)
	lockState, lockErr := loaded.StateRoot().Inspect("credentials.lock", identityPolicy)
	if storeErr != nil || lockErr != nil {
		return typed(ErrValue, contract.D005)
	}
	artifactPolicy := policies.StateFile
	if securefs.PermissionsEqual(artifactPolicy.Access, securefs.PermissionPolicy{}) {
		artifactPolicy.Access = securefs.IdentityOnlyPermissions()
	}
	artifactPolicy.Presence, artifactPolicy.Kind, artifactPolicy.MaxBytes = securefs.Optional, securefs.RegularFile, int64(contract.V1().StoreBytes)
	if storeState.Present || lockState.Present {
		inspector, err := credential.OpenInspector(loaded.StateRoot(), cfg.InstanceID(), artifactPolicy)
		if err != nil {
			return typed(ErrValue, contract.D005)
		}
		inspection, err := inspector.Inspect(context.Background(), credential.ValidateOnly)
		if err != nil || inspection.State != credential.StoreCoherent && inspection.State != credential.StoreSuccessor {
			return typed(ErrValue, contract.D005)
		}
	}
	if _, err := admintoken.LoadVerifier(context.Background(), loaded.StateRoot(), cfg.InstanceID(), artifactPolicy, cfg.Metrics().Enabled()); err != nil {
		return typed(ErrValue, contract.D006)
	}
	if cfg.TLS().Mode() == TLSSupplied {
		filePolicy := artifactPolicy
		filePolicy.Presence = securefs.Required
		filePolicy.MaxBytes = 1 << 20
		if _, err := certmgr.NewSupplied(certmgr.SuppliedConfig{Hostname: cfg.TLS().Hostname(), CertificateFile: cfg.TLS().CertificateFile(), PrivateKeyFile: cfg.TLS().PrivateKeyFile(), RootPolicy: securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()}, FilePolicy: filePolicy}); err != nil {
			return typed(ErrValue, contract.D007)
		}
	}
	if cfg.TLS().Mode() == TLSACME {
		store := certmgr.ACMEStore{Root: loaded.StateRoot(), Name: "acme.json", Policy: artifactPolicy}
		if _, err := store.Load(); err != nil && !errors.Is(err, certmgr.ErrACMEStateAbsent) {
			return typed(ErrValue, contract.D007)
		}
	}
	if source, ok := cfg.OutboundSourceIPv4(); ok {
		if err := (&network.SourceMonitor{Configured: source}).Recheck(context.Background()); err != nil {
			return typed(ErrValue, contract.D011)
		}
	}
	if cfg.Logging().Sink() == LogSinkFile {
		root, err := securefs.OpenRoot(filepath.Dir(cfg.Logging().FilePath()), policies.StateDirectory)
		if err != nil {
			return typed(ErrValue, contract.D008)
		}
		defer root.Close()
		filePolicy := policies.StateFile
		filePolicy.Presence, filePolicy.Kind, filePolicy.MaxBytes = securefs.Optional, securefs.RegularFile, 10_485_760
		if err := telemetry.ValidateFileSink(context.Background(), root, filepath.Base(cfg.Logging().FilePath()), filePolicy, telemetry.CheckOnly); err != nil && !errors.Is(err, telemetry.ErrRepairRequired) {
			return typed(ErrValue, contract.D008)
		}
	}
	return nil
}

func mapConfigRead(err error) error {
	if errors.Is(err, securefs.ErrUnsupportedInspection) {
		return typed(ErrPlatform, contract.D010)
	}
	if errors.Is(err, securefs.ErrPermissions) || errors.Is(err, securefs.ErrIdentityChanged) {
		return typed(ErrPathSecurity, contract.D004)
	}
	if securefs.IsPathSecurityFailure(err) {
		return typed(ErrPathSecurity, contract.D004)
	}
	return typed(ErrRead, contract.D001)
}

func validateRaw(r rawConfig) (Config, error) {
	bad := func() (Config, error) { return Config{}, fmt.Errorf("%w", ErrValue) }
	if r.FormatVersion == nil || *r.FormatVersion != 1 || r.InstanceID == "" || !cleanAbsolute(r.StateRoot) || r.TLS == nil {
		return bad()
	}
	if len(r.InstanceID) != 32 || strings.ToLower(r.InstanceID) != r.InstanceID {
		return bad()
	}
	decoded, err := hex.DecodeString(r.InstanceID)
	if err != nil || len(decoded) != 16 {
		return bad()
	}
	var c Config
	c.formatVersion = 1
	copy(c.instanceID[:], decoded)
	c.stateRoot = r.StateRoot
	addresses := []string{"0.0.0.0:443"}
	if r.PublicListener != nil && r.PublicListener.Addresses != nil {
		addresses = r.PublicListener.Addresses
	}
	if len(addresses) < 1 || len(addresses) > 2 {
		return bad()
	}
	seenAP := map[netip.AddrPort]bool{}
	var port uint16
	loop := -1
	for _, text := range addresses {
		ap, e := netip.ParseAddrPort(text)
		if e != nil || ap.String() != text || ap.Port() == 0 || ap.Addr().Zone() != "" || seenAP[ap] {
			return bad()
		}
		seenAP[ap] = true
		if port == 0 {
			port = ap.Port()
		} else if port != ap.Port() {
			return bad()
		}
		current := 0
		if ap.Addr().IsLoopback() {
			current = 1
		}
		if loop < 0 {
			loop = current
		} else if loop != current {
			return bad()
		}
		c.publicListener.addresses = append(c.publicListener.addresses, ap)
	}
	if r.PublicListener != nil {
		c.publicListener.pacEnabled = r.PublicListener.PACEnabled
	}
	if r.AdminListener != nil {
		c.adminListener.enabled = r.AdminListener.Enabled
		if r.AdminListener.Enabled {
			a := ""
			if r.AdminListener.Address == nil {
				a = "127.0.0.1:9090"
			} else {
				a = *r.AdminListener.Address
			}
			ap, e := netip.ParseAddrPort(a)
			if e != nil || ap.String() != a || ap.Port() == 0 || !(ap.Addr() == netip.MustParseAddr("127.0.0.1") || ap.Addr() == netip.IPv6Loopback()) {
				return bad()
			}
			c.adminListener.address = ap
			c.adminListener.hasAddress = true
		} else if r.AdminListener.Address != nil {
			return bad()
		}
	}
	switch r.TLS.Mode {
	case "acme":
		c.tls.mode = TLSACME
	case "supplied":
		c.tls.mode = TLSSupplied
	case "insecure_loopback":
		c.tls.mode = TLSInsecureLoopback
	default:
		return bad()
	}
	if r.TLS.Hostname != nil {
		c.tls.hostname = *r.TLS.Hostname
	}
	if r.TLS.CertificateFile != nil {
		c.tls.certificateFile = *r.TLS.CertificateFile
	}
	if r.TLS.PrivateKeyFile != nil {
		c.tls.privateKeyFile = *r.TLS.PrivateKeyFile
	}
	switch c.tls.mode {
	case TLSACME:
		if r.TLS.Hostname == nil || !validHostname(c.tls.hostname) || r.TLS.CertificateFile != nil || r.TLS.PrivateKeyFile != nil {
			return bad()
		}
	case TLSSupplied:
		if r.TLS.Hostname == nil || r.TLS.CertificateFile == nil || r.TLS.PrivateKeyFile == nil || !validHostname(c.tls.hostname) || !cleanAbsolute(c.tls.certificateFile) || !cleanAbsolute(c.tls.privateKeyFile) {
			return bad()
		}
	case TLSInsecureLoopback:
		if r.TLS.Hostname != nil || r.TLS.CertificateFile != nil || r.TLS.PrivateKeyFile != nil || loop != 1 {
			return bad()
		}
	}
	c.resolver.mode = ResolverSystem
	if r.Resolver != nil {
		mode := "system"
		if r.Resolver.Mode != nil {
			mode = *r.Resolver.Mode
		}
		switch mode {
		case "system":
			if r.Resolver.Address != nil {
				return bad()
			}
		case "explicit":
			if r.Resolver.Address == nil {
				return bad()
			}
			ap, e := netip.ParseAddrPort(*r.Resolver.Address)
			if e != nil || ap.String() != *r.Resolver.Address || ap.Port() == 0 || ap.Addr().Zone() != "" {
				return bad()
			}
			c.resolver.mode = ResolverExplicit
			c.resolver.address = ap
			c.resolver.hasAddress = true
		default:
			return bad()
		}
	}
	if r.OutboundSourceIPv4 != nil {
		a, e := netip.ParseAddr(*r.OutboundSourceIPv4)
		if e != nil || a.String() != *r.OutboundSourceIPv4 || !globalIPv4(a) {
			return bad()
		}
		c.outboundSource = a
	}
	if len(r.PublicSelfIPv4s) > 8 {
		return bad()
	}
	seenIP := map[netip.Addr]bool{}
	for _, text := range r.PublicSelfIPv4s {
		a, e := netip.ParseAddr(text)
		if e != nil || a.String() != text || !globalIPv4(a) || seenIP[a] {
			return bad()
		}
		seenIP[a] = true
		c.publicSelf = append(c.publicSelf, a)
	}
	capacity := int64(contract.V1().PerDeviceCapacityDefault)
	if r.PerDeviceCapacity != nil {
		capacity = *r.PerDeviceCapacity
	}
	if capacity < int64(contract.V1().PerDeviceCapacityMin) || capacity > int64(contract.V1().PerDeviceCapacityMax) {
		return bad()
	}
	c.perDeviceCapacity = uint32(capacity)
	if r.AbsoluteTunnelLifetime != nil {
		if *r.AbsoluteTunnelLifetime != "disabled" {
			n, ok := canonicalDuration(*r.AbsoluteTunnelLifetime, 'h')
			if !ok || n < 1 || n > 168 {
				return bad()
			}
			c.absoluteTunnelLifetime = time.Duration(n) * time.Hour
			c.absoluteTunnelLifetimeEnabled = true
		}
	}
	drain := "20s"
	if r.GracefulShutdownDrain != nil {
		drain = *r.GracefulShutdownDrain
	}
	n, ok := canonicalDuration(drain, 's')
	if !ok || n < 5 || n > 20 {
		return bad()
	}
	c.gracefulShutdownDrain = time.Duration(n) * time.Second
	c.destination.profile = ProfileCode
	if r.Destination != nil {
		profile := "code"
		if r.Destination.Profile != nil {
			profile = *r.Destination.Profile
		}
		switch profile {
		case "code":
		case "web-desktop":
			c.destination.profile = ProfileWebDesktop
		case "all":
			c.destination.profile = ProfileAll
		default:
			return bad()
		}
		if len(r.Destination.ExactHosts)+len(r.Destination.Suffixes) > contract.V1().CustomRuleLimit {
			return bad()
		}
		for _, s := range append(append([]string{}, r.Destination.ExactHosts...), r.Destination.Suffixes...) {
			if s == "" {
				return bad()
			}
		}
		c.destination.exactHosts = append([]string(nil), r.Destination.ExactHosts...)
		c.destination.suffixes = append([]string(nil), r.Destination.Suffixes...)
		c.destination.dangerousCustomSuffixes = r.Destination.DangerousCustomSuffixes
	}
	profileName := "code"
	switch c.destination.profile {
	case ProfileWebDesktop:
		profileName = "web-desktop"
	case ProfileAll:
		profileName = "all"
	}
	if _, err := policy.Load(profileName, policy.CustomRules{ExactHosts: c.destination.exactHosts, Suffixes: c.destination.suffixes, DangerousCustomSuffixes: c.destination.dangerousCustomSuffixes}); err != nil {
		return bad()
	}
	c.logging.sink = LogSinkDefault
	if r.Logging != nil {
		sink := "default"
		if r.Logging.Sink != nil {
			sink = *r.Logging.Sink
		}
		switch sink {
		case "default":
			if r.Logging.FilePath != nil {
				return bad()
			}
		case "file":
			if r.Logging.FilePath == nil || !cleanAbsolute(*r.Logging.FilePath) {
				return bad()
			}
			c.logging.sink = LogSinkFile
			c.logging.filePath = *r.Logging.FilePath
		default:
			return bad()
		}
		c.logging.sensitiveMetadata = r.Logging.SensitiveMetadata
	}
	if r.Metrics != nil {
		c.metrics.enabled = r.Metrics.Enabled
		if c.metrics.enabled && !c.adminListener.enabled {
			return bad()
		}
	}
	return c, nil
}

func cleanAbsolute(path string) bool {
	return path != "" && !strings.ContainsRune(path, '\x00') && filepath.IsAbs(path) && filepath.Clean(path) == path
}
func canonicalDuration(s string, suffix byte) (int, bool) {
	if len(s) < 2 || len(s) > 4 || s[len(s)-1] != suffix || s[0] == '0' {
		return 0, false
	}
	n := 0
	for _, b := range []byte(s[:len(s)-1]) {
		if b < '0' || b > '9' {
			return 0, false
		}
		n = n*10 + int(b-'0')
	}
	return n, true
}
func validHostname(s string) bool {
	if len(s) < 3 || len(s) > 253 || strings.ToLower(s) != s || strings.HasSuffix(s, ".") {
		return false
	}
	if _, e := netip.ParseAddr(s); e == nil {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || !alnum(l[0]) || !alnum(l[len(l)-1]) {
			return false
		}
		for i := range l {
			if !alnum(l[i]) && l[i] != '-' {
				return false
			}
		}
	}
	return true
}
func alnum(b byte) bool { return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' }
func globalIPv4(a netip.Addr) bool {
	return policy.Classify(a) == policy.AddressGlobalIPv4
}
