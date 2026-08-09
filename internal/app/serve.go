package app

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/admintoken"
	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/certmgr"
	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/pac"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/proxy"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/service"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/hfjohn123/claude-egress-proxy/internal/wire"
	"golang.org/x/crypto/acme"
)

type serveLoaded interface{ Close() error }

type serveDependencies struct {
	defaults       func() (config.DefaultPaths, error)
	load           func(string, config.ValidationMode) (serveLoaded, error)
	run            func(context.Context, serveLoaded) error
	startupFailure func(context.Context)
}

type diagnosticError struct{ code contract.DiagnosticCode }

func (e diagnosticError) Error() string                           { return "serve failed" }
func (e diagnosticError) DiagnosticCode() contract.DiagnosticCode { return e.code }

func NewServeHandler() Handler {
	return newServeHandler(serveDependencies{
		defaults: config.PlatformDefaults,
		load: func(path string, mode config.ValidationMode) (serveLoaded, error) {
			return config.Load(path, mode)
		},
		run:            runProductionServe,
		startupFailure: emitDefaultStartupFailure,
	})
}

func newServeHandler(deps serveDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.defaults == nil || deps.load == nil || deps.run == nil {
			return initFailure(contract.D010)
		}
		path := invocation.ConfigPath
		if path == "" {
			defaults, err := deps.defaults()
			if err != nil {
				if deps.startupFailure != nil {
					deps.startupFailure(ctx)
				}
				return initFailure(contract.D010)
			}
			path = defaults.Config
		}
		loaded, err := deps.load(path, config.ValidatePreServe)
		if err != nil {
			if deps.startupFailure != nil {
				deps.startupFailure(ctx)
			}
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		if err := deps.run(ctx, loaded); err != nil {
			var typed interface {
				DiagnosticCode() contract.DiagnosticCode
			}
			if errors.As(err, &typed) {
				return initFailure(typed.DiagnosticCode())
			}
			return initFailure(contract.D010)
		}
		return Result{}
	}
}

func emitDefaultStartupFailure(ctx context.Context) {
	clock := timebase.Real{}
	metrics, err := telemetry.NewMetrics(clock, func() (time.Time, bool) { return time.Time{}, false })
	if err != nil {
		return
	}
	var sink telemetry.Sink
	if service.IsSCMContext(ctx) {
		sink, err = telemetry.OpenEventLogSink("claude-egress-proxy")
	} else {
		sink, err = telemetry.NewStreamSink(os.Stderr)
	}
	if err != nil {
		return
	}
	logger := telemetry.NewLogger(clock, metrics, sink)
	emitServiceState(logger, clock.Now(), "startup_failed")
	shutdownContext, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	logger.Shutdown(shutdownContext)
}

func runProductionServe(ctx context.Context, loaded serveLoaded) error {
	configuration, ok := loaded.(*config.Loaded)
	if !ok {
		return diagnosticError{code: contract.D010}
	}
	return runServe(ctx, configuration)
}

func runServe(ctx context.Context, loaded *config.Loaded) error {
	if ctx == nil || loaded == nil {
		return diagnosticError{code: contract.D010}
	}
	childContext, cancel := context.WithCancel(ctx)
	defer cancel()
	configuration := loaded.Config()
	policies, err := config.PlatformSecurityPolicies()
	if err != nil {
		emitDefaultStartupFailure(ctx)
		return diagnosticError{code: contract.D010}
	}
	clock := timebase.Real{}
	var provider certmgr.Provider
	metrics, err := telemetry.NewMetrics(clock, func() (time.Time, bool) {
		if provider == nil {
			return time.Time{}, false
		}
		expiry := provider.Expiry(clock.Now())
		return clock.Now().Add(expiry), expiry > 0
	})
	if err != nil {
		return diagnosticError{code: contract.D010}
	}
	logger, err := openApplicationLogger(childContext, configuration, policies, clock, metrics)
	if err != nil {
		return diagnosticError{code: contract.D008}
	}
	serveStarted := false
	defer func() {
		shutdownTimeout := time.Second
		if !serveStarted {
			emitServiceState(logger, clock.Now(), "startup_failed")
			shutdownTimeout = 500 * time.Millisecond
		}
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer shutdownCancel()
		logger.Shutdown(shutdownContext)
	}()
	reloads := newReloadTelemetry(metrics, logger, clock)
	resolver := serveResolver(configuration.Resolver())
	source := &network.SourceMonitor{Clock: clock}
	if address, ok := configuration.OutboundSourceIPv4(); ok {
		source.Configured = address
	}
	if err := source.Recheck(childContext); err != nil {
		return diagnosticError{code: contract.D011}
	}
	mode := network.PublicSelfSupplied
	switch configuration.TLS().Mode() {
	case config.TLSACME:
		mode = network.PublicSelfACME
	case config.TLSInsecureLoopback:
		mode = network.PublicSelfLoopback
	}
	publicSelf := network.NewPublicSelfForMode(mode, configuration.PublicSelfIPv4s(), resolver, configuration.TLS().Hostname())
	selfSnapshot := publicSelf.Refresh(childContext)

	destination, err := policy.Load(profileName(configuration.Destination().Profile()), policy.CustomRules{
		ExactHosts: configuration.Destination().ExactHosts(), Suffixes: configuration.Destination().Suffixes(), DangerousCustomSuffixes: configuration.Destination().DangerousCustomSuffixes(),
	})
	if err != nil {
		return diagnosticError{code: contract.D003}
	}
	authenticationAdmission := admission.NewAuthentication(clock)
	pacAdmission := admission.NewPAC(clock)
	coordinator := session.NewCoordinatorWithCapacity(credential.Verifier{}, authenticationAdmission, int(configuration.PerDeviceCapacity()))
	coordinator.SetTerminalObserver(func(event session.TerminalEvent) {
		if !event.HasClose {
			return
		}
		metrics.FinishTunnel(event.CloseResult, contract.TunnelOutcomeForCloseResult(event.CloseResult), event.Duration, event.Bytes)
		var sensitive *telemetry.SensitiveMetadata
		if configuration.Logging().SensitiveMetadata() {
			sensitive = event.Sensitive
		}
		record, recordErr := telemetry.TunnelClosed(clock.Now(), event.CloseResult, sensitive)
		if recordErr == nil {
			logger.Submit(record)
		}
	})
	readiness := proxy.NewReadiness(coordinator)
	setReadiness(readiness, "drain", true)
	setReadiness(readiness, "source_bind", true)
	setReadiness(readiness, "public_self", network.FreshPublicSelfAt(selfSnapshot, clock.Now()))

	artifactPolicy := policies.StateFile
	artifactPolicy.Presence, artifactPolicy.Kind, artifactPolicy.MaxBytes = securefs.Optional, securefs.RegularFile, int64(contract.V1().StoreBytes)
	credentialInspector, err := credential.OpenInspector(loaded.StateRoot(), configuration.InstanceID(), artifactPolicy)
	if err != nil {
		return diagnosticError{code: contract.D005}
	}
	installCredentials(childContext, credentialInspector, coordinator, readiness)

	provider, err = serveCertificateProvider(configuration, policies, clock, resolver, publicSelf, source, reloads)
	if err != nil {
		return diagnosticError{code: contract.D007}
	}
	var producerWG sync.WaitGroup
	var cleanupOnce sync.Once
	cleanupProducers := func() {
		cleanupOnce.Do(func() {
			cancel()
			if closer, ok := provider.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
			producerWG.Wait()
		})
	}
	defer cleanupProducers()
	startProducer := func(run func()) {
		producerWG.Add(1)
		go func() {
			defer producerWG.Done()
			run()
		}()
	}
	if provider != nil {
		setReadiness(readiness, "certificate", provider.Ready(clock.Now()) && provider.Expiry(clock.Now()) >= 24*time.Hour)
	} else {
		setReadiness(readiness, "certificate", true)
	}

	verifier, err := admintoken.LoadVerifier(childContext, loaded.StateRoot(), configuration.InstanceID(), artifactPolicy, configuration.Metrics().Enabled())
	if err != nil {
		return diagnosticError{code: contract.D006}
	}

	startProducer(func() { watchSource(childContext, clock, source, readiness, reloads, logger) })
	startProducer(func() {
		watchCredentials(childContext, clock, credentialInspector, coordinator, readiness, reloads, logger)
	})
	startProducer(func() { watchPublicSelf(childContext, clock, publicSelf, readiness, reloads, logger) })
	if provider != nil {
		startProducer(func() { watchCertificate(childContext, clock, provider, readiness, logger) })
	}

	publicAddresses := configuration.PublicListener().Addresses()
	publicAdmissions := sharedPublicAdmissions(clock, len(publicAddresses))
	publicHandler := proxy.NewPublicHandler(proxy.PublicConfig{
		Coordinator: coordinator, Policy: destination, Resolver: resolver,
		Dialer: network.Dialer{Source: source, Snapshot: publicSelf.Snapshot, Now: clock.Now}, PublicSelf: publicSelf, Clock: clock,
		Absolute: absoluteLifetime(configuration), PACEnabled: configuration.PublicListener().PACEnabled(), PACBody: servePAC(configuration, destination), PACAdmission: pacAdmission, Metrics: metrics,
	})
	endpoints := make([]proxy.ServerEndpoint, 0, len(configuration.PublicListener().Addresses())+1)
	closeEndpoints := func() {
		for _, endpoint := range endpoints {
			_ = endpoint.Listener.Close()
		}
	}
	for i, address := range publicAddresses {
		listener, listenErr := net.Listen("tcp", address.String())
		if listenErr != nil {
			closeEndpoints()
			return diagnosticError{code: contract.D009}
		}
		tlsEnabled := configuration.TLS().Mode() != config.TLSInsecureLoopback
		owned := proxy.NewInstrumentedPublicListener(listener, publicAdmissions[i], metrics, tlsEnabled)
		if provider != nil {
			owned = proxy.NewInstrumentedTLSOwnedListener(owned, provider.TLSConfig(), metrics)
		}
		endpoints = append(endpoints, proxy.ServerEndpoint{Server: wire.NewServer(publicHandler), Listener: owned})
	}
	if adminAddress, enabled := configuration.AdminListener().Address(); configuration.AdminListener().Enabled() && enabled {
		listener, listenErr := net.Listen("tcp", adminAddress.String())
		if listenErr != nil {
			closeEndpoints()
			return diagnosticError{code: contract.D009}
		}
		adminAdmission := admission.NewAdmin(clock)
		adminHandler := proxy.NewAdminHandler(proxy.AdminConfig{MetricsEnabled: configuration.Metrics().Enabled(), Verifier: verifier, Admission: adminAdmission, Readiness: readiness, Metrics: metrics, Coordinator: coordinator})
		endpoints = append(endpoints, proxy.ServerEndpoint{Server: wire.NewServer(adminHandler), Listener: proxy.NewAdminListener(listener, adminAdmission)})
	}
	if len(endpoints) == 0 {
		return diagnosticError{code: contract.D009}
	}
	if err := startCertificateAfterBind(childContext, provider, endpoints); err != nil {
		closeEndpoints()
		return diagnosticError{code: contract.D007}
	}
	publishRuntimeState(metrics, coordinator, publicAdmissions[0], authenticationAdmission, pacAdmission)
	telemetry.SetStateProvider(metrics, func() telemetry.StateSnapshot {
		return runtimeState(coordinator, publicAdmissions[0], authenticationAdmission, pacAdmission)
	})
	emitInitialServiceState(logger, clock.Now(), configuration, coordinator.Snapshot().Ready, coordinator.Snapshot().CredentialGeneration > 0)
	serveStarted = true
	runErr := proxy.RunServersWithDrain(childContext, endpoints, coordinator, configuration.GracefulShutdownDrain(), func(wasReady bool) {
		publishRuntimeState(metrics, coordinator, publicAdmissions[0], authenticationAdmission, pacAdmission)
		emitServiceState(logger, clock.Now(), "draining")
		if wasReady {
			emitServiceState(logger, clock.Now(), "not_ready")
		}
	})
	cleanupProducers()
	emitServiceState(logger, clock.Now(), "stopped")
	if runErr != nil {
		return diagnosticError{code: contract.D009}
	}
	return nil
}

type rootedSink struct {
	telemetry.Sink
	root securefs.MutableRoot
}

func (s *rootedSink) Close() error {
	sinkErr := s.Sink.Close()
	rootErr := s.root.Close()
	return errors.Join(sinkErr, rootErr)
}

func openApplicationLogger(ctx context.Context, configuration config.Config, policies config.SecurityPolicies, clock timebase.Clock, metrics *telemetry.Metrics) (*telemetry.Logger, error) {
	fail := func(err error) (*telemetry.Logger, error) {
		logger := telemetry.NewLogger(clock, metrics, nil)
		emitServiceState(logger, clock.Now(), "startup_failed")
		shutdownContext, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		logger.Shutdown(shutdownContext)
		return nil, err
	}
	var sink telemetry.Sink
	var err error
	if configuration.Logging().Sink() == config.LogSinkFile {
		root, openErr := securefs.OpenMutableRoot(filepath.Dir(configuration.Logging().FilePath()), policies.StateDirectory)
		if openErr != nil {
			return fail(openErr)
		}
		policy := policies.StateFile
		policy.Presence, policy.Kind, policy.MaxBytes = securefs.Optional, securefs.RegularFile, 10_485_760
		fileSink, sinkErr := telemetry.OpenFileSink(ctx, root, filepath.Base(configuration.Logging().FilePath()), policy)
		if sinkErr != nil {
			_ = root.Close()
			return fail(sinkErr)
		}
		sink = &rootedSink{Sink: fileSink, root: root}
	} else if service.IsSCMContext(ctx) {
		sink, err = telemetry.OpenEventLogSink("claude-egress-proxy")
	} else {
		sink, err = telemetry.NewStreamSink(os.Stderr)
	}
	if err != nil {
		return fail(err)
	}
	return telemetry.NewLogger(clock, metrics, sink), nil
}

func emitInitialServiceState(logger *telemetry.Logger, at time.Time, configuration config.Config, ready, credentialReady bool) {
	if configuration.TLS().Mode() == config.TLSInsecureLoopback {
		emitServiceState(logger, at, "insecure_loopback")
	}
	emitServiceState(logger, at, "started")
	if configuration.Destination().DangerousCustomSuffixes() {
		emitServiceState(logger, at, "dangerous_custom_suffixes")
	}
	if !credentialReady {
		emitServiceState(logger, at, "credential_store_unavailable")
	}
	if ready {
		emitServiceState(logger, at, "ready")
	} else {
		emitServiceState(logger, at, "not_ready")
	}
}

func emitServiceState(logger *telemetry.Logger, at time.Time, reasonName string) {
	reason, ok := contract.ParseServiceStateReason(reasonName)
	if !ok {
		return
	}
	record, err := telemetry.ServiceState(at, reason)
	if err == nil {
		logger.Submit(record)
	}
}

func emitReadinessTransition(logger *telemetry.Logger, at time.Time, before, after bool) {
	if before == after {
		return
	}
	if after {
		emitServiceState(logger, at, "ready")
	} else {
		emitServiceState(logger, at, "not_ready")
	}
}

type reloadTelemetry struct {
	mu      sync.Mutex
	metrics *telemetry.Metrics
	logger  *telemetry.Logger
	clock   timebase.Clock
	episode map[string]bool
}

func newReloadTelemetry(metrics *telemetry.Metrics, logger *telemetry.Logger, clock timebase.Clock) *reloadTelemetry {
	return &reloadTelemetry{metrics: metrics, logger: logger, clock: clock, episode: make(map[string]bool)}
}

func (r *reloadTelemetry) failed(kind string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.episode[kind]
}

func (r *reloadTelemetry) observe(kindName, resultName string) {
	kind, kindOK := contract.ParseReloadKind(kindName)
	result, resultOK := contract.ParseReloadResult(resultName)
	if r == nil || !kindOK || !resultOK {
		return
	}
	r.metrics.IncReload(kind, result)
	r.mu.Lock()
	shouldLog := resultName == "failure" && !r.episode[kindName] || resultName == "recovered"
	if resultName == "failure" {
		r.episode[kindName] = true
	} else {
		r.episode[kindName] = false
	}
	r.mu.Unlock()
	if shouldLog {
		record, err := telemetry.ReloadRecord(r.clock.Now(), kind, result)
		if err == nil {
			r.logger.Submit(record)
		}
	}
}

func publishRuntimeState(metrics *telemetry.Metrics, coordinator *session.Coordinator, public *admission.Public, authentication *admission.Authentication, pacControl *admission.PAC) {
	metrics.PublishState(runtimeState(coordinator, public, authentication, pacControl))
}

func runtimeState(coordinator *session.Coordinator, public *admission.Public, authentication *admission.Authentication, pacControl *admission.PAC) telemetry.StateSnapshot {
	state := coordinator.Snapshot()
	state.TLSHandshakeLimiterEntries = uint64(public.Entries())
	state.AuthenticationLimiterEntries = uint64(authentication.Entries())
	state.PACLimiterEntries = uint64(pacControl.Entries())
	state.PreAuthConnections = uint64(public.Active())
	return state
}

func sharedPublicAdmissions(clock timebase.Clock, count int) []*admission.Public {
	if count <= 0 {
		return nil
	}
	shared := admission.NewPublic(clock)
	result := make([]*admission.Public, count)
	for i := range result {
		result[i] = shared
	}
	return result
}

func startCertificateAfterBind(ctx context.Context, provider certmgr.Provider, endpoints []proxy.ServerEndpoint) error {
	if provider == nil {
		return nil
	}
	if len(endpoints) == 0 {
		return errors.New("certificate lifecycle requires a bound listener")
	}
	for _, endpoint := range endpoints {
		if endpoint.Listener == nil || endpoint.Listener.Addr() == nil {
			return errors.New("certificate lifecycle requires a bound listener")
		}
	}
	return provider.Start(ctx)
}

func serveResolver(selection config.Resolver) network.Resolver {
	address, explicit := selection.Address()
	if selection.Mode() != config.ResolverExplicit || !explicit {
		return network.SystemResolver{}
	}
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, networkName, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, networkName, address.String())
	}}
	return network.SystemResolver{Resolver: resolver}
}

func profileName(profile config.Profile) string {
	switch profile {
	case config.ProfileCode:
		return "code"
	case config.ProfileWebDesktop:
		return "web-desktop"
	case config.ProfileAll:
		return "all"
	default:
		return ""
	}
}

func serveCertificateProvider(configuration config.Config, policies config.SecurityPolicies, clock timebase.Clock, resolver network.Resolver, publicSelf *network.PublicSelf, source network.SourceChecker, reloads *reloadTelemetry) (certmgr.Provider, error) {
	tlsSelection := configuration.TLS()
	switch tlsSelection.Mode() {
	case config.TLSInsecureLoopback:
		return nil, nil
	case config.TLSSupplied:
		filePolicy := policies.StateFile
		filePolicy.Presence, filePolicy.Kind, filePolicy.MaxBytes = securefs.Required, securefs.RegularFile, 1<<20
		return certmgr.NewSupplied(certmgr.SuppliedConfig{Hostname: tlsSelection.Hostname(), CertificateFile: tlsSelection.CertificateFile(), PrivateKeyFile: tlsSelection.PrivateKeyFile(), Clock: clock, RootPolicy: securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()}, FilePolicy: filePolicy, Observe: reloadObserver(reloads, "certificate")})
	case config.TLSACME:
		root, err := securefs.OpenMutableRoot(configuration.StateRootPath(), policies.StateDirectory)
		if err != nil {
			return nil, err
		}
		artifactPolicy := policies.StateFile
		artifactPolicy.Presence, artifactPolicy.Kind, artifactPolicy.MaxBytes = securefs.Optional, securefs.RegularFile, int64(contract.V1().StoreBytes)
		transport, err := certmgr.NewDirectTransport(certmgr.DirectTransportConfig{
			DirectoryURL: acme.LetsEncryptURL, Resolver: resolver, PublicSelf: publicSelf.Snapshot, Acquire: publicSelf.Acquire, Source: source, Now: clock.Now,
		})
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		managed, err := certmgr.NewManagedACME(certmgr.DirectManagedACMEConfig{
			ManagedACMEConfig: certmgr.ManagedACMEConfig{Hostname: tlsSelection.Hostname(), Store: certmgr.ACMEStore{Root: root, Mutable: root, Name: "acme.json", Policy: artifactPolicy}, Clock: clock, Now: clock.Now, Observe: reloadObserver(reloads, "acme")},
			DirectoryURL:      acme.LetsEncryptURL, Transport: transport,
		})
		if err != nil {
			_ = root.Close()
			return nil, err
		}
		return managed, nil
	default:
		return nil, errors.New("invalid TLS mode")
	}
}

func reloadObserver(reloads *reloadTelemetry, kind string) func(contract.ReloadResult) {
	if reloads == nil {
		return nil
	}
	return func(result contract.ReloadResult) { reloads.observe(kind, result.String()) }
}

func absoluteLifetime(configuration config.Config) time.Duration {
	value, enabled := configuration.AbsoluteTunnelLifetime()
	if !enabled {
		return 0
	}
	return value
}

func servePAC(configuration config.Config, destination policy.Policy) []byte {
	if !configuration.PublicListener().PACEnabled() {
		return nil
	}
	var endpoint pac.ProxyEndpoint
	var err error
	if configuration.TLS().Mode() == config.TLSInsecureLoopback {
		first := configuration.PublicListener().Addresses()[0]
		endpoint, err = pac.LoopbackEndpoint(first.Addr(), first.Port())
	} else {
		endpoint, err = pac.RemoteEndpoint(configuration.TLS().Hostname(), 443)
	}
	if err != nil {
		return nil
	}
	body, _ := pac.Render(destination, endpoint, pac.VisibilityPublic)
	return body
}

func installCredentials(ctx context.Context, inspector *credential.Inspector, coordinator *session.Coordinator, readiness *proxy.Readiness) {
	inspection, err := inspector.Inspect(ctx, credential.ValidateOnly)
	if err != nil || inspection.State != credential.StoreCoherent && inspection.State != credential.StoreSuccessor {
		setReadiness(readiness, "credential", false)
		return
	}
	coordinator.InstallCredentials(inspection.Snapshot)
	setReadiness(readiness, "credential", inspection.Snapshot.Generation() > 0)
}

func watchCredentials(ctx context.Context, clock timebase.Clock, inspector *credential.Inspector, coordinator *session.Coordinator, readiness *proxy.Readiness, reloads *reloadTelemetry, logger *telemetry.Logger) {
	lastGeneration := coordinator.Snapshot().CredentialGeneration
	failed := false
	ticker := clock.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			inspection, err := inspector.Inspect(ctx, credential.ValidateOnly)
			if err != nil || inspection.State != credential.StoreCoherent && inspection.State != credential.StoreSuccessor {
				if lastGeneration > 0 && !failed {
					reloads.observe("credential", "failure")
					wasReady := coordinator.ReadinessReady()
					coordinator.SetCredentialUnavailable(coordinator.Snapshot().CredentialGeneration)
					setReadiness(readiness, "credential", false)
					emitServiceState(logger, clock.Now(), "credential_store_unavailable")
					if wasReady {
						emitServiceState(logger, clock.Now(), "not_ready")
					}
					failed = true
				}
				if lastGeneration == 0 {
					setReadiness(readiness, "credential", false)
				}
				continue
			}
			generation := inspection.Snapshot.Generation()
			if coordinator.InstallCredentials(inspection.Snapshot) != session.InstallRejected {
				setReadiness(readiness, "credential", inspection.Snapshot.Generation() > 0)
				if generation != lastGeneration || failed {
					wasFailed := failed
					initialPublication := lastGeneration == 0 && generation > 0
					result := "success"
					if wasFailed {
						result = "recovered"
					}
					reloads.observe("credential", result)
					if wasFailed || initialPublication {
						emitServiceState(logger, clock.Now(), "credential_store_recovered")
						if coordinator.ReadinessReady() {
							emitServiceState(logger, clock.Now(), "ready")
						}
					}
				}
				lastGeneration, failed = generation, false
			}
		}
	}
}

func watchPublicSelf(ctx context.Context, clock timebase.Clock, state *network.PublicSelf, readiness *proxy.Readiness, reloads *reloadTelemetry, logger *telemetry.Logger) {
	ticker := clock.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			snapshot := state.Refresh(ctx)
			ready := network.FreshPublicSelfAt(snapshot, clock.Now())
			result := "success"
			if !ready {
				result = "failure"
			} else if reloads.failed("public_self") {
				result = "recovered"
			}
			reloads.observe("public_self", result)
			wasReady := readiness.Ready()
			setReadiness(readiness, "public_self", ready)
			emitReadinessTransition(logger, clock.Now(), wasReady, readiness.Ready())
		}
	}
}

func watchSource(ctx context.Context, clock timebase.Clock, source *network.SourceMonitor, readiness *proxy.Readiness, reloads *reloadTelemetry, logger *telemetry.Logger) {
	if !source.Configured.IsValid() {
		return
	}
	ticker := clock.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			err := source.Recheck(ctx)
			result := "success"
			if err != nil {
				result = "failure"
			} else if reloads.failed("source_bind") {
				result = "recovered"
			}
			reloads.observe("source_bind", result)
			wasReady := readiness.Ready()
			setReadiness(readiness, "source_bind", err == nil)
			emitReadinessTransition(logger, clock.Now(), wasReady, readiness.Ready())
		}
	}
}

func watchCertificate(ctx context.Context, clock timebase.Clock, provider certmgr.Provider, readiness *proxy.Readiness, logger *telemetry.Logger) {
	ticker := clock.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C():
			wasReady := readiness.Ready()
			setReadiness(readiness, "certificate", provider.Ready(clock.Now()) && provider.Expiry(clock.Now()) >= 24*time.Hour)
			emitReadinessTransition(logger, clock.Now(), wasReady, readiness.Ready())
		}
	}
}

func setReadiness(readiness *proxy.Readiness, name string, ready bool) {
	predicate, ok := contract.ParseReadinessPredicate(name)
	if ok {
		readiness.Set(predicate, ready)
	}
}
