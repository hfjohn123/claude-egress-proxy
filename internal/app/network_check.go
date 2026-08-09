package app

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/network"
	"github.com/hfjohn123/claude-egress-proxy/internal/policy"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

const publicIPWarning = "warning: public IP echo discloses this server's egress address to the selected service\n"

type networkLoaded interface{ Close() error }
type networkDependencies struct {
	defaults func() (config.DefaultPaths, error)
	load     func(string, config.ValidationMode) (networkLoaded, error)
	check    func(context.Context, networkLoaded, string) ([]byte, bool)
}

func NewNetworkHandler() Handler {
	return newNetworkHandler(networkDependencies{
		defaults: config.PlatformDefaults,
		load:     func(path string, mode config.ValidationMode) (networkLoaded, error) { return config.Load(path, mode) },
		check:    runProductionNetworkCheck,
	})
}

func newNetworkHandler(deps networkDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.defaults == nil || deps.load == nil || deps.check == nil {
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
		loaded, err := deps.load(path, config.ValidateOperational)
		if err != nil {
			return initFailure(configCode(err))
		}
		defer loaded.Close()
		output, ready := deps.check(ctx, loaded, invocation.PublicIPURL)
		stderr := []byte(nil)
		if invocation.PublicIPURL != "" {
			stderr = append(stderr, publicIPWarning...)
		}
		if !ready {
			stderr = append(stderr, "network check failed\n"...)
			return Result{ExitCode: 1, Stdout: output, Stderr: stderr}
		}
		return Result{Stdout: output, Stderr: stderr}
	}
}

func runProductionNetworkCheck(ctx context.Context, selected networkLoaded, publicIPURL string) ([]byte, bool) {
	loaded, ok := selected.(*config.Loaded)
	if !ok || ctx == nil {
		return nil, false
	}
	configuration := loaded.Config()
	clock := timebase.Real{}
	resolver := serveResolver(configuration.Resolver())
	source := &network.SourceMonitor{Clock: clock}
	if address, configured := configuration.OutboundSourceIPv4(); configured {
		source.Configured = address
	}
	sourceReady := source.Recheck(ctx) == nil
	destination, policyErr := policy.Load(profileName(configuration.Destination().Profile()), policy.CustomRules{
		ExactHosts: configuration.Destination().ExactHosts(), Suffixes: configuration.Destination().Suffixes(), DangerousCustomSuffixes: configuration.Destination().DangerousCustomSuffixes(),
	})
	policyReady := policyErr == nil
	bindReady := networkBindsAvailable(configuration)

	mode := network.PublicSelfSupplied
	if configuration.TLS().Mode() == config.TLSACME {
		mode = network.PublicSelfACME
	} else if configuration.TLS().Mode() == config.TLSInsecureLoopback {
		mode = network.PublicSelfLoopback
	}
	publicSelf := network.NewPublicSelfForMode(mode, configuration.PublicSelfIPv4s(), resolver, configuration.TLS().Hostname())
	snapshot := publicSelf.Refresh(ctx)
	selfReady := network.FreshPublicSelfAt(snapshot, clock.Now())

	dnsReady := false
	if policyReady {
		host := configuration.TLS().Hostname()
		if host == "" {
			hosts := destination.BuiltInRules().ExactHosts()
			if len(hosts) != 0 {
				host = hosts[0]
			}
		}
		answers, err := resolver.LookupA(ctx, host)
		if err == nil {
			_, err = network.ClassifyCandidates(answers)
		}
		dnsReady = err == nil
	}

	certificateReady := configuration.TLS().Mode() == config.TLSInsecureLoopback
	if !certificateReady {
		policies, err := config.PlatformSecurityPolicies()
		if err == nil {
			provider, providerErr := serveCertificateProvider(configuration, policies, clock, resolver, publicSelf, source, nil)
			certificateReady = providerErr == nil && provider != nil && provider.Ready(clock.Now())
		}
	}

	age := clock.Now().Sub(snapshot.ObservedAt)
	if age < 0 {
		age = 0
	}
	var output bytes.Buffer
	fmt.Fprintf(&output, "local_bind=%s\ndns=%s\npolicy=%s\ncertificate=%s\npublic_self=%s\npublic_self_coverage=%s\npublic_self_generation=%d\npublic_self_age_seconds=%d\nsource_bind=%s\n",
		checkState(bindReady), checkState(dnsReady), checkState(policyReady), checkState(certificateReady), snapshot.Outcome, snapshot.Coverage, snapshot.Generation, int64(age/time.Second), checkState(sourceReady))
	echoReady := true
	if publicIPURL != "" {
		echo := network.EchoClient{Resolver: resolver, Dialer: network.Dialer{Source: source, Snapshot: publicSelf.Snapshot, Now: clock.Now}, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
		address, err := echo.Check(ctx, publicIPURL)
		echoReady = err == nil
		if err == nil {
			fmt.Fprintf(&output, "public_ip=%s\n", address)
		}
	}
	return output.Bytes(), bindReady && dnsReady && policyReady && certificateReady && selfReady && sourceReady && echoReady
}

func networkBindsAvailable(configuration config.Config) bool {
	listeners := make([]net.Listener, 0, len(configuration.PublicListener().Addresses())+1)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for _, address := range configuration.PublicListener().Addresses() {
		listener, err := net.Listen("tcp", address.String())
		if err != nil {
			return false
		}
		listeners = append(listeners, listener)
	}
	if address, ok := configuration.AdminListener().Address(); configuration.AdminListener().Enabled() && ok {
		listener, err := net.Listen("tcp", address.String())
		if err != nil {
			return false
		}
		listeners = append(listeners, listener)
	}
	return true
}

func checkState(ready bool) string {
	if ready {
		return "ready"
	}
	return "unavailable"
}
