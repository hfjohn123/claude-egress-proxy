package contract

import (
	"slices"
	"testing"
)

func TestResultsAreClosed(t *testing.T) {
	tests := []struct {
		name  string
		got   []string
		want  []string
		parse func(string) bool
	}{
		{"connect", AllConnectResults(), []string{"established", "malformed_request", "header_too_large", "port_denied", "hostname_denied", "address_denied", "dns_failed", "dial_failed", "setup_timeout", "credential_store_unavailable", "source_bind_unavailable", "self_address_state_unavailable", "global_capacity", "device_capacity", "draining", "credential_changed", "client_disconnected", "internal_error"}, func(value string) bool { _, ok := ParseConnectResult(value); return ok }},
		{"tls", AllTLSResults(), []string{"success", "rate_limited", "timeout", "tls_error"}, func(value string) bool { _, ok := ParseTLSResult(value); return ok }},
		{"authentication", AllAuthenticationResults(), []string{"challenge", "valid", "invalid", "throttled", "map_capacity", "store_unavailable"}, func(value string) bool { _, ok := ParseAuthenticationResult(value); return ok }},
		{"pac", AllPACResults(), []string{"served", "disabled", "not_found", "prefix_rate_limited", "global_rate_limited", "map_capacity", "capacity"}, func(value string) bool { _, ok := ParsePACResult(value); return ok }},
		{"limiter", AllLimiters(), []string{"tls_handshake", "authentication", "pac"}, func(value string) bool { _, ok := ParseLimiter(value); return ok }},
		{"limiter event", AllLimiterEvents(), []string{"allowed", "throttled", "entry_expired", "map_full", "saturation_overflow"}, func(value string) bool { _, ok := ParseLimiterEvent(value); return ok }},
		{"reload kind", AllReloadKinds(), []string{"credential", "certificate", "public_self", "source_bind", "acme"}, func(value string) bool { _, ok := ParseReloadKind(value); return ok }},
		{"reload result", AllReloadResults(), []string{"success", "failure", "recovered"}, func(value string) bool { _, ok := ParseReloadResult(value); return ok }},
		{"delivery", AllDeliveryResults(), []string{"written", "dropped_queue_full", "dropped_sink_failed", "dropped_shutdown_deadline"}, func(value string) bool { _, ok := ParseDeliveryResult(value); return ok }},
		{"setup", AllSetupOutcomes(), []string{"success", "failure"}, func(value string) bool { _, ok := ParseSetupOutcome(value); return ok }},
		{"close", AllCloseResults(), []string{"clean", "io_error", "idle_timeout", "absolute_lifetime", "credential_revoked", "shutdown_deadline"}, func(value string) bool { _, ok := ParseCloseResult(value); return ok }},
		{"tunnel", AllTunnelOutcomes(), []string{"clean", "error", "revoked", "idle_timeout", "lifetime_timeout", "shutdown"}, func(value string) bool { _, ok := ParseTunnelOutcome(value); return ok }},
		{"readiness", AllReadinessPredicates(), []string{"certificate", "credential", "public_self", "source_bind", "drain"}, func(value string) bool { _, ok := ParseReadinessPredicate(value); return ok }},
		{"public self", AllPublicSelfOutcomes(), []string{"positive", "success_empty", "failure"}, func(value string) bool { _, ok := ParsePublicSelfOutcome(value); return ok }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !slices.Equal(test.got, test.want) {
				t.Fatalf("got %q, want %q", test.got, test.want)
			}
			if test.parse("sentinel.example") {
				t.Fatal("open enum")
			}
		})
	}
}

func TestEnumRelationships(t *testing.T) {
	parseLimiter := func(value string) Limiter {
		result, ok := ParseLimiter(value)
		if !ok {
			t.Fatalf("parse limiter %q", value)
		}
		return result
	}
	parseEvent := func(value string) LimiterEvent {
		result, ok := ParseLimiterEvent(value)
		if !ok {
			t.Fatalf("parse limiter event %q", value)
		}
		return result
	}
	parseClose := func(value string) CloseResult {
		result, ok := ParseCloseResult(value)
		if !ok {
			t.Fatalf("parse close result %q", value)
		}
		return result
	}
	parseTunnel := func(value string) TunnelOutcome {
		result, ok := ParseTunnelOutcome(value)
		if !ok {
			t.Fatalf("parse tunnel outcome %q", value)
		}
		return result
	}
	valid := map[Limiter][]LimiterEvent{
		parseLimiter("tls_handshake"):  {parseEvent("allowed"), parseEvent("throttled"), parseEvent("entry_expired"), parseEvent("saturation_overflow")},
		parseLimiter("authentication"): {parseEvent("allowed"), parseEvent("throttled"), parseEvent("entry_expired"), parseEvent("map_full")},
		parseLimiter("pac"):            {parseEvent("allowed"), parseEvent("throttled"), parseEvent("entry_expired"), parseEvent("map_full")},
	}
	for _, limiter := range AllLimiters() {
		kind, _ := ParseLimiter(limiter)
		for _, event := range AllLimiterEvents() {
			value, _ := ParseLimiterEvent(event)
			want := slices.Contains(valid[kind], value)
			if got := ValidLimiterPair(kind, value); got != want {
				t.Errorf("ValidLimiterPair(%q, %q) = %t, want %t", limiter, event, got, want)
			}
		}
	}

	closeToTunnel := map[CloseResult]TunnelOutcome{
		parseClose("clean"):              parseTunnel("clean"),
		parseClose("io_error"):           parseTunnel("error"),
		parseClose("idle_timeout"):       parseTunnel("idle_timeout"),
		parseClose("absolute_lifetime"):  parseTunnel("lifetime_timeout"),
		parseClose("credential_revoked"): parseTunnel("revoked"),
		parseClose("shutdown_deadline"):  parseTunnel("shutdown"),
	}
	for close, want := range closeToTunnel {
		if got := TunnelOutcomeForCloseResult(close); got != want {
			t.Errorf("TunnelOutcomeForCloseResult(%q) = %q, want %q", close, got, want)
		}
	}
}

func TestByteTotalsHasUnsignedDirections(t *testing.T) {
	totals := ByteTotals{ClientToOrigin: 3, OriginToClient: 5}
	if totals.ClientToOrigin != 3 || totals.OriginToClient != 5 {
		t.Fatalf("got %+v", totals)
	}
}

func TestImpossibleEnumStringPanics(t *testing.T) {
	tests := []struct {
		name   string
		string func() string
	}{
		{"frame", func() string { return Frame(255).String() }},
		{"tls", func() string { return TLSResult(255).String() }},
		{"authentication", func() string { return AuthenticationResult(255).String() }},
		{"connect", func() string { return ConnectResult(255).String() }},
		{"pac", func() string { return PACResult(255).String() }},
		{"limiter", func() string { return Limiter(255).String() }},
		{"limiter event", func() string { return LimiterEvent(255).String() }},
		{"reload kind", func() string { return ReloadKind(255).String() }},
		{"reload result", func() string { return ReloadResult(255).String() }},
		{"delivery", func() string { return DeliveryResult(255).String() }},
		{"setup", func() string { return SetupOutcome(255).String() }},
		{"close", func() string { return CloseResult(255).String() }},
		{"tunnel", func() string { return TunnelOutcome(255).String() }},
		{"readiness", func() string { return ReadinessPredicate(255).String() }},
		{"public self", func() string { return PublicSelfOutcome(255).String() }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("String did not panic for an impossible enum value")
				}
			}()
			_ = test.string()
		})
	}
}
