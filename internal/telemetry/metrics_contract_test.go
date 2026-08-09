package telemetry

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	dto "github.com/prometheus/client_model/go"
)

const exactFloatLimit = uint64(1<<53 - 1)

func TestMetricsTypedMutatorsExhaustClosedValues(t *testing.T) {
	m := newContractMetrics(t)
	for _, s := range contract.AllTLSResults() {
		v, _ := contract.ParseTLSResult(s)
		m.IncTLS(v)
		requireCounter(t, m, "claude_proxy_tls_handshakes_total", "result", s, 1)
	}
	for _, s := range contract.AllAuthenticationResults() {
		v, _ := contract.ParseAuthenticationResult(s)
		m.IncAuthentication(v)
		requireCounter(t, m, "claude_proxy_authentication_total", "result", s, 1)
	}
	for _, s := range contract.AllConnectResults() {
		v, _ := contract.ParseConnectResult(s)
		m.IncConnect(v)
		requireCounter(t, m, "claude_proxy_connect_total", "result", s, 1)
	}
	for _, s := range contract.AllPACResults() {
		v, _ := contract.ParsePACResult(s)
		m.IncPAC(v)
		requireCounter(t, m, "claude_proxy_pac_total", "result", s, 1)
	}
	for _, l := range contract.AllLimiters() {
		for _, e := range contract.AllLimiterEvents() {
			limiter, _ := contract.ParseLimiter(l)
			event, _ := contract.ParseLimiterEvent(e)
			if contract.ValidLimiterPair(limiter, event) {
				m.IncLimiter(limiter, event)
				requireTupleCounter(t, m, "claude_proxy_limiter_events_total", []string{"limiter", "event"}, []string{l, e}, 1)
			}
		}
	}
	for _, k := range contract.AllReloadKinds() {
		for _, r := range contract.AllReloadResults() {
			kind, _ := contract.ParseReloadKind(k)
			result, _ := contract.ParseReloadResult(r)
			m.IncReload(kind, result)
			requireTupleCounter(t, m, "claude_proxy_reload_total", []string{"kind", "result"}, []string{k, r}, 1)
		}
	}
	for _, s := range contract.AllSetupOutcomes() {
		v, _ := contract.ParseSetupOutcome(s)
		m.ObserveSetup(v, time.Second)
		requireHistogram(t, m, "claude_proxy_setup_duration_seconds", "outcome", s, 1, 1)
	}
	for _, s := range contract.AllDeliveryResults() {
		v, _ := contract.ParseDeliveryResult(s)
		m.RecordDelivery(v)
		requireCounter(t, m, "claude_proxy_log_records_total", "result", s, 1)
	}
}

func TestMetricsRejectInvalidClosedValuesBeforeMutation(t *testing.T) {
	m := newContractMetrics(t)
	assertNoMetricMutation(t, m, func() { m.IncTLS(contract.TLSResult(99)) })
	assertNoMetricMutation(t, m, func() { m.IncAuthentication(contract.AuthenticationResult(99)) })
	assertNoMetricMutation(t, m, func() { m.IncConnect(contract.ConnectResult(99)) })
	assertNoMetricMutation(t, m, func() { m.IncPAC(contract.PACResult(99)) })
	assertNoMetricMutation(t, m, func() { m.IncReload(contract.ReloadKind(99), contract.ReloadResult(99)) })
	assertNoMetricMutation(t, m, func() { m.ObserveSetup(contract.SetupOutcome(99), time.Second) })
	assertNoMetricMutation(t, m, func() { m.RecordDelivery(contract.DeliveryResult(99)) })
	for _, e := range contract.AllLimiterEvents() {
		event, _ := contract.ParseLimiterEvent(e)
		assertNoMetricMutation(t, m, func() { m.IncLimiter(contract.Limiter(99), event) })
	}
	for _, l := range contract.AllLimiters() {
		limiter, _ := contract.ParseLimiter(l)
		assertNoMetricMutation(t, m, func() { m.IncLimiter(limiter, contract.LimiterEvent(99)) })
	}
	assertNoMetricMutation(t, m, func() { m.IncLimiter(contract.Limiter(99), contract.LimiterEvent(99)) })
	for _, l := range contract.AllLimiters() {
		for _, e := range contract.AllLimiterEvents() {
			limiter, _ := contract.ParseLimiter(l)
			event, _ := contract.ParseLimiterEvent(e)
			if !contract.ValidLimiterPair(limiter, event) {
				assertNoMetricMutation(t, m, func() { m.IncLimiter(limiter, event) })
			}
		}
	}
	for _, s := range contract.AllSetupOutcomes() {
		v, _ := contract.ParseSetupOutcome(s)
		assertNoMetricMutation(t, m, func() { m.ObserveSetup(v, -time.Nanosecond) })
	}
}

func TestFinishTunnelExactMappingBoundariesAndAtomicRejection(t *testing.T) {
	m := newContractMetrics(t)
	for _, closeName := range contract.AllCloseResults() {
		close, _ := contract.ParseCloseResult(closeName)
		outcome := contract.TunnelOutcomeForCloseResult(close)
		m.FinishTunnel(close, outcome, time.Second, contract.ByteTotals{ClientToOrigin: exactFloatLimit, OriginToClient: exactFloatLimit})
		requireCounter(t, m, "claude_proxy_tunnel_closes_total", "result", closeName, 1)
		requireHistogram(t, m, "claude_proxy_tunnel_duration_seconds", "outcome", outcome.String(), 1, 1)
	}
	requireCounter(t, m, "claude_proxy_bytes_total", "direction", "client_to_origin", float64(len(contract.AllCloseResults()))*float64(exactFloatLimit))
	before := gatherBytes(t, m)
	clean, _ := contract.ParseCloseResult("clean")
	errorOutcome, _ := contract.ParseTunnelOutcome("error")
	assertNoMetricMutation(t, m, func() { m.FinishTunnel(clean, errorOutcome, time.Second, contract.ByteTotals{}) })
	assertNoMetricMutation(t, m, func() { m.FinishTunnel(contract.CloseResult(99), errorOutcome, time.Second, contract.ByteTotals{}) })
	assertNoMetricMutation(t, m, func() { m.FinishTunnel(clean, contract.TunnelOutcome(99), time.Second, contract.ByteTotals{}) })
	assertNoMetricMutation(t, m, func() {
		m.FinishTunnel(clean, contract.TunnelOutcomeForCloseResult(clean), -time.Nanosecond, contract.ByteTotals{})
	})
	assertNoMetricMutation(t, m, func() {
		m.FinishTunnel(clean, contract.TunnelOutcomeForCloseResult(clean), time.Second, contract.ByteTotals{ClientToOrigin: 1 << 53})
	})
	assertNoMetricMutation(t, m, func() {
		m.FinishTunnel(clean, contract.TunnelOutcomeForCloseResult(clean), time.Second, contract.ByteTotals{OriginToClient: 1 << 53})
	})
	if got := gatherBytes(t, m); got != before {
		t.Fatalf("bytes after rejected finish = %v, want %v", got, before)
	}
}

func TestPublishStateCopiesExactValuesAndRejectsOverLimitAtomically(t *testing.T) {
	m := newContractMetrics(t)
	s := StateSnapshot{TLSHandshakeLimiterEntries: exactFloatLimit, AuthenticationLimiterEntries: 2, PACLimiterEntries: 3, PreAuthConnections: 4, PendingSetupReservations: 5, ActiveTunnels: 6, CredentialGeneration: 7}
	m.PublishState(s)
	assertState(t, m, s)
	s.ActiveTunnels = 0
	assertGauge(t, m, "claude_proxy_active_tunnels", "", "", 6)
	prior := StateSnapshot{TLSHandshakeLimiterEntries: exactFloatLimit, AuthenticationLimiterEntries: 2, PACLimiterEntries: 3, PreAuthConnections: 4, PendingSetupReservations: 5, ActiveTunnels: 6, CredentialGeneration: 7}
	for field := 0; field < 7; field++ {
		bad := prior
		switch field {
		case 0:
			bad.TLSHandshakeLimiterEntries = 1 << 53
		case 1:
			bad.AuthenticationLimiterEntries = 1 << 53
		case 2:
			bad.PACLimiterEntries = 1 << 53
		case 3:
			bad.PreAuthConnections = 1 << 53
		case 4:
			bad.PendingSetupReservations = 1 << 53
		case 5:
			bad.ActiveTunnels = 1 << 53
		case 6:
			bad.CredentialGeneration = 1 << 53
		}
		mustPanicClosed(t, func() { m.PublishState(bad) })
		assertState(t, m, prior)
	}
}

func TestMetricsUsesOneCollectorForRelatedStateGauges(t *testing.T) {
	m := newContractMetrics(t)
	if m.stateMetrics == nil {
		t.Fatal("state gauges are not collected from one snapshot")
	}
}

func newContractMetrics(t *testing.T) *Metrics {
	t.Helper()
	m, err := NewMetrics(fixedClock{}, func() (time.Time, bool) { return time.Time{}, false })
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func assertNoMetricMutation(t *testing.T, m *Metrics, f func()) {
	t.Helper()
	before := gatherBytes(t, m)
	mustPanicClosed(t, f)
	if got := gatherBytes(t, m); got != before {
		t.Fatalf("metric mutated after rejected input")
	}
}
func gatherBytes(t *testing.T, m *Metrics) string {
	t.Helper()
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	return string(mustMarshal(t, families))
}
func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func requireCounter(t *testing.T, m *Metrics, name, label, value string, want float64) {
	t.Helper()
	if got := counterValue(t, m, name, label, value); got != want {
		t.Fatalf("%s{%s=%s} = %.0f, want %.0f", name, label, value, got, want)
	}
}
func requireTupleCounter(t *testing.T, m *Metrics, name string, labels, values []string, want float64) {
	t.Helper()
	if got := tupleMetric(t, m, name, labels, values).GetCounter().GetValue(); got != want {
		t.Fatalf("%s%v = %.0f, want %.0f", name, values, got, want)
	}
}
func requireHistogram(t *testing.T, m *Metrics, name, label, value string, count uint64, sum float64) {
	t.Helper()
	h := tupleMetric(t, m, name, []string{label}, []string{value}).GetHistogram()
	if h.GetSampleCount() != count || h.GetSampleSum() != sum {
		t.Fatalf("%s{%s=%s} = (%d,%v), want (%d,%v)", name, label, value, h.GetSampleCount(), h.GetSampleSum(), count, sum)
	}
}
func tupleMetric(t *testing.T, m *Metrics, name string, labels, values []string) *dto.Metric {
	t.Helper()
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, metric := range f.Metric {
			if len(metric.Label) != len(labels) {
				continue
			}
			got := map[string]string{}
			for _, label := range metric.Label {
				got[label.GetName()] = label.GetValue()
			}
			ok := true
			for i := range labels {
				if got[labels[i]] != values[i] {
					ok = false
					break
				}
			}
			if ok {
				return metric
			}
		}
	}
	t.Fatalf("metric %s%v missing", name, values)
	return nil
}
func assertGauge(t *testing.T, m *Metrics, name, label, value string, want float64) {
	t.Helper()
	var got float64
	if label == "" {
		got = gaugeValue(t, m, name)
	} else {
		got = tupleMetric(t, m, name, []string{label}, []string{value}).GetGauge().GetValue()
	}
	if got != want {
		t.Fatalf("%s = %v, want %v", name, got, want)
	}
}
func assertState(t *testing.T, m *Metrics, s StateSnapshot) {
	t.Helper()
	assertGauge(t, m, "claude_proxy_limiter_entries", "limiter", "tls_handshake", float64(s.TLSHandshakeLimiterEntries))
	assertGauge(t, m, "claude_proxy_limiter_entries", "limiter", "authentication", float64(s.AuthenticationLimiterEntries))
	assertGauge(t, m, "claude_proxy_limiter_entries", "limiter", "pac", float64(s.PACLimiterEntries))
	assertGauge(t, m, "claude_proxy_pre_auth_connections", "", "", float64(s.PreAuthConnections))
	assertGauge(t, m, "claude_proxy_pending_setup_reservations", "", "", float64(s.PendingSetupReservations))
	assertGauge(t, m, "claude_proxy_active_tunnels", "", "", float64(s.ActiveTunnels))
	assertGauge(t, m, "claude_proxy_credential_generation", "", "", float64(s.CredentialGeneration))
}
