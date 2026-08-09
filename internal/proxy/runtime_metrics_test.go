package proxy

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestRuntimeClassificationEmitsClosedMetrics(t *testing.T) {
	metrics, err := telemetry.NewMetrics(timebase.Real{}, func() (time.Time, bool) { return time.Time{}, false })
	if err != nil {
		t.Fatal(err)
	}
	cfg := PublicConfig{Metrics: metrics, Clock: timebase.Real{}}
	authentication, _ := contract.ParseAuthenticationResult("invalid")
	recordAuthentication(cfg, authentication)
	recordSetup(cfg, resultFor("established"), time.Now())
	recordPAC(cfg, "served", "allowed")

	assertMetricLabel(t, metrics, "claude_proxy_authentication_total", "result", "invalid", 1)
	assertMetricLabel(t, metrics, "claude_proxy_connect_total", "result", "established", 1)
	assertMetricLabel(t, metrics, "claude_proxy_pac_total", "result", "served", 1)
	assertMetricLabels(t, metrics, "claude_proxy_limiter_events_total", map[string]string{"limiter": "authentication", "event": "allowed"}, 1)
	assertMetricLabels(t, metrics, "claude_proxy_limiter_events_total", map[string]string{"limiter": "pac", "event": "allowed"}, 1)
}

func assertMetricLabel(t *testing.T, metrics *telemetry.Metrics, name, label, value string, want float64) {
	t.Helper()
	assertMetricLabels(t, metrics, name, map[string]string{label: value}, want)
}

func assertMetricLabels(t *testing.T, metrics *telemetry.Metrics, name string, labels map[string]string, want float64) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if metricLabelsMatch(metric, labels) {
				if got := metric.GetCounter().GetValue(); got != want {
					t.Fatalf("%s%v = %v, want %v", name, labels, got, want)
				}
				return
			}
		}
	}
	t.Fatalf("metric %s%v not found", name, labels)
}

func metricLabelsMatch(metric *dto.Metric, want map[string]string) bool {
	if len(metric.Label) != len(want) {
		return false
	}
	for _, pair := range metric.Label {
		if want[pair.GetName()] != pair.GetValue() {
			return false
		}
	}
	return true
}
