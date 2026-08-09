package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/telemetry"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestReloadTelemetryCountsAttemptsAndLogsOnlyEpisodeEdges(t *testing.T) {
	metrics, err := telemetry.NewMetrics(timebase.Real{}, func() (time.Time, bool) { return time.Time{}, false })
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	sink, err := telemetry.NewStreamSink(&output)
	if err != nil {
		t.Fatal(err)
	}
	logger := telemetry.NewLogger(timebase.Real{}, metrics, sink)
	reloads := newReloadTelemetry(metrics, logger, timebase.Real{})
	reloads.observe("credential", "failure")
	reloads.observe("credential", "failure")
	reloads.observe("credential", "recovered")
	logger.Shutdown(context.Background())

	if got := strings.Count(output.String(), `"event":"reload"`); got != 2 {
		t.Fatalf("reload records = %d, want failure and recovery only; output=%s", got, output.String())
	}
	if reloads.failed("credential") {
		t.Fatal("recovery left credential failure episode active")
	}
	assertReloadMetric(t, metrics, "failure", 2)
	assertReloadMetric(t, metrics, "recovered", 1)
}

func assertReloadMetric(t *testing.T, metrics *telemetry.Metrics, result string, want float64) {
	t.Helper()
	families, err := metrics.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "claude_proxy_reload_total" {
			continue
		}
		for _, metric := range family.Metric {
			labels := map[string]string{}
			for _, pair := range metric.Label {
				labels[pair.GetName()] = pair.GetValue()
			}
			if labels["kind"] == "credential" && labels["result"] == result {
				if got := metric.GetCounter().GetValue(); got != want {
					t.Fatalf("reload credential/%s = %v, want %v", result, got, want)
				}
				return
			}
		}
	}
	t.Fatalf("reload credential/%s metric absent", result)
}
