package telemetry

import (
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestPrivateRegistry(t *testing.T) {
	m, err := NewMetrics(timebase.Real{}, func() (time.Time, bool) { return time.Now().Add(time.Hour), true })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Gatherer().Gather(); err != nil {
		t.Fatal(err)
	}
}

// This catches a terminal tunnel being recorded without its required close
// counter, and guards exact uint64 accounting at the Prometheus float boundary.
func TestFinishTunnelRecordsCloseAndRejectsInexactBytes(t *testing.T) {
	clean, _ := contract.ParseCloseResult("clean")
	outcome, _ := contract.ParseTunnelOutcome("clean")
	m, err := NewMetrics(timebase.Real{}, func() (time.Time, bool) { return time.Time{}, false })
	if err != nil {
		t.Fatal(err)
	}
	m.FinishTunnel(clean, outcome, time.Second, contract.ByteTotals{})
	if got := counterValue(t, m, "claude_proxy_tunnel_closes_total", "result", "clean"); got != 1 {
		t.Fatalf("tunnel close counter = %v, want 1", got)
	}
	before := counterValue(t, m, "claude_proxy_bytes_total", "direction", "client_to_origin")
	mustPanicClosed(t, func() { m.FinishTunnel(clean, outcome, time.Second, contract.ByteTotals{ClientToOrigin: 1 << 53}) })
	if got := counterValue(t, m, "claude_proxy_bytes_total", "direction", "client_to_origin"); got != before {
		t.Fatalf("inexact bytes mutated counter: got %v, want %v", got, before)
	}
}

func TestCertificateExpiryRunsOncePerGatherAndFloors(t *testing.T) {
	var calls atomic.Int32
	var clockCalls atomic.Int32
	now := time.Date(2026, 8, 4, 12, 0, 0, 500_000_000, time.UTC)
	clock := countedClock{now: now, calls: &clockCalls}
	m, err := NewMetrics(clock, func() (time.Time, bool) { calls.Add(1); return now.Add(1500 * time.Millisecond), true })
	if err != nil {
		t.Fatal(err)
	}
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 1 {
		t.Fatalf("expiry = %v, want 1", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls = %d, want 1", got)
	}
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 1 {
		t.Fatalf("expiry = %v, want 1", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls = %d, want 2", got)
	}
	if got := clockCalls.Load(); got != 2 {
		t.Fatalf("clock calls = %d, want 2", got)
	}
}

func TestCertificateExpiryCallsClockWhenCertificateAbsent(t *testing.T) {
	var certificateCalls, clockCalls atomic.Int32
	m, err := NewMetrics(countedClock{now: time.Now(), calls: &clockCalls}, func() (time.Time, bool) { certificateCalls.Add(1); return time.Time{}, false })
	if err != nil {
		t.Fatal(err)
	}
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 0 {
		t.Fatalf("expiry = %v, want 0", got)
	}
	if certificateCalls.Load() != 1 || clockCalls.Load() != 1 {
		t.Fatalf("calls certificate=%d clock=%d, want 1,1", certificateCalls.Load(), clockCalls.Load())
	}
}

type fixedClock struct {
	timebase.Real
	now time.Time
}

func (c fixedClock) Now() time.Time { return c.now }

type countedClock struct {
	timebase.Real
	now   time.Time
	calls *atomic.Int32
}

func (c countedClock) Now() time.Time { c.calls.Add(1); return c.now }

func mustPanicClosed(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		got := recover()
		if got != invalidClosed {
			t.Fatalf("panic = %v, want %q", got, invalidClosed)
		}
	}()
	f()
}
func counterValue(t *testing.T, m *Metrics, name, label, value string) float64 {
	t.Helper()
	return metricValue(t, m, name, label, value)
}
func gaugeValue(t *testing.T, m *Metrics, name string) float64 {
	t.Helper()
	return metricValue(t, m, name, "", "")
}
func metricValue(t *testing.T, m *Metrics, name, label, value string) float64 {
	t.Helper()
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() == name {
			for _, metric := range family.Metric {
				if label == "" || (len(metric.Label) == 1 && metric.Label[0].GetName() == label && metric.Label[0].GetValue() == value) {
					if metric.Counter != nil {
						return metric.Counter.GetValue()
					}
					if metric.Gauge != nil {
						return metric.Gauge.GetValue()
					}
				}
			}
		}
	}
	t.Fatalf("metric %s{%s=%s} missing", name, label, value)
	return math.NaN()
}
