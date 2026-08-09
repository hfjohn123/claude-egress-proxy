package telemetry

import (
	"bufio"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type goldenDescriptor struct {
	name, typ, help string
	labels, values  []string
	tuples          [][]string
	buckets         []float64
}

func TestFreshRegistryExactlyMatchesHandAuthoredDescriptorGolden(t *testing.T) {
	want := parseDescriptorGolden(t)
	if len(want) != 17 {
		t.Fatalf("golden rows = %d, want 17", len(want))
	}
	m := newTestMetrics(t, fixedClock{now: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)}, func() (time.Time, bool) { return time.Time{}, false })
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]*dto.MetricFamily, len(families))
	for _, family := range families {
		got[family.GetName()] = family
	}
	if !reflect.DeepEqual(sortedKeys(got), sortedGoldenKeys(want)) {
		t.Fatalf("family names = %v, want %v", sortedKeys(got), sortedGoldenKeys(want))
	}
	for name, expected := range want {
		family := got[name]
		if gotType(family) != expected.typ {
			t.Errorf("%s type = %s, want %s", name, gotType(family), expected.typ)
		}
		if family.GetHelp() != expected.help {
			t.Errorf("%s help = %q, want %q", name, family.GetHelp(), expected.help)
		}
		definition := metricDefinition(name)
		if !equalStrings(definition.Labels, expected.labels) {
			t.Errorf("%s labels = %v, want %v", name, definition.Labels, expected.labels)
		}
		if !equalStrings(definition.Values, expected.values) {
			t.Errorf("%s allowed values = %v, want %v", name, definition.Values, expected.values)
		}
		gotTuples := make([]string, 0, len(family.Metric))
		for _, metric := range family.Metric {
			if got := metricTuple(metric, expected.labels); got == "" && len(expected.labels) != 0 {
				t.Errorf("%s has incomplete labels", name)
			} else {
				gotTuples = append(gotTuples, got)
			}
			assertFreshZero(t, name, expected.typ, metric)
			if expected.typ == "histogram" {
				assertHistogramBuckets(t, name, metric, expected.buckets)
			}
		}
		wantTuples := canonicalTuples(expected.tuples)
		sort.Strings(gotTuples)
		if !reflect.DeepEqual(gotTuples, wantTuples) {
			t.Errorf("%s tuples = %v, want %v", name, gotTuples, wantTuples)
		}
	}
}

func TestFreshRegistryContainsOnlyValidLimiterPairs(t *testing.T) {
	m := newTestMetrics(t, fixedClock{}, func() (time.Time, bool) { return time.Time{}, false })
	families, err := m.Gatherer().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var pairs map[string]bool
	for _, family := range families {
		if family.GetName() == "claude_proxy_limiter_events_total" {
			pairs = map[string]bool{}
			for _, metric := range family.Metric {
				pairs[metricTuple(metric, []string{"limiter", "event"})] = true
			}
		}
	}
	if pairs == nil {
		t.Fatal("limiter family missing")
	}
	for _, limiter := range contract.AllLimiters() {
		for _, event := range contract.AllLimiterEvents() {
			key := limiter + "," + event
			_, got := pairs[key]
			if contract.ValidLimiterPair(mustLimiter(t, limiter), mustLimiterEvent(t, event)) != got {
				t.Errorf("limiter pair %s present = %t", key, got)
			}
		}
	}
}

func TestMetricsLeavesPrometheusDefaultsUntouched(t *testing.T) {
	before := defaultGatherNames(t)
	m := newTestMetrics(t, fixedClock{}, func() (time.Time, bool) { return time.Time{}, false })
	if _, err := m.Gatherer().Gather(); err != nil {
		t.Fatal(err)
	}
	if after := defaultGatherNames(t); !reflect.DeepEqual(after, before) {
		t.Fatalf("default gather names changed: before %v after %v", before, after)
	}
}

func TestGeneratorNeverWritesHandAuthoredDescriptorGolden(t *testing.T) {
	path := filepath.Join("testdata", "descriptors.golden")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "generate", "./internal/telemetry")
	command.Dir = filepath.Join("..", "..")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("go generate: %v\n%s", err, output)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatal("generator rewrote hand-authored descriptors.golden")
	}
}

func TestMetricsExportedSurfaceHasNoRawLabelAPI(t *testing.T) {
	typ := reflect.TypeOf((*Metrics)(nil))
	want := []string{"FinishTunnel", "Gatherer", "IncAuthentication", "IncConnect", "IncLimiter", "IncPAC", "IncReload", "IncTLS", "ObserveSetup", "PublishState", "RecordDelivery"}
	got := make([]string, typ.NumMethod())
	for i := range got {
		method := typ.Method(i)
		got[i] = method.Name
		for j := 1; j < method.Type.NumIn(); j++ {
			if method.Type.In(j).Kind() == reflect.String {
				t.Errorf("%s accepts raw string", method.Name)
			}
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported Metrics methods = %v, want %v", got, want)
	}
}

func TestCertificateExpirySnapshotsCallbackAndClockOncePerGather(t *testing.T) {
	var calls atomic.Int32
	clock := &mutableClock{now: time.Date(2026, 8, 4, 12, 0, 0, 500_000_000, time.UTC)}
	m := newTestMetrics(t, clock, func() (time.Time, bool) { calls.Add(1); return time.Date(2026, 8, 4, 12, 0, 2, 0, time.UTC), true })
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 1 {
		t.Fatalf("expiry = %v, want 1", got)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("callback calls = %d, want 1", got)
	}
	if got := clock.calls.Load(); got != 1 {
		t.Fatalf("clock calls = %d, want 1", got)
	}
	clock.now = clock.now.Add(time.Second)
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 0 {
		t.Fatalf("expiry after clock advance = %v, want 0", got)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("callback calls = %d, want 2", got)
	}
	if got := clock.calls.Load(); got != 2 {
		t.Fatalf("clock calls = %d, want 2", got)
	}
	clock.now = clock.now.Add(2 * time.Second)
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 0 {
		t.Fatalf("expired certificate expiry = %v, want 0", got)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("callback calls = %d, want 3", got)
	}
	if got := clock.calls.Load(); got != 3 {
		t.Fatalf("clock calls = %d, want 3", got)
	}
	m = newTestMetrics(t, clock, func() (time.Time, bool) { calls.Add(1); return time.Time{}, false })
	if got := gaugeValue(t, m, "claude_proxy_certificate_expiry_seconds"); got != 0 {
		t.Fatalf("absent certificate expiry = %v, want 0", got)
	}
}

type mutableClock struct {
	timebase.Real
	now   time.Time
	calls atomic.Int32
}

func (c *mutableClock) Now() time.Time { c.calls.Add(1); return c.now }

func newTestMetrics(t *testing.T, clock timebase.Clock, cert func() (time.Time, bool)) *Metrics {
	t.Helper()
	m, err := NewMetrics(clock, cert)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func defaultGatherNames(t *testing.T) []string {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, len(families))
	for i, family := range families {
		names[i] = family.GetName()
	}
	sort.Strings(names)
	return names
}
func gotType(f *dto.MetricFamily) string {
	return strings.ToLower(strings.TrimPrefix(f.GetType().String(), ""))
}
func assertFreshZero(t *testing.T, name, typ string, m *dto.Metric) {
	t.Helper()
	switch typ {
	case "counter":
		if m.GetCounter().GetValue() != 0 {
			t.Errorf("%s counter nonzero", name)
		}
	case "gauge":
		if m.GetGauge().GetValue() != 0 {
			t.Errorf("%s gauge nonzero", name)
		}
	case "histogram":
		if m.GetHistogram().GetSampleCount() != 0 || m.GetHistogram().GetSampleSum() != 0 {
			t.Errorf("%s histogram nonzero", name)
		}
	}
}
func assertHistogramBuckets(t *testing.T, name string, m *dto.Metric, want []float64) {
	t.Helper()
	buckets := m.GetHistogram().Bucket
	if len(buckets) != len(want) {
		t.Errorf("%s finite bucket count = %d, want %d", name, len(buckets), len(want))
		return
	}
	for i, bucket := range buckets {
		if bucket.GetUpperBound() != want[i] || bucket.GetCumulativeCount() != 0 {
			t.Errorf("%s bucket %d = (%v,%d), want (%v,0)", name, i, bucket.GetUpperBound(), bucket.GetCumulativeCount(), want[i])
		}
	}
	if m.GetHistogram().GetSampleCount() != 0 {
		t.Errorf("%s +Inf count = %d, want 0", name, m.GetHistogram().GetSampleCount())
	}
}
func metricTuple(m *dto.Metric, labels []string) string {
	values := make(map[string]string, len(m.Label))
	for _, label := range m.Label {
		values[label.GetName()] = label.GetValue()
	}
	if len(values) != len(labels) {
		return ""
	}
	tuple := make([]string, len(labels))
	for i, label := range labels {
		value, ok := values[label]
		if !ok {
			return ""
		}
		tuple[i] = value
	}
	return strings.Join(tuple, ",")
}
func canonicalTuples(tuples [][]string) []string {
	out := make([]string, len(tuples))
	for i, tuple := range tuples {
		out[i] = strings.Join(tuple, ",")
	}
	sort.Strings(out)
	return out
}
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for key := range m {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
func sortedGoldenKeys(m map[string]goldenDescriptor) []string { return sortedKeys(m) }
func mustLimiter(t *testing.T, value string) contract.Limiter {
	t.Helper()
	v, ok := contract.ParseLimiter(value)
	if !ok {
		t.Fatal(value)
	}
	return v
}
func mustLimiterEvent(t *testing.T, value string) contract.LimiterEvent {
	t.Helper()
	v, ok := contract.ParseLimiterEvent(value)
	if !ok {
		t.Fatal(value)
	}
	return v
}

func parseDescriptorGolden(t *testing.T) map[string]goldenDescriptor {
	t.Helper()
	file, err := os.Open(filepath.Join("testdata", "descriptors.golden"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	out := map[string]goldenDescriptor{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, "|")
		if len(fields) != 7 {
			t.Fatalf("invalid golden row %q", line)
		}
		if _, exists := out[fields[0]]; exists {
			t.Fatalf("duplicate golden family %s", fields[0])
		}
		d := goldenDescriptor{name: fields[0], typ: fields[1], help: fields[2], labels: splitNonEmpty(fields[3]), values: splitNonEmpty(fields[4])}
		if len(d.labels) == 0 {
			d.tuples = [][]string{{}}
		} else {
			for _, tuple := range strings.Split(fields[5], ";") {
				d.tuples = append(d.tuples, strings.Split(tuple, ","))
			}
		}
		for _, bucket := range splitNonEmpty(fields[6]) {
			if bucket == "+Inf" {
				continue
			}
			n, err := strconv.ParseFloat(bucket, 64)
			if err != nil {
				t.Fatalf("%s bucket %q: %v", d.name, bucket, err)
			}
			d.buckets = append(d.buckets, n)
		}
		out[d.name] = d
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
func splitNonEmpty(value string) []string {
	if value == "" {
		return nil
	}
	return strings.Split(value, ",")
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
