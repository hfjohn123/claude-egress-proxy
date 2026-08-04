package telemetry

import (
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

var recordTime = time.Date(2026, 8, 4, 12, 0, 0, 123456789, time.FixedZone("x", -3600))

func TestGeneratedRecordTuplesExact(t *testing.T) {
	want := []RecordTuple{
		{"tunnel_closed", "clean", "info"}, {"tunnel_closed", "io_error", "error"}, {"tunnel_closed", "idle_timeout", "info"}, {"tunnel_closed", "absolute_lifetime", "info"}, {"tunnel_closed", "credential_revoked", "info"}, {"tunnel_closed", "shutdown_deadline", "info"},
		{"reload", "credential_failure", "warn"}, {"reload", "certificate_failure", "warn"}, {"reload", "public_self_failure", "warn"}, {"reload", "source_bind_failure", "warn"}, {"reload", "acme_failure", "warn"}, {"reload", "credential_recovered", "info"}, {"reload", "certificate_recovered", "info"}, {"reload", "public_self_recovered", "info"}, {"reload", "source_bind_recovered", "info"}, {"reload", "acme_recovered", "info"},
		{"service_state", "started", "info"}, {"service_state", "ready", "info"}, {"service_state", "draining", "info"}, {"service_state", "stopped", "info"}, {"service_state", "credential_store_recovered", "info"}, {"service_state", "not_ready", "warn"}, {"service_state", "insecure_loopback", "warn"}, {"service_state", "dangerous_custom_suffixes", "warn"}, {"service_state", "credential_store_unavailable", "warn"}, {"service_state", "startup_failed", "error"},
	}
	if !slices.Equal(GeneratedRecordTuples, want) {
		t.Fatalf("record tuples = %#v", GeneratedRecordTuples)
	}
	for _, tuple := range want {
		if !generatedRecordLevel(tuple.Event, tuple.Reason, tuple.Level) {
			t.Fatalf("tuple missing %#v", tuple)
		}
	}
	if generatedRecordLevel("reload", "credential_success", "info") {
		t.Fatal("reload success tuple accepted")
	}
}

func TestTunnelClosedExhaustiveClosedGrammar(t *testing.T) {
	for _, name := range contract.AllCloseResults() {
		reason, _ := contract.ParseCloseResult(name)
		r, err := TunnelClosed(recordTime, reason, nil)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		level := "info"
		if name == "io_error" {
			level = "error"
		}
		assertRecord(t, r, []string{"timestamp", "level", "event", "reason"}, map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": level, "event": "tunnel_closed", "reason": name})
	}
	assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, contract.CloseResult(99), nil) })
}

func TestReloadRecordExhaustiveClosedGrammar(t *testing.T) {
	for _, kindName := range contract.AllReloadKinds() {
		kind, _ := contract.ParseReloadKind(kindName)
		for _, resultName := range []string{"failure", "recovered"} {
			result, _ := contract.ParseReloadResult(resultName)
			r, err := ReloadRecord(recordTime, kind, result)
			if err != nil {
				t.Fatalf("%s/%s: %v", kindName, resultName, err)
			}
			level := "warn"
			if resultName == "recovered" {
				level = "info"
			}
			assertRecord(t, r, []string{"timestamp", "level", "event", "reason"}, map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": level, "event": "reload", "reason": kindName + "_" + resultName})
		}
		ok, _ := contract.ParseReloadResult("success")
		assertInvalidRecord(t, func() (Record, error) { return ReloadRecord(recordTime, kind, ok) })
	}
	result, _ := contract.ParseReloadResult("failure")
	assertInvalidRecord(t, func() (Record, error) { return ReloadRecord(recordTime, contract.ReloadKind(99), result) })
	assertInvalidRecord(t, func() (Record, error) {
		return ReloadRecord(recordTime, contract.ReloadKind(99), contract.ReloadResult(99))
	})
}

func TestServiceStateExhaustiveClosedGrammar(t *testing.T) {
	levels := map[string]string{"not_ready": "warn", "insecure_loopback": "warn", "dangerous_custom_suffixes": "warn", "credential_store_unavailable": "warn", "startup_failed": "error"}
	for _, name := range contract.AllServiceStateReasons() {
		reason, _ := contract.ParseServiceStateReason(name)
		r, err := ServiceState(recordTime, reason)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		level := levels[name]
		if level == "" {
			level = "info"
		}
		assertRecord(t, r, []string{"timestamp", "level", "event", "reason"}, map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": level, "event": "service_state", "reason": name})
	}
	assertInvalidRecord(t, func() (Record, error) { return ServiceState(recordTime, contract.ServiceStateReason(99)) })
}

func TestRecordTimestampGrammar(t *testing.T) {
	clean, _ := contract.ParseCloseResult("clean")
	for _, at := range []time.Time{time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(9999, 12, 31, 23, 59, 59, 1, time.UTC)} {
		r, err := TunnelClosed(at, clean, nil)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		_ = json.Unmarshal([]byte(r.JSON()), &got)
		if !strings.HasSuffix(got["timestamp"].(string), "Z") {
			t.Fatalf("not UTC: %s", r.JSON())
		}
	}
	for _, at := range []time.Time{time.Time{}, time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(at, clean, nil) })
	}
}

func TestSensitiveExtensionOrderNumericAndImmutable(t *testing.T) {
	clean, _ := contract.ParseCloseResult("clean")
	s := validSensitiveMetadata()
	s.DurationMillis, s.Bytes = math.MaxUint64, contract.ByteTotals{ClientToOrigin: 1<<53 + 1, OriginToClient: math.MaxUint64}
	r, err := TunnelClosed(recordTime, clean, &s)
	if err != nil {
		t.Fatal(err)
	}
	keys := []string{"timestamp", "level", "event", "reason", "destination_hostname", "device_identifier", "source_prefix", "duration_ms", "bytes_client_to_origin", "bytes_origin_to_client"}
	assertRecord(t, r, keys, map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": "info", "event": "tunnel_closed", "reason": "clean", "destination_hostname": s.DestinationHostname, "device_identifier": s.DeviceIdentifier, "source_prefix": s.SourcePrefix.String(), "duration_ms": json.Number("18446744073709551615"), "bytes_client_to_origin": json.Number("9007199254740993"), "bytes_origin_to_client": json.Number("18446744073709551615")})
	before := r.JSON()
	s.DestinationHostname = "bad host"
	s.Bytes.ClientToOrigin = 0
	if got := r.JSON(); got != before {
		t.Fatalf("record mutated: %s", got)
	}
	r, err = TunnelClosed(recordTime, clean, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, r, keys[:4], map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": "info", "event": "tunnel_closed", "reason": "clean"})
	s = validSensitiveMetadata()
	r, err = TunnelClosed(recordTime, clean, &s)
	if err != nil {
		t.Fatal(err)
	}
	assertRecord(t, r, keys, map[string]any{"timestamp": "2026-08-04T13:00:00.123456789Z", "level": "info", "event": "tunnel_closed", "reason": "clean", "destination_hostname": s.DestinationHostname, "device_identifier": s.DeviceIdentifier, "source_prefix": s.SourcePrefix.String(), "duration_ms": json.Number("0"), "bytes_client_to_origin": json.Number("0"), "bytes_origin_to_client": json.Number("0")})
}

func TestSensitiveMetadataGrammarBoundariesAndAtomicRejection(t *testing.T) {
	clean, _ := contract.ParseCloseResult("clean")
	validHosts := []string{"a", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)}
	for _, host := range validHosts {
		s := validSensitiveMetadata()
		s.DestinationHostname = host
		if _, err := TunnelClosed(recordTime, clean, &s); err != nil {
			t.Fatalf("valid host %q: %v", host, err)
		}
	}
	invalidHosts := []string{"", strings.Repeat("a", 254), strings.Repeat("a", 64), "-a", "a-", "a..b", "a.", "127.0.0.1", "::1", "A.example", "é.example", "a_b", "a/b"}
	for _, host := range invalidHosts {
		s := validSensitiveMetadata()
		s.DestinationHostname = host
		assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, clean, &s) })
	}
	validDevices := []string{"A-z09._~-", strings.Repeat("a", 64)}
	for _, device := range validDevices {
		s := validSensitiveMetadata()
		s.DeviceIdentifier = device
		if _, err := TunnelClosed(recordTime, clean, &s); err != nil {
			t.Fatalf("valid device %q: %v", device, err)
		}
	}
	for _, device := range []string{"", strings.Repeat("a", 65), "a b", "a/b", "a\\b", "a\nb", "é"} {
		s := validSensitiveMetadata()
		s.DeviceIdentifier = device
		assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, clean, &s) })
	}
	for _, prefix := range []string{"0.0.0.0/24", "255.255.255.0/24", "2001:db8::/64", "ffff:ffff:ffff:ffff::/64"} {
		s := validSensitiveMetadata()
		s.SourcePrefix = netip.MustParsePrefix(prefix)
		if _, err := TunnelClosed(recordTime, clean, &s); err != nil {
			t.Fatalf("valid prefix %s: %v", prefix, err)
		}
	}
	for _, prefix := range []string{"192.0.2.1/24", "192.0.2.0/25", "2001:db8::1/64", "2001:db8::/63", "::ffff:0:0/64", "::ffff:192.0.2.0/64"} {
		s := validSensitiveMetadata()
		s.SourcePrefix = netip.MustParsePrefix(prefix)
		assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, clean, &s) })
	}
	s := validSensitiveMetadata()
	s.DeviceIdentifier = "bad host"
	assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, clean, &s) })
	s = validSensitiveMetadata()
	s.SourcePrefix = netip.Prefix{}
	assertInvalidRecord(t, func() (Record, error) { return TunnelClosed(recordTime, clean, &s) })
}

func TestRecordOutputGrammarAndSizeLimit(t *testing.T) {
	clean, _ := contract.ParseCloseResult("clean")
	s := validSensitiveMetadata()
	r, err := TunnelClosed(recordTime, clean, &s)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.JSON()) > GeneratedRecordSchema.MaxBytes || strings.ContainsAny(r.JSON(), "\ufeff\r\n") {
		t.Fatalf("bad output %q", r.JSON())
	}
	if strings.Contains(r.JSON(), "\\u003c") || strings.Contains(r.JSON(), "\\u003e") || strings.Contains(r.JSON(), "\\u0026") {
		t.Fatal("HTML-only escape")
	}
	big := strings.Repeat("x", GeneratedRecordSchema.MaxBytes)
	if r, err := build(recordTime, "info", big, "clean", nil); !errorsIsInvalid(r, err) {
		t.Fatal("oversize accepted")
	}
}

func validSensitiveMetadata() SensitiveMetadata {
	return SensitiveMetadata{DestinationHostname: "api.example.com", DeviceIdentifier: "device-1", SourcePrefix: netip.MustParsePrefix("192.0.2.0/24")}
}
func assertInvalidRecord(t *testing.T, f func() (Record, error)) {
	t.Helper()
	r, err := f()
	if !errorsIsInvalid(r, err) {
		t.Fatalf("got (%q,%v), want zero ErrInvalidRecord", r.JSON(), err)
	}
}
func errorsIsInvalid(r Record, err error) bool { return err == ErrInvalidRecord && r == (Record{}) }
func assertRecord(t *testing.T, r Record, keys []string, want map[string]any) {
	t.Helper()
	var got map[string]any
	decoder := json.NewDecoder(strings.NewReader(r.JSON()))
	decoder.UseNumber()
	if err := decoder.Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(keys) {
		t.Fatalf("keys %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s = %#v, want %#v", k, got[k], w)
		}
	}
	order := jsonKeyOrder(t, r.JSON())
	for i, k := range keys {
		if order[i] != k {
			t.Fatalf("key order %v, want %v", order, keys)
		}
	}
}

func jsonKeyOrder(t *testing.T, raw string) []string {
	t.Helper()
	d := json.NewDecoder(strings.NewReader(raw))
	if _, err := d.Token(); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for d.More() {
		token, err := d.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, token.(string))
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			t.Fatal(err)
		}
	}
	return keys
}
