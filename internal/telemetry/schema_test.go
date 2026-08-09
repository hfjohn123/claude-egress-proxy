package telemetry

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSchemaHasClosedSurface(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "schema", "telemetry.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, required := range []string{"claude_proxy_tls_handshakes_total", "claude_proxy_tunnel_duration_seconds", "matrix_33_service_state_transition", "silence_12_initial_safe_credential_absence_no_reload_log", "reload_07_scheduled_public_self_source_bind_acme_attempt", "lifecycle_09_noncredential_recovery_readiness", "destination_hostname", "duration_ms"} {
		if !strings.Contains(s, required) {
			t.Fatalf("schema missing %s", required)
		}
	}
	if got := strings.Count(s, "id: matrix_"); got != 33 {
		t.Fatalf("matrix cases = %d, want 33", got)
	}
	if got := strings.Count(s, "id: silence_"); got != 12 {
		t.Fatalf("silence cases = %d, want 12", got)
	}
}

func TestFrameworkSilenceNeverNamesRemovedFrameworkToken(t *testing.T) {
	for _, path := range []string{"schema/telemetry.yaml", "internal/telemetry/generated.go", "docs/reference/telemetry.md"} {
		b, err := os.ReadFile(filepath.Join("..", "..", path))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "header_"+"too_large") {
			t.Fatalf("%s names removed framework token", path)
		}
	}
}

func TestGeneratedRecordLookupHasNoMutableExport(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "internal", "telemetry", "generated.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"RecordTuple", "GeneratedRecordTuples"} {
		if strings.Contains(string(b), forbidden) {
			t.Fatalf("generated record lookup exports mutable surface %s", forbidden)
		}
	}
	if !strings.Contains(string(b), "func generatedRecordLevel(") {
		t.Fatal("generated immutable lookup missing")
	}
}

// This fails if telemetrygen stops treating both checked-in artifacts as
// manifest renderings (rather than only checking a convenient subset).
func TestGeneratorCheckRejectsMissingAndDriftedOwnedOutput(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, path := range []string{"internal/telemetry/generated.go", "docs/reference/telemetry.md"} {
		full := filepath.Join(root, path)
		original, err := os.ReadFile(full)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.WriteFile(full, original, 0644) })
		if err := os.WriteFile(full, append(original, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("go", "run", "./internal/tools/telemetrygen", "-check")
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err == nil || bytes.Contains(output, []byte("panic")) {
			t.Fatalf("check accepted drift in %s: %v %s", path, err, output)
		}
		if err := os.WriteFile(full, original, 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(full); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command("go", "run", "./internal/tools/telemetrygen", "-check")
		cmd.Dir = root
		if output, err := cmd.CombinedOutput(); err == nil || bytes.Contains(output, []byte("panic")) {
			t.Fatalf("check accepted missing %s: %v %s", path, err, output)
		}
		if err := os.WriteFile(full, original, 0644); err != nil {
			t.Fatal(err)
		}
	}
}
