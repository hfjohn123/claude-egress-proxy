package telemetry

import (
	"os"
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
