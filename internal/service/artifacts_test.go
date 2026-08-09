package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemdArtifactUsesBoundedServiceProfile(t *testing.T) {
	unit := readArtifact(t, "deploy", "systemd", "claude-egress-proxy.service")
	for _, want := range []string{
		"User=claude-egress-proxy", "Group=claude-egress-proxy",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE", "AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=true", "ProtectSystem=strict", "PrivateTmp=true",
		"StandardOutput=null", "StandardError=journal", "TimeoutStopSec=25s",
		"ExecStart=/usr/local/bin/claude-egress-proxy --config /etc/claude-egress-proxy/config.yaml serve",
	} {
		if !strings.Contains(unit, want+"\n") {
			t.Fatalf("systemd unit missing %q", want)
		}
	}
}

func TestContainerArtifactsUseNonRootBoundedProfile(t *testing.T) {
	dockerfile := readArtifact(t, "deploy", "docker", "Dockerfile")
	for _, want := range []string{
		"USER 65532:65532", "EXPOSE 8443", "STOPSIGNAL SIGTERM",
		`HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/usr/local/bin/claude-egress-proxy","check","health","--address","127.0.0.1:9090"]`,
	} {
		if !strings.Contains(dockerfile, want) {
			t.Fatalf("Dockerfile missing %q", want)
		}
	}
	for _, forbidden := range []string{"/bin/sh", "curl", "wget"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Fatalf("Dockerfile contains forbidden %q", forbidden)
		}
	}
	compose := readArtifact(t, "deploy", "docker", "compose.yaml")
	for _, want := range []string{
		"- \"443:8443\"", "read_only: true", "cap_drop:", "- ALL",
		"stop_signal: SIGTERM", "stop_grace_period: 25s", "- /etc/claude-egress-proxy/config.yaml:/etc/claude-egress-proxy/config.yaml:ro",
		"- claude-egress-proxy-state:/var/lib/claude-egress-proxy:rw",
	} {
		if !strings.Contains(compose, want) {
			t.Fatalf("compose missing %q", want)
		}
	}
}

func readArtifact(t *testing.T, path ...string) string {
	t.Helper()
	full := filepath.Join(append([]string{"..", ".."}, path...)...)
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
