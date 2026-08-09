package docs_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDocumentationContract(t *testing.T) {
	root := filepath.Join("..", "..")
	required := map[string][]string{
		"README.md": {"server-only", "not affiliated", "does not provide a client"},
		"docs/configuration.md": {"generated configuration", "per_device_capacity", "absolute_tunnel_lifetime", "graceful_shutdown_drain"},
		"docs/security.md": {"checkpoint restore", "rotate", "payload"},
		"docs/deploy-home.md": {"CGNAT", "TLS-ALPN-01", "443"},
		"docs/deploy-vps.md": {"--stop-timeout 25", "systemd", "Compose"},
		"docs/client-configuration.md": {"HTTPS_PROXY", "NO_PROXY", "cannot prevent"},
		"docs/compatibility.md": {"Claude Code", "Claude Desktop", "Cowork", "manual"},
		"docs/release-checklist.md": {"verify-claude-code-interop.ps1", "sanitized"},
	}
	for name, want := range required {
		body, err := os.ReadFile(filepath.Join(root, name))
		if err != nil { t.Fatalf("read %s: %v", name, err) }
		text := strings.ToLower(string(body))
		for _, phrase := range want {
			if !strings.Contains(text, strings.ToLower(phrase)) { t.Errorf("%s missing %q", name, phrase) }
		}
	}
}

func TestDocumentationContainsNoClientOrSecretClaims(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, dir := range []string{"docs", "."} {
		entries, err := os.ReadDir(filepath.Join(root, dir))
		if err != nil { t.Fatal(err) }
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") { continue }
			path := filepath.Join(root, dir, entry.Name())
			body, err := os.ReadFile(path); if err != nil { t.Fatal(err) }
			text := strings.ToLower(string(body))
			for _, forbidden := range []string{"api_key", "secret=", "install the client", "enforces pac", "prevents direct bypass"} {
				if strings.Contains(text, forbidden) { t.Errorf("%s contains prohibited claim/fixture %q", path, forbidden) }
			}
		}
	}
}
