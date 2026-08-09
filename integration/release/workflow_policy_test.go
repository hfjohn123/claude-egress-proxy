package release_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(filepath.Join("..", "..", path)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func requireAll(t *testing.T, got string, want ...string) {
	t.Helper()
	for _, s := range want {
		if !strings.Contains(got, s) {
			t.Errorf("missing %q", s)
		}
	}
}

func TestWorkflowPolicy(t *testing.T) {
	ci := read(t, ".github/workflows/ci.yml")
	release := read(t, ".github/workflows/release.yml")
	for name, workflow := range map[string]string{"ci": ci, "release": release} {
		requireAll(t, workflow, "permissions:", "contents: read", "fetch-depth: 0", "go-version: '1.26.5'")
		for _, line := range strings.Split(workflow, "\n") {
			if strings.Contains(line, "uses:") && (strings.Contains(line, "@v") || strings.Contains(line, "@main") || strings.Contains(line, "@master")) {
				t.Errorf("%s has floating action reference", name)
			}
		}
	}
	requireAll(t, ci, "ubuntu-latest", "windows-latest", "go vet ./...", "go test ./... -count=1", "go test -race", "FuzzAuthority", "FuzzCredentialDecode", "FuzzBasicVerifier", "FuzzFramingValues", "verify-generated.ps1", "verify-public-data.ps1", "govulncheck@v1.6.0", "verify-secrets.ps1", "verify-container.ps1", "windows/amd64", "windows/arm64", "retention-days:")
	requireAll(t, release, "workflow_dispatch:", "draft: true", "windows/amd64", "windows/arm64", "linux/amd64", "linux/arm64")
	requireAll(t, release,
		"needs: [secrets, build-binaries, scan-linux-amd64, scan-linux-arm64]",
		"needs: [publish, release-evidence]",
		"contents: write",
		"provenance.intoto.jsonl",
		"--sbom=true",
		"--provenance=mode=max",
		"attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
		"release-evidence",
	)
	if strings.Contains(ci+release, "RequestURI") {
		t.Fatal("CI must not add a custom HTTP parser fuzz target")
	}
}

func TestLocalScriptPolicy(t *testing.T) {
	local := read(t, "scripts/verify-local.ps1")
	requireAll(t, local, "$ErrorActionPreference = 'Stop'", "$PSNativeCommandUseErrorActionPreference = $true", "function Invoke-CheckedNative", "gofmt", "'generate', './...'", "verify-generated.ps1", "'mod', 'tidy'", "'diff', '--exit-code', '--', 'go.mod', 'go.sum'", "'vet', './...'", "'test', './...', '-count=1'", "-tags=cep_testcontrol", "CEP_TEST_BINARY", "finally", "'test', '-tags=resource', './integration/resource', '-count=1', '-timeout=25m', '-v'", "FuzzAuthority", "FuzzCredentialDecode", "FuzzBasicVerifier", "FuzzFramingValues", "verify-public-data.ps1", "verify-secrets.ps1", "verify-release.ps1", "govulncheck@v1.6.0", "CEP_LOCAL_VERIFICATION_OK")
	if strings.Contains(local, "go fmt") {
		t.Fatal("local acceptance must not mutate source with go fmt")
	}
}
