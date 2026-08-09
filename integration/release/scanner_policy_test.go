package release_test

import (
	"encoding/json"
	"strings"
	"testing"
)

type scannerLock struct {
	ReviewDate string  `json:"review_date"`
	Gitleaks   scanner `json:"gitleaks"`
	Grype      scanner `json:"grype"`
}
type scanner struct {
	Image string `json:"image"`
	URL   string `json:"url"`
}

func TestScannerPolicy(t *testing.T) {
	var lock scannerLock
	if err := json.Unmarshal([]byte(read(t, "security/scanners.lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	if lock.ReviewDate != "2026-08-02" {
		t.Fatalf("review date = %q", lock.ReviewDate)
	}
	if lock.Gitleaks.Image != "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f" || lock.Grype.Image != "docker.io/anchore/grype:v0.116.1@sha256:1e71065c0a4cff3e6bd3b8add525ffac4343eb4971694eb90a31cf6d4d3e85db" {
		t.Fatal("scanner lock must retain reviewed version and OCI index digest")
	}
	for _, script := range []string{"scripts/verify-secrets.ps1", "scripts/verify-container.ps1"} {
		got := read(t, script)
		requireAll(t, got, "scanners.lock.json", "sha256:", "--read-only", "docker", "throw")
		if strings.Contains(got, "--only-fixed") {
			t.Fatalf("%s suppresses unfixed vulnerabilities", script)
		}
	}
	secrets := read(t, "scripts/verify-secrets.ps1")
	requireAll(t, secrets, "gitleaks", "--log-opts=--all", "dir", "--redact=100", "safe.directory")
	container := read(t, "scripts/verify-container.ps1")
	requireAll(t, container, "oci-archive:", "--fail-on", "high", "db", "update", "24", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev", "GRYPE_DB_CACHE_DIR=/grype-db", "volume", "create", "rm")
}
