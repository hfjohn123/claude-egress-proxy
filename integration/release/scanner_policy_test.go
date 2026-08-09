package release_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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

func TestContainerScanForwardsRequestedPlatformToGrype(t *testing.T) {
	temp := t.TempDir()
	logPath := filepath.Join(temp, "docker.log")
	archivePath := filepath.Join(temp, "image.tar")
	if err := os.WriteFile(archivePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	var shimPath, shim string
	if runtime.GOOS == "windows" {
		shimPath = filepath.Join(temp, "docker.cmd")
		shim = "@echo off\r\necho %*>>\"%DOCKER_LOG%\"\r\necho %* | findstr /c:\"oci-archive:/image.tar\" >nul && echo {}\r\nexit /b 0\r\n"
	} else {
		shimPath = filepath.Join(temp, "docker")
		shim = "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$DOCKER_LOG\"\ncase \" $* \" in *\"oci-archive:/image.tar\"*) printf '{}\\n';; esac\n"
	}
	if err := os.WriteFile(shimPath, []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}

	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "scripts", "verify-container.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("pwsh", "-NoProfile", "-File", scriptPath,
		"-Archive", archivePath,
		"-ReportDirectory", filepath.Join(temp, "report"),
		"-SourceCommit", "test-commit",
		"-Platform", "linux/arm64",
	)
	cmd.Env = append(os.Environ(), "DOCKER_LOG="+logPath, "PATH="+temp+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify-container.ps1 failed: %v\n%s", err, output)
	}
	got, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "--platform linux/arm64") {
		t.Fatalf("Grype invocation did not receive requested platform:\n%s", got)
	}
}
