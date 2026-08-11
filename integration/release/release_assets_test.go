package release_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestPrepareReleaseEvidenceNamespacesScanReports(t *testing.T) {
	temp := t.TempDir()
	scanRoot := filepath.Join(temp, "scan")
	want := map[string]string{
		"grype-linux-amd64.json":    "amd64-grype",
		"metadata-linux-amd64.json": "amd64-metadata",
		"grype-linux-arm64.json":    "arm64-grype",
		"metadata-linux-arm64.json": "arm64-metadata",
	}
	for _, fixture := range []struct {
		architecture string
		name         string
		body         string
	}{
		{"amd64", "grype.json", "amd64-grype"},
		{"amd64", "metadata.json", "amd64-metadata"},
		{"arm64", "grype.json", "arm64-grype"},
		{"arm64", "metadata.json", "arm64-metadata"},
	} {
		directory := filepath.Join(scanRoot, fixture.architecture)
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, fixture.name), []byte(fixture.body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	scriptPath, err := filepath.Abs(filepath.Join("..", "..", "scripts", "prepare-release-evidence.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	outputDirectory := filepath.Join(temp, "release-scans")
	cmd := exec.Command("pwsh", "-NoProfile", "-File", scriptPath,
		"-ScanRoot", scanRoot,
		"-OutputDirectory", outputDirectory,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("prepare-release-evidence.ps1 failed: %v\n%s", err, output)
	}

	entries, err := os.ReadDir(outputDirectory)
	if err != nil {
		t.Fatal(err)
	}
	gotNames := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotNames = append(gotNames, entry.Name())
		body, err := os.ReadFile(filepath.Join(outputDirectory, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != want[entry.Name()] {
			t.Fatalf("%s body = %q", entry.Name(), body)
		}
	}
	slices.Sort(gotNames)
	wantNames := []string{"grype-linux-amd64.json", "grype-linux-arm64.json", "metadata-linux-amd64.json", "metadata-linux-arm64.json"}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("release scan assets = %v, want %v", gotNames, wantNames)
	}
}
