package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateRejectsSchemaAndDetectsDrift(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "policy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module test\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bad := []byte("format_version: 1\nsource_url: https://code.claude.com/docs/en/corporate-proxy\ndocumentation_date: \"2026-08-02\"\npublic_suffix_module: golang.org/x/net\npublic_suffix_version: v0.57.0\nextra: no\nprofiles: {}\n")
	if err := os.WriteFile(filepath.Join(root, "policy", "profiles.yaml"), bad, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := generate(root); err == nil {
		t.Fatal("accepted unknown manifest field")
	}
	if err := os.WriteFile(filepath.Join(root, "policy", "profiles.yaml"), []byte(validManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := generate(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkOutputs(root, out); err == nil {
		t.Fatal("accepted missing generated outputs")
	}
	for path, body := range out {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, path), body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := checkOutputs(root, out); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "docs", "reference", "profiles.md"), []byte("drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkOutputs(root, out); err == nil {
		t.Fatal("accepted drift")
	}
}

func TestParseManifestRejectsAliasesTagsAndNoncanonicalRules(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"alias": func(s string) string { return strings.Replace(s, "code:\n", "code: &code\n", 1) },
		"tag":   func(s string) string { return strings.Replace(s, "api.anthropic.com", "!bad api.anthropic.com", 1) },
		"duplicate": func(s string) string {
			return strings.Replace(s, "      - api.anthropic.com\n", "      - api.anthropic.com\n      - api.anthropic.com\n", 1)
		},
		"wildcard":      func(s string) string { return strings.Replace(s, "api.anthropic.com", "*.anthropic.com", 1) },
		"public suffix": func(s string) string { return strings.Replace(s, "claudeusercontent.com", "com", 1) },
		"union order": func(s string) string {
			return strings.Replace(s, "union: [code, web-desktop]", "union: [web-desktop, code]", 1)
		},
		"quoted format version": func(s string) string { return strings.Replace(s, "format_version: 1", "format_version: \"1\"", 1) },
		"integer metadata": func(s string) string {
			return strings.Replace(s, "documentation_date: \"2026-08-02\"", "documentation_date: 1", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseManifest([]byte(mutate(validManifest))); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
	}
}

func TestGeneratedDocsRenderManifestMetadataAndProfiles(t *testing.T) {
	m, err := parseManifest([]byte(validManifest))
	if err != nil {
		t.Fatal(err)
	}
	docs := string(renderDocs(m))
	apiHost := "api." + "anthropic.com"
	contentHost := "claudeusercontent.com"
	for _, want := range []string{"https://code.claude.com/docs/en/corporate-proxy", "2026-08-02", "golang.org/x/net v0.57.0", apiHost, contentHost} {
		if !strings.Contains(docs, want) {
			t.Fatalf("docs missing %q: %s", want, docs)
		}
	}
	changed := strings.Replace(validManifest, apiHost, "api2."+"anthropic.com", 1)
	m2, err := parseManifest([]byte(changed))
	if err != nil {
		t.Fatal(err)
	}
	if string(renderGo(m)) == string(renderGo(m2)) || string(renderDocs(m)) == string(renderDocs(m2)) {
		t.Fatal("manifest host did not change both generated artifacts")
	}
}

func TestGeneratorBuildsAndRepairsMissingOwnedOutput(t *testing.T) {
	source, err := findRoot()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	for _, path := range []string{"go.mod", "go.sum", "policy/profiles.yaml", "internal/tools/profilegen/main.go", "internal/hostname/hostname.go"} {
		body, err := os.ReadFile(filepath.Join(source, path))
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(output), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(output, body, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := exec.Command("go", "run", "./internal/tools/profilegen", "-check")
	check.Dir = root
	if out, err := check.CombinedOutput(); err == nil || !strings.Contains(string(out), "generated output drift") {
		t.Fatalf("check missing output = %v: %s", err, out)
	}
	generate := exec.Command("go", "run", "./internal/tools/profilegen")
	generate.Dir = root
	if out, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("generate = %v: %s", err, out)
	}
	check = exec.Command("go", "run", "./internal/tools/profilegen", "-check")
	check.Dir = root
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("check after generate = %v: %s", err, out)
	}
}

const validManifest = `format_version: 1
source_url: https://code.claude.com/docs/en/corporate-proxy
documentation_date: "2026-08-02"
public_suffix_module: golang.org/x/net
public_suffix_version: v0.57.0
profiles:
  code:
    exact_hosts:
      - api.anthropic.com
    suffixes: []
  web-desktop:
    exact_hosts:
      - claude.ai
    suffixes:
      - claudeusercontent.com
  all:
    union: [code, web-desktop]
`
