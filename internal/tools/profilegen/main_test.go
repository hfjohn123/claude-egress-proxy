package main

import (
	"os"
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
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseManifest([]byte(mutate(validManifest))); err == nil {
				t.Fatal("accepted invalid manifest")
			}
		})
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
