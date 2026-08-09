// profilegen renders the destination-policy artifacts from the sole manifest.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/hfjohn123/claude-egress-proxy/internal/hostname"
	"golang.org/x/net/publicsuffix"
	"gopkg.in/yaml.v3"
)

var outputPaths = []string{"internal/policy/generated_profiles.go", "docs/reference/profiles.md"}

type profile struct{ exact, suffixes []string }
type manifest struct {
	sourceURL, documentationDate            string
	publicSuffixModule, publicSuffixVersion string
	code, web, all                          profile
}

func main() {
	check := flag.Bool("check", false, "check generated files")
	flag.Parse()
	root, err := findRoot()
	if err == nil {
		var out map[string][]byte
		out, err = generate(root)
		if err == nil && *check {
			err = checkOutputs(root, out)
		}
		if err == nil && !*check {
			for path, body := range out {
				err = os.MkdirAll(filepath.Dir(filepath.Join(root, path)), 0o755)
				if err == nil {
					err = os.WriteFile(filepath.Join(root, path), body, 0o644)
				}
				if err != nil {
					break
				}
			}
		}
	}
	if err != nil {
		fail(err)
	}
}

func findRoot() (string, error) {
	root, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if fileNonempty(filepath.Join(root, "go.mod")) && fileNonempty(filepath.Join(root, "policy", "profiles.yaml")) {
			return root, nil
		}
		next := filepath.Dir(root)
		if next == root {
			return "", errors.New("repository root not found")
		}
		root = next
	}
}
func fileNonempty(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && len(bytes.TrimSpace(b)) != 0
}
func fail(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }

func generate(root string) (map[string][]byte, error) {
	b, err := os.ReadFile(filepath.Join(root, "policy", "profiles.yaml"))
	if err != nil {
		return nil, err
	}
	m, err := parseManifest(b)
	if err != nil {
		return nil, err
	}
	return map[string][]byte{"internal/policy/generated_profiles.go": renderGo(m), "docs/reference/profiles.md": renderDocs(m)}, nil
}
func checkOutputs(root string, out map[string][]byte) error {
	for _, path := range outputPaths {
		got, err := os.ReadFile(filepath.Join(root, path))
		if err != nil || !bytes.Equal(got, out[path]) {
			return fmt.Errorf("generated output drift: %s", path)
		}
	}
	return nil
}

func parseManifest(b []byte) (manifest, error) {
	var doc yaml.Node
	d := yaml.NewDecoder(bytes.NewReader(b))
	if err := d.Decode(&doc); err != nil {
		return manifest{}, err
	}
	var extra yaml.Node
	if d.Decode(&extra) != io.EOF {
		return manifest{}, errors.New("manifest has multiple documents")
	}
	if badNode(&doc) || len(doc.Content) != 1 {
		return manifest{}, errors.New("manifest uses aliases or tags")
	}
	top, err := mapping(doc.Content[0], []string{"format_version", "source_url", "documentation_date", "public_suffix_module", "public_suffix_version", "profiles"})
	if err != nil {
		return manifest{}, err
	}
	if scalar(top["format_version"], "1", "!!int") != nil || scalar(top["source_url"], "https://code.claude.com/docs/en/corporate-proxy", "!!str") != nil || scalar(top["documentation_date"], "2026-08-02", "!!str") != nil || scalar(top["public_suffix_module"], "golang.org/x/net", "!!str") != nil || scalar(top["public_suffix_version"], "v0.57.0", "!!str") != nil {
		return manifest{}, errors.New("manifest metadata is not canonical")
	}
	profiles, err := mapping(top["profiles"], []string{"code", "web-desktop", "all"})
	if err != nil {
		return manifest{}, err
	}
	code, err := leaf(profiles["code"])
	if err != nil {
		return manifest{}, err
	}
	web, err := leaf(profiles["web-desktop"])
	if err != nil {
		return manifest{}, err
	}
	all, err := mapping(profiles["all"], []string{"union"})
	if err != nil {
		return manifest{}, err
	}
	if !sequenceEqual(all["union"], []string{"code", "web-desktop"}) {
		return manifest{}, errors.New("all union is not canonical")
	}
	return manifest{sourceURL: top["source_url"].Value, documentationDate: top["documentation_date"].Value, publicSuffixModule: top["public_suffix_module"].Value, publicSuffixVersion: top["public_suffix_version"].Value, code: code, web: web, all: profile{exact: union(code.exact, web.exact), suffixes: union(code.suffixes, web.suffixes)}}, nil
}

func badNode(n *yaml.Node) bool {
	if n.Alias != nil || n.Anchor != "" || n.Tag == "!!merge" || n.Style&yaml.TaggedStyle != 0 {
		return true
	}
	for _, c := range n.Content {
		if badNode(c) {
			return true
		}
	}
	return false
}
func mapping(n *yaml.Node, keys []string) (map[string]*yaml.Node, error) {
	if n == nil || n.Kind != yaml.MappingNode || n.Tag != "!!map" || len(n.Content) != len(keys)*2 {
		return nil, errors.New("noncanonical mapping")
	}
	out := map[string]*yaml.Node{}
	for i, want := range keys {
		k, v := n.Content[2*i], n.Content[2*i+1]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" || k.Value != want {
			return nil, errors.New("unknown, missing, or unordered field")
		}
		out[want] = v
	}
	return out, nil
}
func scalar(n *yaml.Node, want, tag string) error {
	if n == nil || n.Kind != yaml.ScalarNode || n.Value != want || n.Tag != tag {
		return errors.New("invalid scalar")
	}
	return nil
}
func sequenceEqual(n *yaml.Node, want []string) bool {
	if n == nil || n.Kind != yaml.SequenceNode || n.Tag != "!!seq" || len(n.Content) != len(want) {
		return false
	}
	for i, s := range want {
		if scalar(n.Content[i], s, "!!str") != nil {
			return false
		}
	}
	return true
}
func leaf(n *yaml.Node) (profile, error) {
	m, err := mapping(n, []string{"exact_hosts", "suffixes"})
	if err != nil {
		return profile{}, err
	}
	exact, err := hostList(m["exact_hosts"], false)
	if err != nil {
		return profile{}, err
	}
	suffixes, err := hostList(m["suffixes"], true)
	if err != nil {
		return profile{}, err
	}
	return profile{exact, suffixes}, nil
}
func hostList(n *yaml.Node, suffix bool) ([]string, error) {
	if n == nil || n.Kind != yaml.SequenceNode || n.Tag != "!!seq" {
		return nil, errors.New("invalid host list")
	}
	out := make([]string, len(n.Content))
	for i, v := range n.Content {
		if scalar(v, v.Value, "!!str") != nil {
			return nil, errors.New("non-string host")
		}
		normalized, err := hostname.Normalize(v.Value)
		if err != nil || normalized != v.Value {
			return nil, errors.New("noncanonical host")
		}
		if suffix {
			public, _ := publicsuffix.PublicSuffix(normalized)
			if public == normalized {
				return nil, errors.New("public suffix")
			}
		}
		out[i] = normalized
	}
	if !sort.StringsAreSorted(out) {
		return nil, errors.New("unordered host list")
	}
	for i := 1; i < len(out); i++ {
		if out[i] == out[i-1] {
			return nil, errors.New("duplicate host")
		}
	}
	return out, nil
}
func union(a, b []string) []string {
	out := append(append([]string{}, a...), b...)
	sort.Strings(out)
	result := out[:0]
	for _, s := range out {
		if len(result) == 0 || result[len(result)-1] != s {
			result = append(result, s)
		}
	}
	return result
}
func quoted(items []string) string {
	out := make([]string, len(items))
	for i, v := range items {
		out[i] = strconv.Quote(v)
	}
	return "[]string{" + join(out, ", ") + "}"
}
func join(in []string, sep string) string {
	var b bytes.Buffer
	for i, s := range in {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteString(s)
	}
	return b.String()
}
func renderGo(m manifest) []byte {
	source := "// Code generated by profilegen; DO NOT EDIT.\npackage policy\n\nimport \"sort\"\n\nfunc sortedUnique(in []string) []string { sort.Strings(in); if len(in) == 0 { return in }; out := in[:1]; for _, s := range in[1:] { if s != out[len(out)-1] { out = append(out, s) } }; return out }\nfunc generatedProfile(name string) (Rules, bool) {\n\tcode := Rules{exactHosts: " + quoted(m.code.exact) + ", suffixes: " + quoted(m.code.suffixes) + "}\n\tweb := Rules{exactHosts: " + quoted(m.web.exact) + ", suffixes: " + quoted(m.web.suffixes) + "}\n\tswitch name { case \"code\": return code, true; case \"web-desktop\": return web, true; case \"all\": return Rules{exactHosts: sortedUnique(append(code.ExactHosts(), web.ExactHosts()...)), suffixes: sortedUnique(append(code.Suffixes(), web.Suffixes()...))}, true; default: return Rules{}, false }\n}\n"
	out, err := format.Source([]byte(source))
	if err != nil {
		panic(err)
	}
	return out
}
func renderDocs(m manifest) []byte {
	var out bytes.Buffer
	out.WriteString("# Destination profiles\n\n")
	out.WriteString("Generated from `policy/profiles.yaml`. Source: `" + m.sourceURL + "` (documentation date `" + m.documentationDate + "`). Public Suffix List module: `" + m.publicSuffixModule + " " + m.publicSuffixVersion + "`.\n\n")
	for _, p := range []struct {
		name  string
		rules profile
	}{{"code", m.code}, {"web-desktop", m.web}, {"all", m.all}} {
		out.WriteString("## `" + p.name + "`\n\n| Rule | Values |\n| --- | --- |\n")
		out.WriteString("| exact hosts | " + join(p.rules.exact, "<br>") + " |\n")
		out.WriteString("| suffixes | " + join(p.rules.suffixes, "<br>") + " |\n\n")
	}
	return append(bytes.TrimRight(out.Bytes(), "\n"), '\n')
}
