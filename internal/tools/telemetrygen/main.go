// telemetrygen renders the two artifacts owned by schema/telemetry.yaml.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

var owned = []string{"internal/telemetry/generated.go", "docs/reference/telemetry.md"}

type manifest struct {
	Version      string     `yaml:"version"`
	Metrics      []metric   `yaml:"metrics"`
	LimiterPairs []string   `yaml:"limiter_pairs"`
	Records      records    `yaml:"records"`
	Matrix       []emission `yaml:"matrix"`
	Silence      []emission `yaml:"silence"`
	Reload       []string   `yaml:"reload"`
	Lifecycle    []string   `yaml:"lifecycle"`
}
type metric struct {
	Name, Type, Help        string
	Labels, Values, Buckets []string
}
type records struct {
	Base, Sensitive []string
	MaxBytes        int `yaml:"max_bytes"`
}
type emission struct {
	ID             string `yaml:"id"`
	PrimaryEmitter string `yaml:"primary_emitter"`
	Emission       string `yaml:"emission"`
}

func main() {
	check := flag.Bool("check", false, "check generated files")
	flag.Parse()
	root, err := findRoot()
	if err != nil {
		fatal(err)
	}
	m, err := readManifest(filepath.Join(root, "schema", "telemetry.yaml"))
	if err != nil {
		fatal(err)
	}
	goText, err := renderGo(m)
	if err != nil {
		fatal(err)
	}
	docText := renderDocs(m)
	want := map[string][]byte{owned[0]: goText, owned[1]: []byte(docText)}
	for _, path := range owned {
		full := filepath.Join(root, path)
		if *check {
			got, err := os.ReadFile(full)
			if err != nil {
				fatal(fmt.Errorf("generated output missing %s: %w", path, err))
			}
			if !bytes.Equal(got, want[path]) {
				fatal(fmt.Errorf("generated file differs: %s", path))
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0755); err != nil {
			fatal(err)
		}
		if err := os.WriteFile(full, want[path], 0644); err != nil {
			fatal(err)
		}
	}
}

func readManifest(path string) (manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, err
	}
	var n yaml.Node
	if err := yaml.Unmarshal(b, &n); err != nil {
		return manifest{}, fmt.Errorf("invalid telemetry manifest: %w", err)
	}
	if len(n.Content) != 1 || n.Content[0].Kind != yaml.MappingNode {
		return manifest{}, fmt.Errorf("manifest must be one mapping")
	}
	if err := rejectUnknown(n.Content[0], map[string]bool{"version": true, "metrics": true, "limiter_pairs": true, "records": true, "matrix": true, "silence": true, "reload": true, "lifecycle": true}); err != nil {
		return manifest{}, err
	}
	var m manifest
	d := yaml.NewDecoder(bytes.NewReader(b))
	d.KnownFields(true)
	if err := d.Decode(&m); err != nil {
		return manifest{}, fmt.Errorf("invalid telemetry manifest: %w", err)
	}
	if err := validate(m); err != nil {
		return manifest{}, err
	}
	return m, nil
}
func rejectUnknown(n *yaml.Node, allowed map[string]bool) error {
	seen := map[string]bool{}
	for i := 0; i < len(n.Content); i += 2 {
		k := n.Content[i].Value
		if !allowed[k] {
			return fmt.Errorf("unknown manifest field %q", k)
		}
		if seen[k] {
			return fmt.Errorf("duplicate manifest field %q", k)
		}
		seen[k] = true
	}
	return nil
}
func validate(m manifest) error {
	if m.Version != "v1" || len(m.Metrics) != 17 || m.Records.MaxBytes != 2047 {
		return fmt.Errorf("invalid manifest version, metric count, or record bound")
	}
	metricNames := []string{"claude_proxy_tls_handshakes_total", "claude_proxy_authentication_total", "claude_proxy_connect_total", "claude_proxy_tunnel_closes_total", "claude_proxy_pac_total", "claude_proxy_limiter_events_total", "claude_proxy_reload_total", "claude_proxy_log_records_total", "claude_proxy_bytes_total", "claude_proxy_limiter_entries", "claude_proxy_pre_auth_connections", "claude_proxy_pending_setup_reservations", "claude_proxy_active_tunnels", "claude_proxy_credential_generation", "claude_proxy_certificate_expiry_seconds", "claude_proxy_setup_duration_seconds", "claude_proxy_tunnel_duration_seconds"}
	for i, x := range m.Metrics {
		if x.Name != metricNames[i] || x.Help == "" || (x.Type != "counter" && x.Type != "gauge" && x.Type != "histogram") {
			return fmt.Errorf("invalid or reordered metric row %d", i)
		}
		if x.Type == "histogram" && (len(x.Buckets) < 2 || x.Buckets[len(x.Buckets)-1] != "+Inf") {
			return fmt.Errorf("invalid histogram buckets for %s", x.Name)
		}
	}
	if !slices.Equal(m.Metrics[5].Labels, []string{"limiter", "event"}) || !slices.Equal(m.Metrics[6].Labels, []string{"kind", "result"}) || !slices.Equal(m.Metrics[15].Labels, []string{"outcome"}) || !slices.Equal(m.Metrics[16].Labels, []string{"outcome"}) {
		return fmt.Errorf("invalid closed label order")
	}
	if !slices.Equal(m.LimiterPairs, []string{"tls_handshake/allowed", "tls_handshake/throttled", "tls_handshake/entry_expired", "tls_handshake/saturation_overflow", "authentication/allowed", "authentication/throttled", "authentication/entry_expired", "authentication/map_full", "pac/allowed", "pac/throttled", "pac/entry_expired", "pac/map_full"}) {
		return fmt.Errorf("invalid closed limiter pairs")
	}
	if err := validateCases("matrix", m.Matrix, 33, "matrix_"); err != nil {
		return err
	}
	if err := validateCases("silence", m.Silence, 12, "silence_"); err != nil {
		return err
	}
	if err := validateIDs("reload", m.Reload, 7, "reload_"); err != nil {
		return err
	}
	if err := validateIDs("lifecycle", m.Lifecycle, 9, "lifecycle_"); err != nil {
		return err
	}
	if len(m.LimiterPairs) != 12 || len(m.Records.Base) != 4 || len(m.Records.Sensitive) != 6 {
		return fmt.Errorf("incomplete closed telemetry rows")
	}
	return nil
}
func validateCases(kind string, rows []emission, want int, prefix string) error {
	if len(rows) != want {
		return fmt.Errorf("%s rows=%d want=%d", kind, len(rows), want)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if !strings.HasPrefix(r.ID, prefix) || r.PrimaryEmitter == "" || seen[r.ID] {
			return fmt.Errorf("invalid %s row %q", kind, r.ID)
		}
		seen[r.ID] = true
	}
	return nil
}
func validateIDs(kind string, rows []string, want int, prefix string) error {
	if len(rows) != want {
		return fmt.Errorf("%s rows=%d want=%d", kind, len(rows), want)
	}
	seen := map[string]bool{}
	for _, id := range rows {
		if !strings.HasPrefix(id, prefix) || seen[id] {
			return fmt.Errorf("invalid %s row %q", kind, id)
		}
		seen[id] = true
	}
	return nil
}

func renderGo(m manifest) ([]byte, error) {
	var b strings.Builder
	b.WriteString("// Code generated by telemetrygen; DO NOT EDIT.\n\npackage telemetry\n\n")
	b.WriteString("const schemaVersion = \"v1\"\n\n")
	b.WriteString("type MetricDefinition struct { Name, Type, Help string; Labels, Values []string; Buckets []float64 }\n")
	b.WriteString("var MetricDefinitions = []MetricDefinition{\n")
	for _, x := range m.Metrics {
		fmt.Fprintf(&b, "{Name:%q, Type:%q, Help:%q, Labels:%#v, Values:%#v", x.Name, x.Type, x.Help, x.Labels, x.Values)
		if len(x.Buckets) > 0 {
			b.WriteString(", Buckets:[]float64{")
			for _, v := range x.Buckets[:len(x.Buckets)-1] {
				fmt.Fprintf(&b, "%s,", v)
			}
			b.WriteString("}")
		}
		b.WriteString("},\n")
	}
	b.WriteString("}\n\ntype EmissionCase struct { ID, PrimaryEmitter, Emission string }\n")
	b.WriteString("type RecordSchema struct { Base, Sensitive []string; MaxBytes int }\n")
	fmt.Fprintf(&b, "var GeneratedRecordSchema = RecordSchema{Base:%#v, Sensitive:%#v, MaxBytes:%d}\n", m.Records.Base, m.Records.Sensitive, m.Records.MaxBytes)
	b.WriteString("var ValidLimiterPairs = map[string]bool{\n")
	for _, pair := range m.LimiterPairs {
		fmt.Fprintf(&b, "%q:true,\n", pair)
	}
	b.WriteString("}\n")
	renderCases(&b, "MatrixCases", m.Matrix)
	renderCases(&b, "SilenceCases", m.Silence)
	renderIDs(&b, "ReloadCases", m.Reload, "reload")
	renderIDs(&b, "LifecycleCases", m.Lifecycle, "service")
	return format.Source([]byte(b.String()))
}
func renderCases(b *strings.Builder, name string, rows []emission) {
	fmt.Fprintf(b, "var %s = []EmissionCase{\n", name)
	for _, r := range rows {
		fmt.Fprintf(b, "{ID:%q, PrimaryEmitter:%q, Emission:%q},\n", r.ID, r.PrimaryEmitter, r.Emission)
	}
	b.WriteString("}\n")
}
func renderIDs(b *strings.Builder, name string, rows []string, owner string) {
	fmt.Fprintf(b, "var %s = []EmissionCase{\n", name)
	for _, id := range rows {
		fmt.Fprintf(b, "{ID:%q, PrimaryEmitter:%q},\n", id, owner)
	}
	b.WriteString("}\n")
}
func renderDocs(m manifest) string {
	var b strings.Builder
	b.WriteString("# Telemetry\n\nThis reference is generated from `schema/telemetry.yaml`; its labels and values are closed.\n\n## Metrics\n\n| Family | Type | Labels | Allowed values | HELP |\n| --- | --- | --- | --- | --- |\n")
	for _, x := range m.Metrics {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s |\n", x.Name, x.Type, strings.Join(x.Labels, ", "), strings.Join(x.Values, ", "), x.Help)
		if len(x.Buckets) > 0 {
			fmt.Fprintf(&b, "\nBuckets: `%s`.\n", strings.Join(x.Buckets, "`, `"))
		}
	}
	b.WriteString("\n## Records\n\nBase fields: `" + strings.Join(m.Records.Base, "`, `") + "`. Sensitive tunnel extension (all-or-none): `" + strings.Join(m.Records.Sensitive, "`, `") + fmt.Sprintf("`. Maximum JSON size: %d bytes.\n", m.Records.MaxBytes))
	renderDocCases(&b, "Primary emission matrix", m.Matrix)
	renderDocCases(&b, "Deliberate silence", m.Silence)
	renderDocIDs(&b, "Reload cases", m.Reload)
	renderDocIDs(&b, "Lifecycle cases", m.Lifecycle)
	return b.String()
}
func renderDocCases(b *strings.Builder, title string, rows []emission) {
	b.WriteString("\n## " + title + "\n\n| ID | Owner | Emission |\n| --- | --- | --- |\n")
	for _, r := range rows {
		fmt.Fprintf(b, "| `%s` | `%s` | %s |\n", r.ID, r.PrimaryEmitter, r.Emission)
	}
}
func renderDocIDs(b *strings.Builder, title string, rows []string) {
	b.WriteString("\n## " + title + "\n\n")
	for _, r := range rows {
		fmt.Fprintf(b, "- `%s`\n", r)
	}
}
func findRoot() (string, error) {
	d, e := os.Getwd()
	if e != nil {
		return "", e
	}
	for {
		if _, e = os.Stat(filepath.Join(d, "go.mod")); e == nil {
			return d, nil
		}
		n := filepath.Dir(d)
		if n == d {
			return "", fmt.Errorf("go.mod not found")
		}
		d = n
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
