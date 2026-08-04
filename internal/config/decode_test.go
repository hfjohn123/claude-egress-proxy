package config_test

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

func validDocument(t *testing.T) []byte {
	t.Helper()
	return []byte(fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\n", filepath.Join(t.TempDir(), "state")))
}

func TestDecodeAppliesClosedDefaultsAndReturnsDefensiveLists(t *testing.T) {
	cfg, err := config.Decode(validDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FormatVersion() != 1 || cfg.InstanceID() != [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15} {
		t.Fatalf("identity defaults = %d %x", cfg.FormatVersion(), cfg.InstanceID())
	}
	addresses := cfg.PublicListener().Addresses()
	if len(addresses) != 1 || addresses[0] != netip.MustParseAddrPort("0.0.0.0:443") || cfg.PublicListener().PACEnabled() {
		t.Fatalf("public defaults = %v pac=%v", addresses, cfg.PublicListener().PACEnabled())
	}
	addresses[0] = netip.MustParseAddrPort("127.0.0.1:1")
	if cfg.PublicListener().Addresses()[0] != netip.MustParseAddrPort("0.0.0.0:443") {
		t.Fatal("caller mutated immutable address list")
	}
	if cfg.AdminListener().Enabled() || cfg.Resolver().Mode() != config.ResolverSystem || cfg.PerDeviceCapacity() != 64 {
		t.Fatal("listener/resolver/capacity defaults differ")
	}
	if _, ok := cfg.AbsoluteTunnelLifetime(); ok || cfg.GracefulShutdownDrain() != 20*time.Second || cfg.Destination().Profile() != config.ProfileCode || cfg.Logging().Sink() != config.LogSinkDefault || cfg.Metrics().Enabled() {
		t.Fatal("duration/destination/logging/metrics defaults differ")
	}
}

func TestDecodeRejectsClosedSchemaAndNonCanonicalYAML(t *testing.T) {
	base := string(validDocument(t))
	tests := map[string]string{
		"unknown":         base + "setup_timeout: 1\n",
		"duplicate":       strings.Replace(base, "format_version: 1\n", "format_version: 1\nformat_version: 1\n", 1),
		"alias":           base + "destination: &d {profile: code}\nlogging: *d\n",
		"second document": base + "---\nformat_version: 1\n",
		"quoted integer":  strings.Replace(base, "format_version: 1", "format_version: \"1\"", 1),
		"BOM":             "\ufeff" + base,
		"invalid UTF-8":   base + string([]byte{0xff}),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := config.Decode([]byte(doc))
			if err == nil {
				t.Fatal("Decode accepted invalid document")
			}
			if name == "unknown" && !errors.Is(err, config.ErrUnknownField) {
				t.Fatalf("unknown error = %v", err)
			}
		})
	}
	tooLarge := make([]byte, contract.V1().ConfigBytes+1)
	if _, err := config.Decode(tooLarge); !errors.Is(err, config.ErrSyntax) {
		t.Fatalf("oversize Decode error = %v", err)
	}
}

func TestDecodeValidatesBoundsAndCrossFields(t *testing.T) {
	base := string(validDocument(t))
	tests := map[string]string{
		"zero capacity":             base + "per_device_capacity: 0\n",
		"capacity over max":         base + "per_device_capacity: 65\n",
		"capacity integer overflow": base + "per_device_capacity: 18446744073709551615\n",
		"duration leading zero":     base + "absolute_tunnel_lifetime: 01h\n",
		"drain below min":           base + "graceful_shutdown_drain: 4s\n",
		"lifetime above max":        base + "absolute_tunnel_lifetime: 169h\n",
		"drain above max":           base + "graceful_shutdown_drain: 21s\n",
		"metrics no admin":          base + "metrics:\n  enabled: true\n",
		"system resolver address":   base + "resolver:\n  mode: system\n  address: 1.1.1.1:53\n",
		"explicit empty source":     base + "outbound_source_ipv4: ''\n",
		"empty admin address":       base + "admin_listener:\n  enabled: true\n  address: ''\n",
		"forbidden ACME file key":   strings.Replace(base, "tls:\n  mode: acme\n  hostname: proxy.example.com\n", "tls:\n  mode: acme\n  hostname: proxy.example.com\n  certificate_file: ''\n", 1),
		"ACME wrong port":           strings.Replace(base, "tls:\n", "public_listener:\n  addresses: [0.0.0.0:8443]\n  pac_enabled: false\ntls:\n", 1),
		"bad hostname":              strings.Replace(base, "proxy.example.com", "Proxy_example.com", 1),
		"bad instance":              strings.Replace(base, "000102030405060708090a0b0c0d0e0f", "ABC", 1),
	}
	for name, doc := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Decode([]byte(doc)); !errors.Is(err, config.ErrValue) {
				t.Fatalf("Decode error = %v, want ErrValue", err)
			}
		})
	}
}

func TestDecodeRejectsEveryFixedConstantOverride(t *testing.T) {
	for _, key := range []string{"setup_timeout", "global_capacity", "header_bytes", "pac_work_slots"} {
		if _, err := config.Decode(append(validDocument(t), []byte(key+": 1\n")...)); !errors.Is(err, config.ErrUnknownField) {
			t.Fatalf("%s error = %v", key, err)
		}
	}
}

func TestDecodeRejectsNestedUnknownDuplicateAndCustomRuleOverflow(t *testing.T) {
	base := string(validDocument(t))
	cases := []string{
		base + "metrics:\n  enabled: false\n  future: false\n",
		base + "metrics:\n  enabled: false\n  enabled: false\n",
		base + "destination:\n  profile: code\n  exact_hosts: [" + strings.TrimSuffix(strings.Repeat("x.example, ", 129), ", ") + "]\n",
	}
	for _, doc := range cases {
		if _, err := config.Decode([]byte(doc)); err == nil {
			t.Fatal("Decode accepted nested schema violation")
		}
	}
}

func TestRenderExampleIsDeterministicAndPureValid(t *testing.T) {
	id := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	state := filepath.Join(t.TempDir(), "state")
	one, two := config.RenderExample(id, state), config.RenderExample(id, state)
	if string(one) != string(two) || len(one) == 0 || one[len(one)-1] != '\n' || strings.Contains(string(one), "\r") {
		t.Fatal("RenderExample is not deterministic LF-only YAML")
	}
	if _, err := config.Decode(one); err != nil {
		t.Fatalf("rendered example is not pure-valid: %v", err)
	}
}

func TestDecodeValidMinDefaultAndMaxFixtures(t *testing.T) {
	for _, name := range []string{"valid-min.yaml", "valid-default.yaml", "valid-max.yaml"} {
		t.Run(name, func(t *testing.T) {
			doc, err := os.ReadFile(filepath.Join("testdata", name))
			if err != nil {
				t.Fatal(err)
			}
			doc = []byte(strings.Replace(string(doc), "/var/lib/claude-egress-proxy", fmt.Sprintf("%q", filepath.Join(t.TempDir(), "state")), 1))
			if _, err := config.Decode(doc); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDecodeAcceptsExactConfigByteLimit(t *testing.T) {
	doc := validDocument(t)
	remaining := contract.V1().ConfigBytes - len(doc)
	if remaining < 2 {
		t.Fatal("fixture unexpectedly large")
	}
	doc = append(doc, []byte("#"+strings.Repeat("x", remaining-2)+"\n")...)
	if len(doc) != contract.V1().ConfigBytes {
		t.Fatalf("size = %d", len(doc))
	}
	if _, err := config.Decode(doc); err != nil {
		t.Fatalf("exact limit = %v", err)
	}
}

func TestDecodeRejectsIANAIPv4RangesThatAreNotGloballyReachable(t *testing.T) {
	for _, field := range []string{"outbound_source_ipv4: %s\n", "public_self_ipv4s: [%s]\n"} {
		for _, address := range []string{"100.64.0.1", "192.0.2.1", "198.18.0.1", "203.0.113.1", "240.0.0.1", "255.255.255.254"} {
			doc := append(validDocument(t), []byte(fmt.Sprintf(field, address))...)
			if _, err := config.Decode(doc); !errors.Is(err, config.ErrValue) {
				t.Fatalf("%q %s error = %v", field, address, err)
			}
		}
	}
}

func TestDecodeMapsInvalidDestinationRulesToValue(t *testing.T) {
	for _, destination := range []string{
		"exact_hosts: [bücher..example]", "exact_hosts: [api.anthropic.com, api.anthropic.com]",
		"suffixes: [com]", "suffixes: [example.invalid]",
	} {
		doc := append(validDocument(t), []byte("destination:\n  "+destination+"\n")...)
		if _, err := config.Decode(doc); !errors.Is(err, config.ErrValue) {
			t.Fatalf("%q error = %v", destination, err)
		}
	}
}
