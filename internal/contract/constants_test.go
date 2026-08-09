package contract

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestFixedV1Limits(t *testing.T) {
	got := V1()
	checks := []struct {
		name string
		got  int64
		want int64
	}{
		{"tls handshake", int64(got.TLSHandshake), int64(10 * time.Second)},
		{"header read", int64(got.HeaderRead), int64(10 * time.Second)},
		{"dns", int64(got.DNS), int64(5 * time.Second)},
		{"dial", int64(got.Dial), int64(10 * time.Second)},
		{"setup", int64(got.Setup), int64(15 * time.Second)},
		{"response write", int64(got.ResponseWrite), int64(10 * time.Second)},
		{"idle", int64(got.Idle), int64(30 * time.Minute)},
		{"credential poll", int64(got.CredentialPoll), int64(250 * time.Millisecond)},
		{"credential validation", int64(got.CredentialValidation), int64(250 * time.Millisecond)},
		{"fatal diagnostic write", int64(got.FatalDiagnosticWrite), int64(250 * time.Millisecond)},
		{"fatal startup reporting", int64(got.FatalStartupReporting), int64(500 * time.Millisecond)},
		{"absolute tunnel lifetime disabled", int64(got.AbsoluteTunnelLifetimeDisabled), 0},
		{"header bytes", int64(got.HeaderBytes), 16 << 10},
		{"config bytes", int64(got.ConfigBytes), 1 << 20},
		{"store bytes", int64(got.StoreBytes), 1 << 20},
		{"pac bytes", int64(got.PACBytes), 64 << 10},
		{"credential list bytes", int64(got.CredentialListBytes), 32 << 10},
		{"credential records", int64(got.RecordLimit), 128},
		{"custom rules", int64(got.CustomRuleLimit), 128},
		{"authenticated capacity", int64(got.GlobalCapacity), 256},
		{"prefix entries", int64(got.PrefixEntries), 4096},
		{"relay buffer bytes", int64(got.RelayBufferBytes), 32 << 10},
		{"relay buffers per tunnel", int64(got.RelayBuffersPerTunnel), 2},
		{"retained relay buffers", int64(got.RelayRetainedBuffers), 512},
		{"log queue slots", int64(got.LogQueueSlots), 256},
		{"log record bytes", int64(got.LogRecordBytes), 2048},
		{"journal bytes", int64(got.JournalBytes), 256},
		{"journal slot bytes", int64(got.JournalSlotBytes), 128},
		{"journal slots", int64(got.JournalSlots), 2},
		{"pre-auth active", int64(got.PreAuthActive), 128},
		{"pre-auth rate per second", int64(got.PreAuthRatePerSecond), 20},
		{"pre-auth burst", int64(got.PreAuthBurst), 40},
		{"mapped prefix active", int64(got.MappedPrefixActive), 16},
		{"mapped prefix rate per second", int64(got.MappedPrefixRatePerSecond), 5},
		{"mapped prefix burst", int64(got.MappedPrefixBurst), 10},
		{"overflow active", int64(got.OverflowActive), 16},
		{"overflow rate per second", int64(got.OverflowRatePerSecond), 5},
		{"overflow burst", int64(got.OverflowBurst), 10},
		{"limiter entry ttl", int64(got.LimiterEntryTTL), int64(15 * time.Minute)},
		{"invalid auth rate per minute", int64(got.InvalidAuthRatePerMinute), 5},
		{"invalid auth burst", int64(got.InvalidAuthBurst), 10},
		{"invalid auth entries", int64(got.InvalidAuthEntries), 4096},
		{"invalid auth entry ttl", int64(got.InvalidAuthEntryTTL), int64(15 * time.Minute)},
		{"pac prefix rate per minute", int64(got.PACPrefixRatePerMinute), 30},
		{"pac prefix burst", int64(got.PACPrefixBurst), 10},
		{"pac global rate per minute", int64(got.PACGlobalRatePerMinute), 120},
		{"pac global burst", int64(got.PACGlobalBurst), 30},
		{"pac entries", int64(got.PACEntries), 4096},
		{"pac entry ttl", int64(got.PACEntryTTL), int64(15 * time.Minute)},
		{"pac work slots", int64(got.PACWorkSlots), 32},
		{"admin active", int64(got.AdminActive), 16},
		{"admin rate per second", int64(got.AdminRatePerSecond), 20},
		{"admin burst", int64(got.AdminBurst), 40},
		{"admin metrics work slots", int64(got.AdminMetricsWorkSlots), 2},
		{"credential id bytes", int64(got.CredentialIDBytes), 16},
		{"credential secret bytes", int64(got.CredentialSecretBytes), 32},
		{"credential owned slots", int64(got.CredentialOwnedSlots), 64},
		{"credential revoke deadline", int64(got.CredentialRevokeDeadline), int64(time.Second)},
		{"checkpoint slots", int64(got.CheckpointSlots), 2},
		{"per-device capacity minimum", int64(got.PerDeviceCapacityMin), 1},
		{"per-device capacity default", int64(got.PerDeviceCapacityDefault), 64},
		{"per-device capacity maximum", int64(got.PerDeviceCapacityMax), 64},
		{"absolute tunnel lifetime minimum", int64(got.AbsoluteTunnelLifetimeMin), int64(time.Hour)},
		{"absolute tunnel lifetime maximum", int64(got.AbsoluteTunnelLifetimeMax), int64(168 * time.Hour)},
		{"graceful shutdown drain minimum", int64(got.GracefulShutdownDrainMin), int64(5 * time.Second)},
		{"graceful shutdown drain default", int64(got.GracefulShutdownDrainDefault), int64(20 * time.Second)},
		{"graceful shutdown drain maximum", int64(got.GracefulShutdownDrainMax), int64(20 * time.Second)},
		{"connect port", int64(got.ConnectPort), 443},
		{"validated address attempts", int64(got.ValidatedAddressAttempts), 4},
		{"requests per connection", int64(got.RequestsPerConnection), 1},
		{"http major version", int64(got.HTTPMajor), 1},
		{"http minor version", int64(got.HTTPMinor), 1},
		{"minimum tls version", int64(got.MinTLSVersion), 0x0303},
	}

	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if check.got != check.want {
				t.Fatalf("got %d, want %d", check.got, check.want)
			}
		})
	}
}

func TestOnlyThreeNumericConfigurableBounds(t *testing.T) {
	got := ConfigurableNames()
	want := []string{"absolute_tunnel_lifetime", "graceful_shutdown_drain", "per_device_capacity"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestGitignorePreservesPublicScaffold(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}

	ignored := string(contents)
	for _, pattern := range []string{
		".superpowers/",
		"config/",
		"state/",
		"certificates/",
		"*.pem",
		"*.key",
		"*.crt",
		"logs/",
		"*.log",
		"coverage/",
		"*.coverprofile",
		".idea/",
		".vscode/",
		"*.swp",
		"compatibility-results/",
		"compatibility-results-*/",
		"*.compatibility-result.json",
	} {
		if !strings.Contains(ignored, pattern) {
			t.Errorf(".gitignore does not contain %q", pattern)
		}
	}

	for _, trackable := range []string{"config.example.yaml", "manifests/"} {
		if strings.Contains(ignored, trackable) {
			t.Errorf(".gitignore hides public scaffold %q", trackable)
		}
	}
}
