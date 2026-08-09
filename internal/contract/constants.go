// Package contract owns the fixed v1 runtime limits.
package contract

import "time"

// Limits contains the fixed numeric v1 protocol, resource, and safety limits.
// Values returned by V1 are copies so callers cannot mutate shared state.
type Limits struct {
	TLSHandshake, HeaderRead, DNS, Dial, Setup, ResponseWrite time.Duration
	Idle, CredentialPoll, CredentialValidation                time.Duration
	FatalDiagnosticWrite, FatalStartupReporting               time.Duration
	AbsoluteTunnelLifetimeDisabled, AbsoluteTunnelLifetimeMin time.Duration
	AbsoluteTunnelLifetimeMax                                 time.Duration
	GracefulShutdownDrainMin, GracefulShutdownDrainDefault    time.Duration
	GracefulShutdownDrainMax                                  time.Duration
	LimiterEntryTTL, InvalidAuthEntryTTL, PACEntryTTL         time.Duration
	CredentialRevokeDeadline                                  time.Duration

	HeaderBytes, ConfigBytes, StoreBytes, PACBytes, CredentialListBytes  int
	RecordLimit, CustomRuleLimit, GlobalCapacity, PrefixEntries          int
	RelayBufferBytes, RelayBuffersPerTunnel, RelayRetainedBuffers        int
	LogQueueSlots, LogRecordBytes                                        int
	JournalBytes, JournalSlotBytes, JournalSlots, CheckpointSlots        int
	PreAuthActive, PreAuthRatePerSecond, PreAuthBurst                    int
	MappedPrefixActive, MappedPrefixRatePerSecond, MappedPrefixBurst     int
	OverflowActive, OverflowRatePerSecond, OverflowBurst                 int
	InvalidAuthRatePerMinute, InvalidAuthBurst, InvalidAuthEntries       int
	PACPrefixRatePerMinute, PACPrefixBurst                               int
	PACGlobalRatePerMinute, PACGlobalBurst, PACEntries, PACWorkSlots     int
	AdminActive, AdminRatePerSecond, AdminBurst, AdminMetricsWorkSlots   int
	CredentialIDBytes, CredentialSecretBytes, CredentialOwnedSlots       int
	PerDeviceCapacityMin, PerDeviceCapacityDefault, PerDeviceCapacityMax int
	ConnectPort, ValidatedAddressAttempts, RequestsPerConnection         int
	HTTPMajor, HTTPMinor                                                 int
	MinTLSVersion                                                        uint16
}

// V1 returns the immutable fixed v1 limit set.
func V1() Limits {
	return Limits{
		TLSHandshake: 10 * time.Second, HeaderRead: 10 * time.Second,
		DNS: 5 * time.Second, Dial: 10 * time.Second, Setup: 15 * time.Second,
		ResponseWrite: 10 * time.Second, Idle: 30 * time.Minute,
		CredentialPoll: 250 * time.Millisecond, CredentialValidation: 250 * time.Millisecond,
		FatalDiagnosticWrite: 250 * time.Millisecond, FatalStartupReporting: 500 * time.Millisecond,
		AbsoluteTunnelLifetimeDisabled: 0, AbsoluteTunnelLifetimeMin: time.Hour,
		AbsoluteTunnelLifetimeMax: 168 * time.Hour, GracefulShutdownDrainMin: 5 * time.Second,
		GracefulShutdownDrainDefault: 20 * time.Second, GracefulShutdownDrainMax: 20 * time.Second,
		LimiterEntryTTL: 15 * time.Minute, InvalidAuthEntryTTL: 15 * time.Minute,
		PACEntryTTL: 15 * time.Minute, CredentialRevokeDeadline: time.Second,
		HeaderBytes: 16 << 10, ConfigBytes: 1 << 20, StoreBytes: 1 << 20,
		PACBytes: 64 << 10, CredentialListBytes: 32 << 10, RecordLimit: 128,
		CustomRuleLimit: 128, GlobalCapacity: 256, PrefixEntries: 4096,
		RelayBufferBytes: 32 << 10, RelayBuffersPerTunnel: 2, RelayRetainedBuffers: 512,
		LogQueueSlots: 256, LogRecordBytes: 2048, JournalBytes: 256,
		JournalSlotBytes: 128, JournalSlots: 2, CheckpointSlots: 2,
		PreAuthActive: 128, PreAuthRatePerSecond: 20, PreAuthBurst: 40,
		MappedPrefixActive: 16, MappedPrefixRatePerSecond: 5, MappedPrefixBurst: 10,
		OverflowActive: 16, OverflowRatePerSecond: 5, OverflowBurst: 10,
		InvalidAuthRatePerMinute: 5, InvalidAuthBurst: 10, InvalidAuthEntries: 4096,
		PACPrefixRatePerMinute: 30, PACPrefixBurst: 10, PACGlobalRatePerMinute: 120,
		PACGlobalBurst: 30, PACEntries: 4096, PACWorkSlots: 32,
		AdminActive: 16, AdminRatePerSecond: 20, AdminBurst: 40, AdminMetricsWorkSlots: 2,
		CredentialIDBytes: 16, CredentialSecretBytes: 32, CredentialOwnedSlots: 64,
		PerDeviceCapacityMin: 1, PerDeviceCapacityDefault: 64, PerDeviceCapacityMax: 64,
		ConnectPort: 443, ValidatedAddressAttempts: 4, RequestsPerConnection: 1,
		HTTPMajor: 1, HTTPMinor: 1, MinTLSVersion: 0x0303,
	}
}

// ConfigurableNames lists the only v1 configuration keys with numeric ranges.
func ConfigurableNames() []string {
	return []string{"absolute_tunnel_lifetime", "graceful_shutdown_drain", "per_device_capacity"}
}
