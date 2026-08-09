package contract

// TLSResult classifies the TLS handshake outcome.
type TLSResult uint8

const (
	tlsSuccess TLSResult = iota
	tlsRateLimited
	tlsTimeout
	tlsError
)

func AllTLSResults() []string { return []string{"success", "rate_limited", "timeout", "tls_error"} }
func ParseTLSResult(value string) (TLSResult, bool) {
	switch value {
	case "success":
		return tlsSuccess, true
	case "rate_limited":
		return tlsRateLimited, true
	case "timeout":
		return tlsTimeout, true
	case "tls_error":
		return tlsError, true
	default:
		return 0, false
	}
}
func (r TLSResult) String() string {
	switch r {
	case tlsSuccess:
		return "success"
	case tlsRateLimited:
		return "rate_limited"
	case tlsTimeout:
		return "timeout"
	case tlsError:
		return "tls_error"
	default:
		panic("invalid TLS result")
	}
}

// AuthenticationResult classifies authentication processing.
type AuthenticationResult uint8

const (
	authenticationChallenge AuthenticationResult = iota
	authenticationValid
	authenticationInvalid
	authenticationThrottled
	authenticationMapCapacity
	authenticationStoreUnavailable
)

func AllAuthenticationResults() []string {
	return []string{"challenge", "valid", "invalid", "throttled", "map_capacity", "store_unavailable"}
}
func ParseAuthenticationResult(value string) (AuthenticationResult, bool) {
	switch value {
	case "challenge":
		return authenticationChallenge, true
	case "valid":
		return authenticationValid, true
	case "invalid":
		return authenticationInvalid, true
	case "throttled":
		return authenticationThrottled, true
	case "map_capacity":
		return authenticationMapCapacity, true
	case "store_unavailable":
		return authenticationStoreUnavailable, true
	default:
		return 0, false
	}
}
func (r AuthenticationResult) String() string {
	switch r {
	case authenticationChallenge:
		return "challenge"
	case authenticationValid:
		return "valid"
	case authenticationInvalid:
		return "invalid"
	case authenticationThrottled:
		return "throttled"
	case authenticationMapCapacity:
		return "map_capacity"
	case authenticationStoreUnavailable:
		return "store_unavailable"
	default:
		panic("invalid authentication result")
	}
}

// ConnectResult classifies a CONNECT setup terminal.
type ConnectResult uint8

const (
	connectEstablished ConnectResult = iota
	connectMalformedRequest
	connectPortDenied
	connectHostnameDenied
	connectAddressDenied
	connectDNSFailed
	connectDialFailed
	connectSetupTimeout
	connectCredentialStoreUnavailable
	connectSourceBindUnavailable
	connectSelfAddressStateUnavailable
	connectGlobalCapacity
	connectDeviceCapacity
	connectDraining
	connectCredentialChanged
	connectClientDisconnected
	connectInternalError
)

func AllConnectResults() []string {
	return []string{"established", "malformed_request", "port_denied", "hostname_denied", "address_denied", "dns_failed", "dial_failed", "setup_timeout", "credential_store_unavailable", "source_bind_unavailable", "self_address_state_unavailable", "global_capacity", "device_capacity", "draining", "credential_changed", "client_disconnected", "internal_error"}
}
func ParseConnectResult(value string) (ConnectResult, bool) {
	switch value {
	case "established":
		return connectEstablished, true
	case "malformed_request":
		return connectMalformedRequest, true
	case "port_denied":
		return connectPortDenied, true
	case "hostname_denied":
		return connectHostnameDenied, true
	case "address_denied":
		return connectAddressDenied, true
	case "dns_failed":
		return connectDNSFailed, true
	case "dial_failed":
		return connectDialFailed, true
	case "setup_timeout":
		return connectSetupTimeout, true
	case "credential_store_unavailable":
		return connectCredentialStoreUnavailable, true
	case "source_bind_unavailable":
		return connectSourceBindUnavailable, true
	case "self_address_state_unavailable":
		return connectSelfAddressStateUnavailable, true
	case "global_capacity":
		return connectGlobalCapacity, true
	case "device_capacity":
		return connectDeviceCapacity, true
	case "draining":
		return connectDraining, true
	case "credential_changed":
		return connectCredentialChanged, true
	case "client_disconnected":
		return connectClientDisconnected, true
	case "internal_error":
		return connectInternalError, true
	default:
		return 0, false
	}
}
func (r ConnectResult) String() string {
	switch r {
	case connectEstablished:
		return "established"
	case connectMalformedRequest:
		return "malformed_request"
	case connectPortDenied:
		return "port_denied"
	case connectHostnameDenied:
		return "hostname_denied"
	case connectAddressDenied:
		return "address_denied"
	case connectDNSFailed:
		return "dns_failed"
	case connectDialFailed:
		return "dial_failed"
	case connectSetupTimeout:
		return "setup_timeout"
	case connectCredentialStoreUnavailable:
		return "credential_store_unavailable"
	case connectSourceBindUnavailable:
		return "source_bind_unavailable"
	case connectSelfAddressStateUnavailable:
		return "self_address_state_unavailable"
	case connectGlobalCapacity:
		return "global_capacity"
	case connectDeviceCapacity:
		return "device_capacity"
	case connectDraining:
		return "draining"
	case connectCredentialChanged:
		return "credential_changed"
	case connectClientDisconnected:
		return "client_disconnected"
	case connectInternalError:
		return "internal_error"
	default:
		panic("invalid connect result")
	}
}

// PACResult classifies PAC delivery.
type PACResult uint8

const (
	pacServed PACResult = iota
	pacDisabled
	pacNotFound
	pacPrefixRateLimited
	pacGlobalRateLimited
	pacMapCapacity
	pacCapacity
)

func AllPACResults() []string {
	return []string{"served", "disabled", "not_found", "prefix_rate_limited", "global_rate_limited", "map_capacity", "capacity"}
}
func ParsePACResult(value string) (PACResult, bool) {
	switch value {
	case "served":
		return pacServed, true
	case "disabled":
		return pacDisabled, true
	case "not_found":
		return pacNotFound, true
	case "prefix_rate_limited":
		return pacPrefixRateLimited, true
	case "global_rate_limited":
		return pacGlobalRateLimited, true
	case "map_capacity":
		return pacMapCapacity, true
	case "capacity":
		return pacCapacity, true
	default:
		return 0, false
	}
}
func (r PACResult) String() string {
	switch r {
	case pacServed:
		return "served"
	case pacDisabled:
		return "disabled"
	case pacNotFound:
		return "not_found"
	case pacPrefixRateLimited:
		return "prefix_rate_limited"
	case pacGlobalRateLimited:
		return "global_rate_limited"
	case pacMapCapacity:
		return "map_capacity"
	case pacCapacity:
		return "capacity"
	default:
		panic("invalid PAC result")
	}
}

// Limiter identifies one bounded rate limiter.
type Limiter uint8

const (
	limiterTLSHandshake Limiter = iota
	limiterAuthentication
	limiterPAC
)

func AllLimiters() []string { return []string{"tls_handshake", "authentication", "pac"} }
func ParseLimiter(value string) (Limiter, bool) {
	switch value {
	case "tls_handshake":
		return limiterTLSHandshake, true
	case "authentication":
		return limiterAuthentication, true
	case "pac":
		return limiterPAC, true
	default:
		return 0, false
	}
}
func (l Limiter) String() string {
	switch l {
	case limiterTLSHandshake:
		return "tls_handshake"
	case limiterAuthentication:
		return "authentication"
	case limiterPAC:
		return "pac"
	default:
		panic("invalid limiter")
	}
}

// LimiterEvent identifies a limiter observation.
type LimiterEvent uint8

const (
	limiterAllowed LimiterEvent = iota
	limiterThrottled
	limiterEntryExpired
	limiterMapFull
	limiterSaturationOverflow
)

func AllLimiterEvents() []string {
	return []string{"allowed", "throttled", "entry_expired", "map_full", "saturation_overflow"}
}
func ParseLimiterEvent(value string) (LimiterEvent, bool) {
	switch value {
	case "allowed":
		return limiterAllowed, true
	case "throttled":
		return limiterThrottled, true
	case "entry_expired":
		return limiterEntryExpired, true
	case "map_full":
		return limiterMapFull, true
	case "saturation_overflow":
		return limiterSaturationOverflow, true
	default:
		return 0, false
	}
}
func (e LimiterEvent) String() string {
	switch e {
	case limiterAllowed:
		return "allowed"
	case limiterThrottled:
		return "throttled"
	case limiterEntryExpired:
		return "entry_expired"
	case limiterMapFull:
		return "map_full"
	case limiterSaturationOverflow:
		return "saturation_overflow"
	default:
		panic("invalid limiter event")
	}
}

// ValidLimiterPair reports whether event may be recorded by limiter.
func ValidLimiterPair(limiter Limiter, event LimiterEvent) bool {
	switch limiter {
	case limiterTLSHandshake:
		return event == limiterAllowed || event == limiterThrottled || event == limiterEntryExpired || event == limiterSaturationOverflow
	case limiterAuthentication, limiterPAC:
		return event == limiterAllowed || event == limiterThrottled || event == limiterEntryExpired || event == limiterMapFull
	default:
		return false
	}
}

// ReloadKind identifies reloadable runtime state.
type ReloadKind uint8

const (
	reloadCredential ReloadKind = iota
	reloadCertificate
	reloadPublicSelf
	reloadSourceBind
	reloadACME
)

func AllReloadKinds() []string {
	return []string{"credential", "certificate", "public_self", "source_bind", "acme"}
}
func ParseReloadKind(value string) (ReloadKind, bool) {
	switch value {
	case "credential":
		return reloadCredential, true
	case "certificate":
		return reloadCertificate, true
	case "public_self":
		return reloadPublicSelf, true
	case "source_bind":
		return reloadSourceBind, true
	case "acme":
		return reloadACME, true
	default:
		return 0, false
	}
}
func (r ReloadKind) String() string {
	switch r {
	case reloadCredential:
		return "credential"
	case reloadCertificate:
		return "certificate"
	case reloadPublicSelf:
		return "public_self"
	case reloadSourceBind:
		return "source_bind"
	case reloadACME:
		return "acme"
	default:
		panic("invalid reload kind")
	}
}

// ReloadResult classifies a reload attempt.
type ReloadResult uint8

const (
	reloadSuccess ReloadResult = iota
	reloadFailure
	reloadRecovered
)

func AllReloadResults() []string { return []string{"success", "failure", "recovered"} }
func ParseReloadResult(value string) (ReloadResult, bool) {
	switch value {
	case "success":
		return reloadSuccess, true
	case "failure":
		return reloadFailure, true
	case "recovered":
		return reloadRecovered, true
	default:
		return 0, false
	}
}
func (r ReloadResult) String() string {
	switch r {
	case reloadSuccess:
		return "success"
	case reloadFailure:
		return "failure"
	case reloadRecovered:
		return "recovered"
	default:
		panic("invalid reload result")
	}
}

// DeliveryResult classifies a log delivery attempt.
type DeliveryResult uint8

const (
	deliveryWritten DeliveryResult = iota
	deliveryDroppedQueueFull
	deliveryDroppedSinkFailed
	deliveryDroppedShutdownDeadline
)

func AllDeliveryResults() []string {
	return []string{"written", "dropped_queue_full", "dropped_sink_failed", "dropped_shutdown_deadline"}
}
func ParseDeliveryResult(value string) (DeliveryResult, bool) {
	switch value {
	case "written":
		return deliveryWritten, true
	case "dropped_queue_full":
		return deliveryDroppedQueueFull, true
	case "dropped_sink_failed":
		return deliveryDroppedSinkFailed, true
	case "dropped_shutdown_deadline":
		return deliveryDroppedShutdownDeadline, true
	default:
		return 0, false
	}
}
func (r DeliveryResult) String() string {
	switch r {
	case deliveryWritten:
		return "written"
	case deliveryDroppedQueueFull:
		return "dropped_queue_full"
	case deliveryDroppedSinkFailed:
		return "dropped_sink_failed"
	case deliveryDroppedShutdownDeadline:
		return "dropped_shutdown_deadline"
	default:
		panic("invalid delivery result")
	}
}

// SetupOutcome is the success/failure setup telemetry outcome.
type SetupOutcome uint8

const (
	setupSuccess SetupOutcome = iota
	setupFailure
)

func AllSetupOutcomes() []string { return []string{"success", "failure"} }
func ParseSetupOutcome(value string) (SetupOutcome, bool) {
	switch value {
	case "success":
		return setupSuccess, true
	case "failure":
		return setupFailure, true
	default:
		return 0, false
	}
}
func (o SetupOutcome) String() string {
	switch o {
	case setupSuccess:
		return "success"
	case setupFailure:
		return "failure"
	default:
		panic("invalid setup outcome")
	}
}

// CloseResult classifies how a tunnel closed.
type CloseResult uint8

const (
	closeClean CloseResult = iota
	closeIOError
	closeIdleTimeout
	closeAbsoluteLifetime
	closeCredentialRevoked
	closeShutdownDeadline
)

func AllCloseResults() []string {
	return []string{"clean", "io_error", "idle_timeout", "absolute_lifetime", "credential_revoked", "shutdown_deadline"}
}
func ParseCloseResult(value string) (CloseResult, bool) {
	switch value {
	case "clean":
		return closeClean, true
	case "io_error":
		return closeIOError, true
	case "idle_timeout":
		return closeIdleTimeout, true
	case "absolute_lifetime":
		return closeAbsoluteLifetime, true
	case "credential_revoked":
		return closeCredentialRevoked, true
	case "shutdown_deadline":
		return closeShutdownDeadline, true
	default:
		return 0, false
	}
}
func (r CloseResult) String() string {
	switch r {
	case closeClean:
		return "clean"
	case closeIOError:
		return "io_error"
	case closeIdleTimeout:
		return "idle_timeout"
	case closeAbsoluteLifetime:
		return "absolute_lifetime"
	case closeCredentialRevoked:
		return "credential_revoked"
	case closeShutdownDeadline:
		return "shutdown_deadline"
	default:
		panic("invalid close result")
	}
}

// TunnelOutcome is the stable tunnel-duration telemetry classification.
type TunnelOutcome uint8

const (
	tunnelClean TunnelOutcome = iota
	tunnelError
	tunnelRevoked
	tunnelIdleTimeout
	tunnelLifetimeTimeout
	tunnelShutdown
)

func AllTunnelOutcomes() []string {
	return []string{"clean", "error", "revoked", "idle_timeout", "lifetime_timeout", "shutdown"}
}
func ParseTunnelOutcome(value string) (TunnelOutcome, bool) {
	switch value {
	case "clean":
		return tunnelClean, true
	case "error":
		return tunnelError, true
	case "revoked":
		return tunnelRevoked, true
	case "idle_timeout":
		return tunnelIdleTimeout, true
	case "lifetime_timeout":
		return tunnelLifetimeTimeout, true
	case "shutdown":
		return tunnelShutdown, true
	default:
		return 0, false
	}
}
func (o TunnelOutcome) String() string {
	switch o {
	case tunnelClean:
		return "clean"
	case tunnelError:
		return "error"
	case tunnelRevoked:
		return "revoked"
	case tunnelIdleTimeout:
		return "idle_timeout"
	case tunnelLifetimeTimeout:
		return "lifetime_timeout"
	case tunnelShutdown:
		return "shutdown"
	default:
		panic("invalid tunnel outcome")
	}
}

// TunnelOutcomeForCloseResult maps every close terminal to a duration outcome.
func TunnelOutcomeForCloseResult(result CloseResult) TunnelOutcome {
	switch result {
	case closeClean:
		return tunnelClean
	case closeIOError:
		return tunnelError
	case closeIdleTimeout:
		return tunnelIdleTimeout
	case closeAbsoluteLifetime:
		return tunnelLifetimeTimeout
	case closeCredentialRevoked:
		return tunnelRevoked
	case closeShutdownDeadline:
		return tunnelShutdown
	default:
		panic("invalid close result")
	}
}

// ReadinessPredicate is one independently satisfied readiness condition.
type ReadinessPredicate uint8

const (
	readinessCertificate ReadinessPredicate = iota
	readinessCredential
	readinessPublicSelf
	readinessSourceBind
	readinessDrain
)

func AllReadinessPredicates() []string {
	return []string{"certificate", "credential", "public_self", "source_bind", "drain"}
}
func ParseReadinessPredicate(value string) (ReadinessPredicate, bool) {
	switch value {
	case "certificate":
		return readinessCertificate, true
	case "credential":
		return readinessCredential, true
	case "public_self":
		return readinessPublicSelf, true
	case "source_bind":
		return readinessSourceBind, true
	case "drain":
		return readinessDrain, true
	default:
		return 0, false
	}
}
func (p ReadinessPredicate) String() string {
	switch p {
	case readinessCertificate:
		return "certificate"
	case readinessCredential:
		return "credential"
	case readinessPublicSelf:
		return "public_self"
	case readinessSourceBind:
		return "source_bind"
	case readinessDrain:
		return "drain"
	default:
		panic("invalid readiness predicate")
	}
}

// PublicSelfOutcome classifies only the semantic outcome of public-self resolution.
type PublicSelfOutcome uint8

const (
	publicSelfPositive PublicSelfOutcome = iota
	publicSelfSuccessEmpty
	publicSelfFailure
)

func AllPublicSelfOutcomes() []string { return []string{"positive", "success_empty", "failure"} }
func ParsePublicSelfOutcome(value string) (PublicSelfOutcome, bool) {
	switch value {
	case "positive":
		return publicSelfPositive, true
	case "success_empty":
		return publicSelfSuccessEmpty, true
	case "failure":
		return publicSelfFailure, true
	default:
		return 0, false
	}
}
func (o PublicSelfOutcome) String() string {
	switch o {
	case publicSelfPositive:
		return "positive"
	case publicSelfSuccessEmpty:
		return "success_empty"
	case publicSelfFailure:
		return "failure"
	default:
		panic("invalid public-self outcome")
	}
}

// ByteTotals holds opaque relay bytes by direction.
type ByteTotals struct {
	ClientToOrigin uint64
	OriginToClient uint64
}

// ServiceStateReason classifies a closed service lifecycle record.
type ServiceStateReason uint8

const (
	serviceStarted ServiceStateReason = iota
	serviceReady
	serviceDraining
	serviceStopped
	serviceCredentialStoreRecovered
	serviceNotReady
	serviceInsecureLoopback
	serviceDangerousCustomSuffixes
	serviceCredentialStoreUnavailable
	serviceStartupFailed
)

func AllServiceStateReasons() []string {
	return []string{"started", "ready", "draining", "stopped", "credential_store_recovered", "not_ready", "insecure_loopback", "dangerous_custom_suffixes", "credential_store_unavailable", "startup_failed"}
}
func ParseServiceStateReason(value string) (ServiceStateReason, bool) {
	for i, candidate := range AllServiceStateReasons() {
		if value == candidate {
			return ServiceStateReason(i), true
		}
	}
	return 0, false
}
func (r ServiceStateReason) String() string {
	if r < serviceStarted || r > serviceStartupFailed {
		panic("invalid service state reason")
	}
	return AllServiceStateReasons()[r]
}
