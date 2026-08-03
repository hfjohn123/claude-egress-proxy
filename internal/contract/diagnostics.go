package contract

// DiagnosticCode identifies one closed fatal startup diagnostic.
type DiagnosticCode uint8

const (
	DiagnosticNone DiagnosticCode = iota
	D001
	D002
	D003
	D004
	D005
	D006
	D007
	D008
	D009
	D010
	D011
)

// Fatal returns the fixed diagnostic line for code.
func Fatal(code DiagnosticCode) []byte {
	switch code {
	case DiagnosticNone:
		return nil
	case D001:
		return []byte("ERROR D001 CONFIG_READ: cannot safely read the selected configuration; check its existence, type, and access.\n")
	case D002:
		return []byte("ERROR D002 CONFIG_SYNTAX: configuration syntax or schema is invalid; correct the strict YAML document.\n")
	case D003:
		return []byte("ERROR D003 CONFIG_VALUE: a configuration value or combination is invalid; review the documented modes and bounds.\n")
	case D004:
		return []byte("ERROR D004 PATH_SECURITY: required state failed identity or access checks; review ownership, permissions, and links.\n")
	case D005:
		return []byte("ERROR D005 STATE_INVALID: credential or instance state is invalid; restore a current valid state generation.\n")
	case D006:
		return []byte("ERROR D006 ADMIN_TOKEN: metrics token state is invalid; rotate the token or disable metrics.\n")
	case D007:
		return []byte("ERROR D007 CERTIFICATE: serving certificate state is invalid; repair the configured certificate mode or files.\n")
	case D008:
		return []byte("ERROR D008 LOG_SINK: the selected application-log sink is unusable; repair its access or platform service.\n")
	case D009:
		return []byte("ERROR D009 LISTENER_BIND: a required listener could not bind; stop the conflict or correct the bind.\n")
	case D010:
		return []byte("ERROR D010 PLATFORM: a required platform security operation is unavailable; use supported privileges and host controls.\n")
	case D011:
		return []byte("ERROR D011 NETWORK_STATE: required local network state is unavailable; check configured addresses and interfaces.\n")
	default:
		panic("invalid diagnostic code")
	}
}

// ServiceCode returns the matching platform service exit code.
func ServiceCode(code DiagnosticCode) uint32 {
	if code == DiagnosticNone {
		return 0
	}
	if code < D001 || code > D011 {
		panic("invalid diagnostic code")
	}
	return 1000 + uint32(code)
}

// SelectFatal chooses the highest-precedence code from codes.
func SelectFatal(codes []DiagnosticCode) DiagnosticCode {
	selected := DiagnosticNone
	for _, code := range codes {
		rank := diagnosticRank(code)
		if rank < 0 {
			panic("invalid diagnostic code")
		}
		if code != DiagnosticNone && (selected == DiagnosticNone || rank < diagnosticRank(selected)) {
			selected = code
		}
	}
	return selected
}

func diagnosticRank(code DiagnosticCode) int {
	switch code {
	case DiagnosticNone:
		return 99
	case D001:
		return 0
	case D002:
		return 1
	case D003:
		return 2
	case D010:
		return 3
	case D004:
		return 4
	case D005:
		return 5
	case D006:
		return 6
	case D007:
		return 7
	case D011:
		return 8
	case D008:
		return 9
	case D009:
		return 10
	default:
		return -1
	}
}
