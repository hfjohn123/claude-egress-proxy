package contract

import (
	"bytes"
	"testing"
)

func TestFatalDiagnosticBytesAndServiceCodesCatchMisclassifiedStartupFailures(t *testing.T) {
	tests := []struct {
		code    DiagnosticCode
		fatal   string
		service uint32
	}{
		{D001, "ERROR D001 CONFIG_READ: cannot safely read the selected configuration; check its existence, type, and access.\n", 1001},
		{D002, "ERROR D002 CONFIG_SYNTAX: configuration syntax or schema is invalid; correct the strict YAML document.\n", 1002},
		{D003, "ERROR D003 CONFIG_VALUE: a configuration value or combination is invalid; review the documented modes and bounds.\n", 1003},
		{D004, "ERROR D004 PATH_SECURITY: required state failed identity or access checks; review ownership, permissions, and links.\n", 1004},
		{D005, "ERROR D005 STATE_INVALID: credential or instance state is invalid; restore a current valid state generation.\n", 1005},
		{D006, "ERROR D006 ADMIN_TOKEN: metrics token state is invalid; rotate the token or disable metrics.\n", 1006},
		{D007, "ERROR D007 CERTIFICATE: serving certificate state is invalid; repair the configured certificate mode or files.\n", 1007},
		{D008, "ERROR D008 LOG_SINK: the selected application-log sink is unusable; repair its access or platform service.\n", 1008},
		{D009, "ERROR D009 LISTENER_BIND: a required listener could not bind; stop the conflict or correct the bind.\n", 1009},
		{D010, "ERROR D010 PLATFORM: a required platform security operation is unavailable; use supported privileges and host controls.\n", 1010},
		{D011, "ERROR D011 NETWORK_STATE: required local network state is unavailable; check configured addresses and interfaces.\n", 1011},
	}
	for _, test := range tests {
		t.Run(test.fatal[6:10], func(t *testing.T) {
			got := Fatal(test.code)
			if string(got) != test.fatal {
				t.Fatalf("Fatal(%v) = %q, want %q", test.code, got, test.fatal)
			}
			if gotCode := ServiceCode(test.code); gotCode != test.service {
				t.Fatalf("ServiceCode(%v) = %d, want %d", test.code, gotCode, test.service)
			}
			if len(got) > 192 || bytes.Count(got, []byte{'\n'}) != 1 || bytes.Contains(got, []byte{'\r'}) {
				t.Fatalf("fatal diagnostic violates fixed output bounds: %q", got)
			}
		})
	}
}

func TestFatalDiagnosticSentinelsAndOpenValuesPanicInsteadOfProducingOutput(t *testing.T) {
	if got := Fatal(DiagnosticNone); got != nil {
		t.Fatalf("Fatal(DiagnosticNone) = %q, want nil", got)
	}
	if got := ServiceCode(DiagnosticNone); got != 0 {
		t.Fatalf("ServiceCode(DiagnosticNone) = %d, want 0", got)
	}
	if got := SelectFatal(nil); got != DiagnosticNone {
		t.Fatalf("SelectFatal(nil) = %v, want DiagnosticNone", got)
	}
	if got := SelectFatal([]DiagnosticCode{DiagnosticNone, DiagnosticNone}); got != DiagnosticNone {
		t.Fatalf("SelectFatal(none) = %v, want DiagnosticNone", got)
	}
	for _, exercise := range []func(){
		func() { Fatal(DiagnosticCode(255)) },
		func() { ServiceCode(DiagnosticCode(255)) },
		func() { SelectFatal([]DiagnosticCode{DiagnosticCode(255)}) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatal("open diagnostic value did not panic")
				}
			}()
			exercise()
		}()
	}
}

func TestSelectFatalUsesFrozenNonNumericPrecedence(t *testing.T) {
	order := []DiagnosticCode{D001, D002, D003, D010, D004, D005, D006, D007, D011, D008, D009}
	for earlier, want := range order {
		for _, later := range order[earlier+1:] {
			if got := SelectFatal([]DiagnosticCode{later, want}); got != want {
				t.Fatalf("SelectFatal(%v, %v) = %v, want earlier diagnostic", later, want, got)
			}
		}
	}
}
