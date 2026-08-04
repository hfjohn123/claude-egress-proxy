package app

import (
	"errors"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestPACPathFailuresMapToFixedDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want contract.DiagnosticCode
	}{
		{securefs.ErrUnsafePath, contract.D004}, {securefs.ErrIdentityChanged, contract.D004},
		{securefs.ErrPermissions, contract.D004}, {securefs.ErrUnsupportedInspection, contract.D010},
		{errors.New("io"), contract.D010},
	} {
		if got := pacPathCode(tc.err); got != tc.want {
			t.Fatalf("%v = %v want %v", tc.err, got, tc.want)
		}
	}
}
