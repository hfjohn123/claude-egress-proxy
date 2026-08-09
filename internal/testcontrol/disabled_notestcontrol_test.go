//go:build !cep_testcontrol

package testcontrol

import "testing"

func TestDisabledInOrdinaryBuild(t *testing.T) {
	if Enabled() {
		t.Fatal("ordinary build enabled test control")
	}
}
