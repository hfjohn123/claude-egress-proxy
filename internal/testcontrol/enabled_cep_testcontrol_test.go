//go:build cep_testcontrol

package testcontrol

import "testing"

func TestEnabledInTaggedBuild(t *testing.T) {
	if !Enabled() {
		t.Fatal("tagged build disabled test control")
	}
}
