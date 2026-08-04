//go:build windows

package securefs

import (
	"context"
	"errors"
	"testing"
)

// This is deliberately a contract test: validation must reject an unsafe
// namespace before it opens or creates any filesystem member.
func TestAcquireRotationNamespaceRejectsUnsafeLeaves(t *testing.T) {
	root := &mutableRoot{}
	policy := FilePolicy{Presence: Optional, Kind: RegularFile, Access: windowsRestrictedPermissionsForRotationTest(t), MaxBytes: 32}
	_, err := root.AcquireRotationNamespace(context.Background(), "state", [3]string{"state", "state.1", "state"}, policy)
	if !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("AcquireRotationNamespace unsafe leaves error = %v, want ErrUnsafePath", err)
	}
}

// WindowsRestrictedPermissionsForTest supplies a syntactically valid policy;
// the unsafe-leaf assertion above must happen before root use.
func windowsRestrictedPermissionsForRotationTest(t *testing.T) PermissionPolicy {
	t.Helper()
	p, err := WindowsRestrictedPermissions([]string{"S-1-5-18"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
