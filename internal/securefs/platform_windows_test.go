//go:build windows

package securefs

import (
	"errors"
	"testing"
)

// TestWindowsACLPolicyRejectsUnsafeInputs catches an ACL policy constructor
// that accepts empty, duplicate, malformed, or zero-access security rules.
func TestWindowsACLPolicyRejectsUnsafeInputs(t *testing.T) {
	for _, test := range [][]string{{}, {"not-a-sid"}, {"S-1-5-32-544", "S-1-5-32-544"}} {
		if _, err := WindowsRestrictedPermissions(test, 1); !errors.Is(err, ErrPermissions) {
			t.Fatalf("WindowsRestrictedPermissions(%q) error = %v, want ErrPermissions", test, err)
		}
	}
	if _, err := WindowsRestrictedPermissions([]string{"S-1-5-32-544"}, 0); !errors.Is(err, ErrPermissions) {
		t.Fatalf("zero access error = %v, want ErrPermissions", err)
	}
}
