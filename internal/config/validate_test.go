package config_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestLoaderRetainsRootsAndBorrowCannotCloseThem(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "config.yaml")
	doc := fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\n", state)
	if err := os.WriteFile(path, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	p := securefs.IdentityOnlyPermissions()
	loaded, err := (config.Loader{Policies: config.SecurityPolicies{
		ConfigContainer: securefs.RootPolicy{Access: p}, ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:     securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
		StateContainer: securefs.RootPolicy{Access: p}, StateDirectory: securefs.RootPolicy{Access: p},
	}}).Load(path, config.ValidatePure)
	if err != nil {
		t.Fatal(err)
	}
	borrow := loaded.StateRoot()
	if _, ok := borrow.(securefs.Root); ok {
		t.Fatal("borrowed StateRoot implements Root")
	}
	if borrow.Identity() == (securefs.Identity{}) {
		t.Fatal("borrow has no retained identity")
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	if err := borrow.RecheckIdentity(); !errors.Is(err, securefs.ErrClosed) {
		t.Fatalf("borrow after close = %v", err)
	}
	if err := loaded.Close(); err != nil {
		t.Fatalf("idempotent close = %v", err)
	}
}

func TestLoaderRejectsUnavailableAndUnknownModesBeforeOpening(t *testing.T) {
	for _, mode := range []config.ValidationMode{config.ValidateOperational, config.ValidatePreServe} {
		if _, err := (config.Loader{}).Load(filepath.Join(t.TempDir(), "missing"), mode); !errors.Is(err, config.ErrValidationUnavailable) {
			t.Fatalf("mode %d error = %v", mode, err)
		}
	}
	if _, err := (config.Loader{}).Load(filepath.Join(t.TempDir(), "missing"), config.ValidationInvalid); !errors.Is(err, config.ErrValue) {
		t.Fatalf("invalid mode error = %v", err)
	}
}

func TestLoaderMapsClosedDiagnosticsWithoutLeakingPaths(t *testing.T) {
	base := t.TempDir()
	p := securefs.IdentityOnlyPermissions()
	loader := config.Loader{Policies: config.SecurityPolicies{ConfigDirectory: securefs.RootPolicy{Access: p}, ConfigFile: securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)}, StateDirectory: securefs.RootPolicy{Access: p}}}
	cases := []struct {
		name, path, doc string
		code            contract.DiagnosticCode
		sentinel        error
	}{
		{"missing", filepath.Join(base, "missing.yaml"), "", contract.D001, config.ErrRead},
		{"syntax", filepath.Join(base, "syntax.yaml"), "not: [yaml", contract.D002, config.ErrSyntax},
		{"value", filepath.Join(base, "value.yaml"), fmt.Sprintf("format_version: 2\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\n", filepath.Join(base, "state")), contract.D003, config.ErrValue},
		{"state", filepath.Join(base, "state.yaml"), fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\n", filepath.Join(base, "absent-state")), contract.D004, config.ErrPathSecurity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.doc != "" {
				if err := os.WriteFile(tc.path, []byte(tc.doc), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := loader.Load(tc.path, config.ValidatePure)
			var typed *config.Error
			if !errors.As(err, &typed) || typed.DiagnosticCode() != tc.code || !errors.Is(err, tc.sentinel) {
				t.Fatalf("error = %v code=%v", err, func() contract.DiagnosticCode {
					if typed == nil {
						return contract.DiagnosticNone
					}
					return typed.DiagnosticCode()
				}())
			}
			if strings.Contains(err.Error(), base) {
				t.Fatalf("diagnostic leaked path: %v", err)
			}
		})
	}
}

func TestLoaderMapsCheckoutIdentityExclusionToPathSecurity(t *testing.T) {
	base := t.TempDir()
	root, err := securefs.OpenRoot(base, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	checkout := root.Identity()
	_ = root.Close()
	path := filepath.Join(base, "config.yaml")
	if err := os.WriteFile(path, []byte("irrelevant"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := securefs.IdentityOnlyPermissions()
	loader := config.Loader{CheckoutIdentity: checkout, Policies: config.SecurityPolicies{ConfigDirectory: securefs.RootPolicy{Access: p}, ConfigFile: securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)}, StateDirectory: securefs.RootPolicy{Access: p}}}
	_, err = loader.Load(path, config.ValidatePure)
	var typed *config.Error
	if !errors.As(err, &typed) || typed.DiagnosticCode() != contract.D004 || !errors.Is(err, config.ErrPathSecurity) {
		t.Fatalf("checkout exclusion error = %v", err)
	}
}
