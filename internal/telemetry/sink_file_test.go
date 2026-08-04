package telemetry

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestValidateFileSinkRejectsUnsafeBase(t *testing.T) {
	policy := securefs.FilePolicy{
		Presence: securefs.Optional,
		Kind:     securefs.RegularFile,
		Access:   securefs.IdentityOnlyPermissions(),
		MaxBytes: 10_485_760,
	}
	for _, base := range []string{"", ".", "..", "../log", "log.1", "log.lock", "log.delete"} {
		err := ValidateFileSink(context.Background(), nil, base, policy, CheckOnly)
		if !errors.Is(err, ErrInvalidFileSink) {
			t.Fatalf("base %q: got %v, want ErrInvalidFileSink", base, err)
		}
	}
}

func TestValidateFileSinkRejectsIdentityOnlyPolicy(t *testing.T) {
	dir := t.TempDir()
	root, err := securefs.OpenRoot(dir, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.IdentityOnlyPermissions(), MaxBytes: fileSinkMemberBytes}
	clean, _ := TunnelClosed(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), mustCloseResult(t, "clean"), nil)
	path := filepath.Join(dir, "events")
	before := []byte(clean.JSON() + "\n")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFileSink(context.Background(), root, "events", policy, CheckOnly); !errors.Is(err, ErrInvalidFileSink) {
		t.Fatalf("ValidateFileSink = %v, want ErrInvalidFileSink", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("invalid policy mutated generation: %q", after)
	}
}

func TestValidateFileSinkRejectsIdentityOnlyPolicyBeforeTailRepair(t *testing.T) {
	dir := t.TempDir()
	root, err := securefs.OpenRoot(dir, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.IdentityOnlyPermissions(), MaxBytes: fileSinkMemberBytes}
	clean, _ := TunnelClosed(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), mustCloseResult(t, "clean"), nil)
	if err := os.WriteFile(filepath.Join(dir, "events"), []byte(clean.JSON()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFileSink(context.Background(), root, "events", policy, CheckOnly); !errors.Is(err, ErrInvalidFileSink) {
		t.Fatalf("ValidateFileSink = %v, want ErrInvalidFileSink", err)
	}
}

func TestValidateFileSinkRejectsIdentityOnlyPolicyBeforeTombstoneRepair(t *testing.T) {
	dir := t.TempDir()
	root, err := securefs.OpenRoot(dir, securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: securefs.IdentityOnlyPermissions(), MaxBytes: fileSinkMemberBytes}
	if err := os.WriteFile(filepath.Join(dir, "events.delete"), []byte("interrupted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFileSink(context.Background(), root, "events", policy, CheckOnly); !errors.Is(err, ErrInvalidFileSink) {
		t.Fatalf("ValidateFileSink = %v, want ErrInvalidFileSink", err)
	}
}

func mustCloseResult(t *testing.T, name string) contract.CloseResult {
	t.Helper()
	v, ok := contract.ParseCloseResult(name)
	if !ok {
		t.Fatalf("ParseCloseResult(%q)", name)
	}
	return v
}
