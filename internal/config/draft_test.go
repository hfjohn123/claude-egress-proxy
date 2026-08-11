package config_test

import (
	"bytes"
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

func TestReadDraftReturnsStableDecodedDefensiveSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.yaml")
	document := append(validDocument(t), []byte("destination:\n  profile: all\n")...)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}

	draft, err := config.ReadDraft(path)
	if err != nil {
		t.Fatal(err)
	}
	if draft.Identity() == (securefs.Identity{}) {
		t.Fatal("draft has no retained file identity")
	}
	if draft.Config().Destination().Profile() != config.ProfileAll {
		t.Fatalf("profile = %v, want all", draft.Config().Destination().Profile())
	}
	got := draft.Document()
	if !bytes.Equal(got, document) {
		t.Fatalf("document = %q, want %q", got, document)
	}
	got[0] = 'x'
	if bytes.Equal(got, draft.Document()) {
		t.Fatal("caller mutated retained draft bytes")
	}
}

func TestReadDraftReportsClosedDraftStage(t *testing.T) {
	_, err := config.ReadDraft(filepath.Join(t.TempDir(), "missing", "draft.yaml"))
	if stage, ok := config.PathStageOf(err); !ok || stage != "draft_file" || !errors.Is(err, config.ErrPathSecurity) {
		t.Fatalf("draft error = stage %q ok %v err %v", stage, ok, err)
	}
}

func TestValidateReplacementRejectsImmutableFieldsAndReusesInstalledState(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	currentDocument := replacementDocument(state, "000102030405060708090a0b0c0d0e0f", "code")
	loaded := loadReplacementBase(t, base, currentDocument)
	defer loaded.Close()

	valid := readReplacementDraft(t, base, replacementDocument(state, "000102030405060708090a0b0c0d0e0f", "all"))
	if err := config.ValidateReplacement(loaded, valid); err != nil {
		t.Fatalf("valid replacement = %v", err)
	}

	changedID := readReplacementDraft(t, base, replacementDocument(state, "100102030405060708090a0b0c0d0e0f", "all"))
	if err := config.ValidateReplacement(loaded, changedID); !errors.Is(err, config.ErrImmutable) {
		t.Fatalf("changed instance error = %v", err)
	}

	otherState := filepath.Join(base, "other-state")
	if err := os.Mkdir(otherState, 0o700); err != nil {
		t.Fatal(err)
	}
	changedState := readReplacementDraft(t, base, replacementDocument(otherState, "000102030405060708090a0b0c0d0e0f", "all"))
	if err := config.ValidateReplacement(loaded, changedState); !errors.Is(err, config.ErrImmutable) {
		t.Fatalf("changed state error = %v", err)
	}

	missingRoot := filepath.VolumeName(base) + string(os.PathSeparator)
	missingCertificate := bytes.Replace(valid.Document(), []byte("mode: acme\n  hostname: proxy.example.com"), []byte(fmt.Sprintf("mode: supplied\n  hostname: proxy.example.com\n  certificate_file: %q\n  private_key_file: %q", filepath.Join(missingRoot, "missing", "cert.pem"), filepath.Join(missingRoot, "missing", "key.pem"))), 1)
	badRuntime := readReplacementDraft(t, base, missingCertificate)
	if err := config.ValidateReplacement(loaded, badRuntime); err == nil || errors.Is(err, config.ErrImmutable) {
		t.Fatalf("missing certificate error = %v", err)
	}

	document := loaded.Document()
	document[0] = 'x'
	if bytes.Equal(document, loaded.Document()) {
		t.Fatal("caller mutated retained installed bytes")
	}
}

func TestLoaderReportsNonSensitivePathStages(t *testing.T) {
	base := t.TempDir()
	p := securefs.IdentityOnlyPermissions()
	policies := config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
		StateDirectory:  securefs.RootPolicy{Access: p},
	}
	loader := config.Loader{Policies: policies}

	_, err := loader.Load(filepath.Join(base, "missing", "config.yaml"), config.ValidatePure)
	if stage, ok := config.PathStageOf(err); !ok || stage != "config_directory" {
		t.Fatalf("config directory error = stage %q ok %v err %v", stage, ok, err)
	}

	_, err = loader.Load(filepath.Join(base, "missing.yaml"), config.ValidatePure)
	if stage, ok := config.PathStageOf(err); !ok || stage != "config_file" {
		t.Fatalf("config file error = stage %q ok %v err %v", stage, ok, err)
	}

	path := filepath.Join(base, "config.yaml")
	document := replacementDocument(filepath.Join(base, "missing-state"), "000102030405060708090a0b0c0d0e0f", "code")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = loader.Load(path, config.ValidatePure)
	if stage, ok := config.PathStageOf(err); !ok || stage != "state_directory" {
		t.Fatalf("state directory error = stage %q ok %v err %v", stage, ok, err)
	}
	if strings.Contains(err.Error(), base) {
		t.Fatalf("path stage leaked deployment path: %v", err)
	}
}

func replacementDocument(state, instance, profile string) []byte {
	return []byte(fmt.Sprintf("format_version: 1\ninstance_id: %s\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\ndestination:\n  profile: %s\n", instance, state, profile))
}

func replacementPolicies() config.SecurityPolicies {
	p := securefs.IdentityOnlyPermissions()
	return config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
		StateDirectory:  securefs.RootPolicy{Access: p},
		StateFile:       securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().StoreBytes)},
	}
}

func loadReplacementBase(t *testing.T, base string, document []byte) *config.Loaded {
	t.Helper()
	path := filepath.Join(base, "installed.yaml")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := (config.Loader{Policies: replacementPolicies()}).Load(path, config.ValidateOperational)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func readReplacementDraft(t *testing.T, base string, document []byte) config.Draft {
	t.Helper()
	path := filepath.Join(base, fmt.Sprintf("draft-%d.yaml", len(document)))
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	draft, err := config.ReadDraft(path)
	if err != nil {
		t.Fatal(err)
	}
	return draft
}
