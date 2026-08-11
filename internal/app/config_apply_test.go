package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestConfigApplyRejectsDraftInInstalledDirectory(t *testing.T) {
	base := t.TempDir()
	called := false
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			called = true
			return nil, errors.New("unexpected load")
		},
	})

	result := handler(context.Background(), cli.Invocation{
		ConfigPath:  filepath.Join(base, "config.yaml"),
		ConfigInput: filepath.Join(base, "draft.yaml"),
	})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: draft_invalid\n" || called {
		t.Fatalf("result=%+v called=%v", result, called)
	}
}

func TestConfigApplyStopsBeforePublishOnDraftAndPreflightFailures(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	tests := []struct {
		name        string
		readErr     error
		validateErr error
		want        string
	}{
		{name: "draft", readErr: errors.New("bad draft"), want: "config apply error: draft_invalid\n"},
		{name: "immutable", validateErr: config.ErrImmutable, want: "config apply error: immutable_change\n"},
		{name: "preflight", validateErr: errors.New("bad runtime"), want: "config apply error: preflight_failed\n"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			published := 0
			handler := newConfigApplyHandler(configApplyDependencies{
				load: func(string, config.ValidationMode) (*config.Loaded, error) {
					return loadConfigApplySnapshot(t, base, current)
				},
				readDraft: func(string) (config.Draft, error) {
					if test.readErr != nil {
						return config.Draft{}, test.readErr
					}
					return draft, nil
				},
				validate: func(*config.Loaded, config.Draft) error { return test.validateErr },
				publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
					published++
					return securefs.CommitBoundary{}, nil
				},
			})
			result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
			if result.ExitCode != 1 || string(result.Stderr) != test.want || published != 0 {
				t.Fatalf("result=%+v publishes=%d", result, published)
			}
		})
	}
}

func TestConfigApplyPublishesOnceAndReloadsOnSuccess(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	loads, publishes := 0, 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loads++
			if loads == 1 {
				return loadConfigApplySnapshot(t, base, current)
			}
			return loadConfigApplySnapshot(t, base, draft.Document())
		},
		readDraft: func(string) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(_ context.Context, _ string, body []byte) (securefs.CommitBoundary, error) {
			publishes++
			if string(body) != string(draft.Document()) {
				t.Fatal("published body differs from stable draft")
			}
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 0 || string(result.Stdout) != "state=applied\nrestart_required=true\n" || len(result.Stderr) != 0 || loads != 2 || publishes != 1 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func TestConfigApplyRollsBackPublishedFailure(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	loads, publishes := 0, 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loads++
			return loadConfigApplySnapshot(t, base, current)
		},
		readDraft: func(string) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(_ context.Context, _ string, body []byte) (securefs.CommitBoundary, error) {
			publishes++
			if publishes == 1 {
				return securefs.CommitBoundary{NamespacePublished: true}, errors.New("durability failed")
			}
			if string(body) != string(current) {
				t.Fatal("rollback did not use retained installed bytes")
			}
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: publish_failed\n" || loads != 2 || publishes != 2 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func TestConfigApplyRollsBackPostLoadFailure(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	loads, publishes := 0, 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loads++
			if loads == 2 {
				return nil, errors.New("candidate rejected after publication")
			}
			return loadConfigApplySnapshot(t, base, current)
		},
		readDraft: func(string) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			publishes++
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: post_publish_failed rollback=restored\n" || loads != 3 || publishes != 2 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func TestConfigApplyReportsRollbackFailure(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	loads, publishes := 0, 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loads++
			if loads == 2 {
				return nil, errors.New("candidate rejected after publication")
			}
			return loadConfigApplySnapshot(t, base, current)
		},
		readDraft: func(string) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			publishes++
			if publishes == 2 {
				return securefs.CommitBoundary{}, errors.New("rollback rejected")
			}
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: rollback_failed\n" || loads != 2 || publishes != 2 || len(result.Stdout) != 0 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func configApplyFixture(t *testing.T) (string, []byte, config.Draft) {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	current := configApplyDocument(state, "code")
	draftPath := filepath.Join(base, "draft-source", "draft.yaml")
	if err := os.Mkdir(filepath.Dir(draftPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(draftPath, configApplyDocument(state, "all"), 0o600); err != nil {
		t.Fatal(err)
	}
	draft, err := config.ReadDraft(draftPath)
	if err != nil {
		t.Fatal(err)
	}
	return base, current, draft
}

func loadConfigApplySnapshot(t *testing.T, base string, document []byte) (*config.Loaded, error) {
	t.Helper()
	dir, err := os.MkdirTemp(base, "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	p := securefs.IdentityOnlyPermissions()
	policies := config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
		StateDirectory:  securefs.RootPolicy{Access: p},
		StateFile:       securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().StoreBytes)},
	}
	return (config.Loader{Policies: policies}).Load(path, config.ValidateOperational)
}

func configApplyDocument(state, profile string) []byte {
	return []byte(fmt.Sprintf("format_version: 1\ninstance_id: 000102030405060708090a0b0c0d0e0f\nstate_root: %q\ntls:\n  mode: acme\n  hostname: proxy.example.com\ndestination:\n  profile: %s\n", state, profile))
}
