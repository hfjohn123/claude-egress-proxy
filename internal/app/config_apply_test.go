package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

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
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: draft_invalid stage=draft_file\n" || called {
		t.Fatalf("result=%+v called=%v", result, called)
	}
}

func TestConfigApplyRejectsDraftBelowInstalledDirectory(t *testing.T) {
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
		ConfigInput: filepath.Join(base, "staged", "draft.yaml"),
	})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: draft_invalid stage=draft_file\n" || called {
		t.Fatalf("result=%+v called=%v", result, called)
	}
}

func TestConfigApplyReportsDraftPathStage(t *testing.T) {
	base, current, _ := configApplyFixture(t)
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			return loadConfigApplySnapshot(t, base, current)
		},
		readDraft: readConfigApplyDraft,
		validate:  config.ValidateReplacement,
		publish:   publishInstalledConfig,
		withLock:  passthroughConfigApplyLock,
	})

	result := handler(context.Background(), cli.Invocation{
		ConfigPath:  filepath.Join(base, "installed", "config.yaml"),
		ConfigInput: filepath.Join(base, "missing", "draft.yaml"),
	})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: draft_invalid stage=draft_file\n" {
		t.Fatalf("result=%+v", result)
	}
}

func TestConfigApplyRejectsSameFileThroughHardLink(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "state")
	installedDir := filepath.Join(base, "installed")
	draftDir := filepath.Join(base, "draft")
	for _, path := range []string{state, installedDir, draftDir} {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installed := filepath.Join(installedDir, "config.yaml")
	if err := os.WriteFile(installed, configApplyDocument(state, "code"), 0o600); err != nil {
		t.Fatal(err)
	}
	draftPath := filepath.Join(draftDir, "draft.yaml")
	if err := os.Link(installed, draftPath); err != nil {
		t.Fatal(err)
	}
	p := securefs.IdentityOnlyPermissions()
	loader := config.Loader{Policies: config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: p},
		ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().ConfigBytes)},
		StateDirectory:  securefs.RootPolicy{Access: p},
		StateFile:       securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, Access: p, MaxBytes: int64(contract.V1().StoreBytes)},
	}}
	published := false
	handler := newConfigApplyHandler(configApplyDependencies{
		load:      loader.Load,
		readDraft: readConfigApplyDraft,
		validate:  config.ValidateReplacement,
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			published = true
			return securefs.CommitBoundary{}, nil
		},
		withLock: passthroughConfigApplyLock,
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: installed, ConfigInput: draftPath})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: draft_invalid stage=draft_file\n" || published {
		t.Fatalf("result=%+v published=%v", result, published)
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
				readDraft: func(string, securefs.Identity) (config.Draft, error) {
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
				withLock: passthroughConfigApplyLock,
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
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(_ context.Context, _ string, body []byte) (securefs.CommitBoundary, error) {
			publishes++
			if string(body) != string(draft.Document()) {
				t.Fatal("published body differs from stable draft")
			}
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: passthroughConfigApplyLock,
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 0 || string(result.Stdout) != "state=applied\nrestart_required=true\n" || len(result.Stderr) != 0 || loads != 2 || publishes != 1 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func TestConfigApplyRunsCompleteTransactionUnderLock(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	insideLock := false
	loads := 0
	assertLocked := func(stage string) {
		t.Helper()
		if !insideLock {
			t.Fatalf("%s ran outside config apply lock", stage)
		}
	}
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			assertLocked("load")
			loads++
			if loads == 1 {
				return loadConfigApplySnapshot(t, base, current)
			}
			return loadConfigApplySnapshot(t, base, draft.Document())
		},
		readDraft: func(_ string, excluded securefs.Identity) (config.Draft, error) {
			assertLocked("draft read")
			if excluded == (securefs.Identity{}) {
				t.Fatal("draft read did not receive installed directory identity")
			}
			return draft, nil
		},
		validate: func(*config.Loaded, config.Draft) error {
			assertLocked("validation")
			return nil
		},
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			assertLocked("publish")
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: func(ctx context.Context, _ string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
			if insideLock {
				t.Fatal("nested config apply lock")
			}
			insideLock = true
			result := fn(ctx, configApplyTransaction{})
			insideLock = false
			return result, nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 0 || loads != 2 || insideLock {
		t.Fatalf("result=%+v loads=%d insideLock=%v", result, loads, insideLock)
	}
}

func TestConfigApplyRejectsReopenedDirectoryOutsideLock(t *testing.T) {
	base, current, _ := configApplyFixture(t)
	lockedIdentity := configApplyTestIdentity(t)
	draftRead := false
	published := false
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			return loadConfigApplySnapshot(t, base, current)
		},
		readDraft: func(string, securefs.Identity) (config.Draft, error) {
			draftRead = true
			return config.Draft{}, nil
		},
		validate: func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			published = true
			return securefs.CommitBoundary{}, nil
		},
		withLock: func(ctx context.Context, _ string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
			return fn(ctx, configApplyTransaction{
				directoryIdentity: lockedIdentity,
				publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
					published = true
					return securefs.CommitBoundary{}, nil
				},
			}), nil
		},
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: installed_path_security stage=config_directory\n" || draftRead || published {
		t.Fatalf("result=%+v draftRead=%v published=%v", result, draftRead, published)
	}
}

func TestConfigApplyRejectsLockedTransactionWithoutBoundPublisher(t *testing.T) {
	loaded := false
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loaded = true
			return nil, errors.New("unexpected load")
		},
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return config.Draft{}, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			return securefs.CommitBoundary{}, nil
		},
		withLock: func(ctx context.Context, _ string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
			return fn(ctx, configApplyTransaction{directoryIdentity: configApplyTestIdentity(t)}), nil
		},
	})
	base := t.TempDir()
	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: preflight_failed\n" || loaded {
		t.Fatalf("result=%+v loaded=%v", result, loaded)
	}
}

func TestConfigApplySerializesConcurrentTransactions(t *testing.T) {
	base, _, draft := configApplyFixture(t)
	snapshots := make([]*config.Loaded, 4)
	for index := range snapshots {
		loaded, err := loadConfigApplySnapshot(t, base, draft.Document())
		if err != nil {
			t.Fatal(err)
		}
		snapshots[index] = loaded
	}
	var snapshotMu sync.Mutex
	nextSnapshot := 0
	var transactionMu sync.Mutex
	var stateMu sync.Mutex
	active, maximum := 0, 0
	attempted := make(chan struct{}, 2)
	releaseFirst := make(chan struct{})
	lockEntry := 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			snapshotMu.Lock()
			defer snapshotMu.Unlock()
			loaded := snapshots[nextSnapshot]
			nextSnapshot++
			return loaded, nil
		},
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: func(ctx context.Context, _ string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
			attempted <- struct{}{}
			transactionMu.Lock()
			defer transactionMu.Unlock()
			stateMu.Lock()
			active++
			if active > maximum {
				maximum = active
			}
			lockEntry++
			entry := lockEntry
			stateMu.Unlock()
			if entry == 1 {
				<-releaseFirst
			}
			result := fn(ctx, configApplyTransaction{})
			stateMu.Lock()
			active--
			stateMu.Unlock()
			return result, nil
		},
	})

	start := make(chan struct{})
	results := make(chan Result, 2)
	for index := 0; index < 2; index++ {
		go func() {
			<-start
			results <- handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
		}()
	}
	close(start)
	<-attempted
	<-attempted
	close(releaseFirst)
	for index := 0; index < 2; index++ {
		if result := <-results; result.ExitCode != 0 {
			t.Fatalf("concurrent apply result=%+v", result)
		}
	}
	if maximum != 1 || nextSnapshot != len(snapshots) {
		t.Fatalf("maximum active transactions=%d snapshots=%d", maximum, nextSnapshot)
	}
}

func TestPublishInstalledConfigComposesSecurityPolicies(t *testing.T) {
	root := &fakeConfigApplyMutableRoot{}
	configAccess := securefs.IdentityOnlyPermissions()
	directoryAccess := securefs.IdentityOnlyPermissions()
	identityRoot, err := securefs.OpenRoot(t.TempDir(), securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	checkout := identityRoot.Identity()
	if err := identityRoot.Close(); err != nil {
		t.Fatal(err)
	}
	policies := config.SecurityPolicies{
		ConfigDirectory: securefs.RootPolicy{Access: directoryAccess},
		ConfigFile: securefs.FilePolicy{
			Presence: securefs.Required,
			Kind:     securefs.Directory,
			Access:   configAccess,
			MaxBytes: 1,
		},
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	document := []byte("replacement")
	validated := false
	filesystem := installedConfigFilesystem{
		securityPolicies: func() (config.SecurityPolicies, error) { return policies, nil },
		checkoutIdentity: func() (securefs.Identity, error) { return checkout, nil },
		validateMutableOutput: func(gotPath string, gotCheckout securefs.Identity, parent securefs.RootPolicy, output securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error) {
			validated = true
			if gotPath != path || gotCheckout != checkout || !securefs.PermissionsEqual(parent.Access, directoryAccess) {
				t.Fatalf("mutable output path/identity/policy = %q %v %+v", gotPath, gotCheckout == checkout, parent)
			}
			assertConfigApplyFilePolicy(t, output, configAccess)
			return root, "config.yaml", securefs.FileState{}, nil
		},
	}

	boundary, err := publishInstalledConfigUsing(context.Background(), path, document, securefs.Identity{}, filesystem)
	if err != nil || !commitComplete(boundary) || !validated || root.publishName != "config.yaml" || string(root.publishBody) != string(document) {
		t.Fatalf("boundary=%+v err=%v validated=%v root=%+v", boundary, err, validated, root)
	}
	assertConfigApplyFilePolicy(t, root.publishPolicy, configAccess)
}

func TestPublishInstalledConfigRejectsDirectoryOutsideLock(t *testing.T) {
	lockedIdentity := configApplyTestIdentity(t)
	root := &fakeConfigApplyMutableRoot{identity: configApplyTestIdentity(t)}
	access := securefs.IdentityOnlyPermissions()
	filesystem := installedConfigFilesystem{
		securityPolicies: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigDirectory: securefs.RootPolicy{Access: access},
				ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: access, MaxBytes: 1},
			}, nil
		},
		checkoutIdentity: func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: func(string, securefs.Identity, securefs.RootPolicy, securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error) {
			return root, "config.yaml", securefs.FileState{}, nil
		},
	}

	_, err := publishInstalledConfigUsing(context.Background(), filepath.Join(t.TempDir(), "config.yaml"), []byte("replacement"), lockedIdentity, filesystem)
	if stage, ok := installedPathStage(err); !ok || stage != config.PathStageConfigDirectory || root.publishName != "" {
		t.Fatalf("publish mismatch stage=%q ok=%v err=%v root=%+v", stage, ok, err, root)
	}
}

func TestInstalledConfigLockComposesSecurityPolicies(t *testing.T) {
	root := &fakeConfigApplyMutableRoot{identity: configApplyTestIdentity(t)}
	access := securefs.IdentityOnlyPermissions()
	filesystem := installedConfigFilesystem{
		securityPolicies: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigDirectory: securefs.RootPolicy{Access: access},
				ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.Directory, Access: access, MaxBytes: 1},
			}, nil
		},
		checkoutIdentity: func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: func(string, securefs.Identity, securefs.RootPolicy, securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error) {
			return root, "config.yaml", securefs.FileState{}, nil
		},
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	called := false
	result, err := withInstalledConfigLockUsing(context.Background(), path, func(ctx context.Context, transaction configApplyTransaction) Result {
		called = true
		if transaction.directoryIdentity != root.identity || transaction.publish == nil {
			t.Fatalf("transaction=%+v root identity match=%v", transaction, transaction.directoryIdentity == root.identity)
		}
		if boundary, publishErr := transaction.publish(ctx, path, []byte("replacement")); publishErr != nil || !commitComplete(boundary) {
			t.Fatalf("locked publisher boundary=%+v err=%v", boundary, publishErr)
		}
		return Result{Stdout: []byte("locked")}
	}, filesystem)
	if err != nil || !called || string(result.Stdout) != "locked" || root.lockName != configApplyLockName || root.publishName != "config.yaml" {
		t.Fatalf("result=%+v err=%v called=%v root=%+v", result, err, called, root)
	}
	assertConfigApplyFilePolicy(t, root.lockPolicy, access)
}

func TestInstalledConfigLockNeverUsesInstalledLeaf(t *testing.T) {
	root := &fakeConfigApplyMutableRoot{identity: configApplyTestIdentity(t)}
	access := securefs.IdentityOnlyPermissions()
	filesystem := installedConfigFilesystem{
		securityPolicies: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigDirectory: securefs.RootPolicy{Access: access},
				ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: access, MaxBytes: 1},
			}, nil
		},
		checkoutIdentity: func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: func(string, securefs.Identity, securefs.RootPolicy, securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error) {
			return root, configApplyLockName, securefs.FileState{}, nil
		},
	}
	path := filepath.Join(t.TempDir(), configApplyLockName)
	if _, err := withInstalledConfigLockUsing(context.Background(), path, func(context.Context, configApplyTransaction) Result { return Result{} }, filesystem); err == nil {
		t.Fatal("reserved installed leaf accepted")
	}
	if root.lockName != "" {
		t.Fatalf("lock attempted on reserved installed leaf %q", root.lockName)
	}
}

func TestConfigApplyReportsLockFailureAsInstalledDirectory(t *testing.T) {
	handler := newConfigApplyHandler(configApplyDependencies{
		load:      func(string, config.ValidationMode) (*config.Loaded, error) { return nil, nil },
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return config.Draft{}, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			return securefs.CommitBoundary{}, nil
		},
		withLock: func(context.Context, string, func(context.Context, configApplyTransaction) Result) (Result, error) {
			return Result{}, installedPathError{stage: config.PathStageConfigDirectory, err: securefs.ErrUnsafePath}
		},
	})
	base := t.TempDir()
	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: installed_path_security stage=config_directory\n" {
		t.Fatalf("result=%+v", result)
	}
}

func TestInstalledConfigLockClassifiesNamespaceFailure(t *testing.T) {
	root := &fakeConfigApplyMutableRoot{identity: configApplyTestIdentity(t), lockErr: securefs.ErrUnsafePath}
	access := securefs.IdentityOnlyPermissions()
	filesystem := installedConfigFilesystem{
		securityPolicies: func() (config.SecurityPolicies, error) {
			return config.SecurityPolicies{
				ConfigDirectory: securefs.RootPolicy{Access: access},
				ConfigFile:      securefs.FilePolicy{Presence: securefs.Required, Kind: securefs.RegularFile, Access: access, MaxBytes: 1},
			}, nil
		},
		checkoutIdentity: func() (securefs.Identity, error) { return securefs.Identity{}, nil },
		validateMutableOutput: func(string, securefs.Identity, securefs.RootPolicy, securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error) {
			return root, "config.yaml", securefs.FileState{}, nil
		},
	}
	_, err := withInstalledConfigLockUsing(context.Background(), filepath.Join(t.TempDir(), "config.yaml"), func(context.Context, configApplyTransaction) Result { return Result{} }, filesystem)
	if stage, ok := installedPathStage(err); !ok || stage != config.PathStageConfigDirectory {
		t.Fatalf("lock error stage=%q ok=%v err=%v", stage, ok, err)
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
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
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
		withLock: passthroughConfigApplyLock,
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: publish_failed rollback=restored\n" || loads != 2 || publishes != 2 {
		t.Fatalf("result=%+v loads=%d publishes=%d", result, loads, publishes)
	}
}

func TestConfigApplyRollsBackWhenReloadedBytesDiffer(t *testing.T) {
	base, current, draft := configApplyFixture(t)
	other := configApplyDocument(filepath.Join(base, "state"), "web-desktop")
	loads, publishes := 0, 0
	handler := newConfigApplyHandler(configApplyDependencies{
		load: func(string, config.ValidationMode) (*config.Loaded, error) {
			loads++
			switch loads {
			case 1, 3:
				return loadConfigApplySnapshot(t, base, current)
			default:
				return loadConfigApplySnapshot(t, base, other)
			}
		},
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			publishes++
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: passthroughConfigApplyLock,
	})

	result := handler(context.Background(), cli.Invocation{ConfigPath: filepath.Join(base, "installed", "config.yaml"), ConfigInput: filepath.Join(base, "draft", "draft.yaml")})
	if result.ExitCode != 1 || string(result.Stderr) != "config apply error: post_publish_failed rollback=restored\n" || loads != 3 || publishes != 2 {
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
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			publishes++
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: passthroughConfigApplyLock,
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
		readDraft: func(string, securefs.Identity) (config.Draft, error) { return draft, nil },
		validate:  func(*config.Loaded, config.Draft) error { return nil },
		publish: func(context.Context, string, []byte) (securefs.CommitBoundary, error) {
			publishes++
			if publishes == 2 {
				return securefs.CommitBoundary{}, errors.New("rollback rejected")
			}
			return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
		},
		withLock: passthroughConfigApplyLock,
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

type fakeConfigApplyMutableRoot struct {
	identity      securefs.Identity
	publishName   string
	publishBody   []byte
	publishPolicy securefs.FilePolicy
	lockName      string
	lockPolicy    securefs.FilePolicy
	lockErr       error
}

func (r *fakeConfigApplyMutableRoot) Identity() securefs.Identity { return r.identity }
func (*fakeConfigApplyMutableRoot) RecheckIdentity() error        { return nil }
func (*fakeConfigApplyMutableRoot) Inspect(string, securefs.FilePolicy) (securefs.FileState, error) {
	return securefs.FileState{}, nil
}
func (*fakeConfigApplyMutableRoot) ReadFile(string, securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	return nil, securefs.FileState{}, nil
}
func (*fakeConfigApplyMutableRoot) Close() error { return nil }
func (r *fakeConfigApplyMutableRoot) PublishOutput(_ context.Context, name string, body []byte, policy securefs.FilePolicy) (securefs.CommitBoundary, error) {
	r.publishName = name
	r.publishBody = append([]byte(nil), body...)
	r.publishPolicy = policy
	return securefs.CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}
func (r *fakeConfigApplyMutableRoot) WithExclusiveLock(_ context.Context, name string, policy securefs.FilePolicy, fn func(securefs.LockedFile) error) error {
	r.lockName = name
	r.lockPolicy = policy
	if r.lockErr != nil {
		return r.lockErr
	}
	return fn(nil)
}
func (*fakeConfigApplyMutableRoot) AcquireRotationNamespace(context.Context, string, [3]string, securefs.FilePolicy) (securefs.RotationNamespace, error) {
	return nil, errors.New("not implemented")
}

func assertConfigApplyFilePolicy(t *testing.T, policy securefs.FilePolicy, access securefs.PermissionPolicy) {
	t.Helper()
	if policy.Presence != securefs.Optional || policy.Kind != securefs.RegularFile || policy.MaxBytes != int64(contract.V1().ConfigBytes) || !securefs.PermissionsEqual(policy.Access, access) {
		t.Fatalf("config apply file policy = %+v", policy)
	}
}

func configApplyTestIdentity(t *testing.T) securefs.Identity {
	t.Helper()
	root, err := securefs.OpenRoot(t.TempDir(), securefs.RootPolicy{Access: securefs.IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	identity := root.Identity()
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	return identity
}

func assertRealInstalledConfigLockSerializes(t *testing.T, path string, filesystem installedConfigFilesystem) {
	t.Helper()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		_, err := withInstalledConfigLockUsing(context.Background(), path, func(context.Context, configApplyTransaction) Result {
			close(firstEntered)
			<-releaseFirst
			return Result{}
		}, filesystem)
		firstDone <- err
	}()
	<-firstEntered

	secondCalled := false
	secondContext, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	_, secondErr := withInstalledConfigLockUsing(secondContext, path, func(context.Context, configApplyTransaction) Result {
		secondCalled = true
		return Result{}
	}, filesystem)
	cancel()
	close(releaseFirst)
	firstErr := <-firstDone
	if firstErr != nil || !errors.Is(secondErr, context.DeadlineExceeded) || secondCalled {
		t.Fatalf("real lock firstErr=%v secondErr=%v secondCalled=%v", firstErr, secondErr, secondCalled)
	}

	thirdCalled := false
	_, thirdErr := withInstalledConfigLockUsing(context.Background(), path, func(context.Context, configApplyTransaction) Result {
		thirdCalled = true
		return Result{}
	}, filesystem)
	if thirdErr != nil || !thirdCalled {
		t.Fatalf("released lock thirdErr=%v thirdCalled=%v", thirdErr, thirdCalled)
	}
}

func readConfigApplyDraft(path string, excluded securefs.Identity) (config.Draft, error) {
	return config.ReadDraftExcluding(path, excluded)
}

func passthroughConfigApplyLock(ctx context.Context, _ string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
	return fn(ctx, configApplyTransaction{}), nil
}
