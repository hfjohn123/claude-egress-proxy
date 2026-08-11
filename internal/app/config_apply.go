package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

const configApplyLockName = "cfgapply.lck"

var errConfigApplyReservedLockName = errors.New("installed configuration uses reserved apply lock name")

type configApplyDependencies struct {
	defaults  func() (config.DefaultPaths, error)
	load      func(string, config.ValidationMode) (*config.Loaded, error)
	readDraft func(string, securefs.Identity) (config.Draft, error)
	validate  func(*config.Loaded, config.Draft) error
	publish   func(context.Context, string, []byte) (securefs.CommitBoundary, error)
	withLock  func(context.Context, string, func(context.Context, configApplyTransaction) Result) (Result, error)
}

type configApplyTransaction struct {
	directoryIdentity securefs.Identity
	publish           func(context.Context, string, []byte) (securefs.CommitBoundary, error)
}

type installedConfigFilesystem struct {
	securityPolicies      func() (config.SecurityPolicies, error)
	checkoutIdentity      func() (securefs.Identity, error)
	validateMutableOutput func(string, securefs.Identity, securefs.RootPolicy, securefs.FilePolicy) (securefs.MutableRoot, string, securefs.FileState, error)
}

type installedPathError struct {
	stage config.PathStage
	err   error
}

func (e installedPathError) Error() string { return e.err.Error() }
func (e installedPathError) Unwrap() error { return e.err }

func NewConfigApplyHandler() Handler {
	filesystem := productionInstalledConfigFilesystem()
	return newConfigApplyHandler(configApplyDependencies{
		defaults: config.PlatformDefaults,
		load:     config.Load,
		readDraft: func(path string, excluded securefs.Identity) (config.Draft, error) {
			return config.ReadDraftExcluding(path, excluded)
		},
		validate: config.ValidateReplacement,
		publish:  publishInstalledConfig,
		withLock: func(ctx context.Context, path string, fn func(context.Context, configApplyTransaction) Result) (Result, error) {
			return withInstalledConfigLockUsing(ctx, path, fn, filesystem)
		},
	})
}

func newConfigApplyHandler(deps configApplyDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		path := invocation.ConfigPath
		if path == "" {
			if deps.defaults == nil {
				return configApplyFailure("preflight_failed")
			}
			defaults, err := deps.defaults()
			if err != nil {
				return configApplyFailure("preflight_failed")
			}
			path = defaults.Config
		}
		if sameConfigApplyPath(path, invocation.ConfigInput) || configApplyDraftWithinInstalledDirectory(path, invocation.ConfigInput) {
			return configApplyFailure("draft_invalid stage=" + string(config.PathStageDraftFile))
		}
		if deps.load == nil || deps.readDraft == nil || deps.validate == nil || deps.publish == nil || deps.withLock == nil {
			return configApplyFailure("preflight_failed")
		}

		result, err := deps.withLock(ctx, path, func(lockedContext context.Context, transaction configApplyTransaction) Result {
			return applyConfigLocked(lockedContext, invocation, path, transaction, deps)
		})
		if err == nil {
			return result
		}
		if stage, ok := installedPathStage(err); ok {
			return configApplyFailure("installed_path_security stage=" + string(stage))
		}
		return configApplyFailure("preflight_failed")
	}
}

func applyConfigLocked(ctx context.Context, invocation cli.Invocation, path string, transaction configApplyTransaction, deps configApplyDependencies) Result {
	if transaction.directoryIdentity != (securefs.Identity{}) && transaction.publish == nil {
		return configApplyFailure("preflight_failed")
	}
	current, err := deps.load(path, config.ValidateOperational)
	if err != nil {
		return configApplyInstalledFailure(err)
	}
	if !configApplyLoadedInDirectory(current, transaction.directoryIdentity) {
		_ = current.Close()
		return configApplyFailure("installed_path_security stage=" + string(config.PathStageConfigDirectory))
	}

	draft, err := deps.readDraft(invocation.ConfigInput, current.ConfigDirectoryIdentity())
	if err != nil {
		_ = current.Close()
		if stage, ok := config.PathStageOf(err); ok && stage == config.PathStageDraftFile {
			return configApplyFailure("draft_invalid stage=" + string(stage))
		}
		return configApplyFailure("draft_invalid")
	}
	if draft.Identity() == current.ConfigIdentity() {
		_ = current.Close()
		return configApplyFailure("draft_invalid stage=" + string(config.PathStageDraftFile))
	}
	previous := current.Document()
	if err := deps.validate(current, draft); err != nil {
		_ = current.Close()
		if errors.Is(err, config.ErrImmutable) {
			return configApplyFailure("immutable_change")
		}
		return configApplyFailure("preflight_failed")
	}
	if err := current.Close(); err != nil {
		return configApplyFailure("preflight_failed")
	}
	publish := deps.publish
	if transaction.publish != nil {
		publish = transaction.publish
	}

	boundary, err := publish(ctx, path, draft.Document())
	if err != nil || !commitComplete(boundary) {
		if boundary.NamespacePublished {
			if !restoreInstalledConfig(ctx, deps, publish, path, previous, transaction.directoryIdentity) {
				return configApplyFailure("rollback_failed")
			}
			return configApplyFailure("publish_failed rollback=restored")
		}
		if stage, ok := installedPathStage(err); ok {
			return configApplyFailure("installed_path_security stage=" + string(stage))
		}
		return configApplyFailure("publish_failed")
	}

	candidate, err := deps.load(path, config.ValidateOperational)
	if err == nil && !configApplyLoadedInDirectory(candidate, transaction.directoryIdentity) {
		err = installedPathError{stage: config.PathStageConfigDirectory, err: securefs.ErrIdentityChanged}
	}
	if err == nil && !bytes.Equal(candidate.Document(), draft.Document()) {
		err = errors.New("published configuration bytes differ")
	}
	if candidate != nil {
		if closeErr := candidate.Close(); err == nil {
			err = closeErr
		}
	}
	if err != nil {
		if !restoreInstalledConfig(ctx, deps, publish, path, previous, transaction.directoryIdentity) {
			return configApplyFailure("rollback_failed")
		}
		return configApplyFailure("post_publish_failed rollback=restored")
	}
	return Result{Stdout: []byte("state=applied\nrestart_required=true\n")}
}

func productionInstalledConfigFilesystem() installedConfigFilesystem {
	return installedConfigFilesystem{
		securityPolicies:      config.PlatformSecurityPolicies,
		checkoutIdentity:      config.CheckoutIdentity,
		validateMutableOutput: securefs.ValidateMutableOutput,
	}
}

func installedConfigFilePolicy(policies config.SecurityPolicies) securefs.FilePolicy {
	policy := policies.ConfigFile
	policy.Presence = securefs.Optional
	policy.Kind = securefs.RegularFile
	policy.MaxBytes = int64(contract.V1().ConfigBytes)
	return policy
}

func validateInstalledMutableOutput(path string, expectedDirectory securefs.Identity, filesystem installedConfigFilesystem) (securefs.MutableRoot, string, securefs.FilePolicy, error) {
	policies, err := filesystem.securityPolicies()
	if err != nil {
		return nil, "", securefs.FilePolicy{}, err
	}
	checkout, err := filesystem.checkoutIdentity()
	if err != nil {
		return nil, "", securefs.FilePolicy{}, securefs.ErrIdentityChanged
	}
	policy := installedConfigFilePolicy(policies)
	parent, name, _, err := filesystem.validateMutableOutput(path, checkout, policies.ConfigDirectory, policy)
	if err != nil {
		stage := config.PathStageConfigDirectory
		if outputStage, ok := securefs.OutputStageOf(err); ok && outputStage == securefs.OutputStageLeaf {
			stage = config.PathStageConfigFile
		}
		return nil, "", securefs.FilePolicy{}, installedPathError{stage: stage, err: err}
	}
	if expectedDirectory != (securefs.Identity{}) && parent.Identity() != expectedDirectory {
		_ = parent.Close()
		return nil, "", securefs.FilePolicy{}, installedPathError{stage: config.PathStageConfigDirectory, err: securefs.ErrIdentityChanged}
	}
	return parent, name, policy, nil
}

func publishInstalledConfig(ctx context.Context, path string, document []byte) (securefs.CommitBoundary, error) {
	return publishInstalledConfigUsing(ctx, path, document, securefs.Identity{}, productionInstalledConfigFilesystem())
}

func publishInstalledConfigUsing(ctx context.Context, path string, document []byte, expectedDirectory securefs.Identity, filesystem installedConfigFilesystem) (securefs.CommitBoundary, error) {
	parent, name, policy, err := validateInstalledMutableOutput(path, expectedDirectory, filesystem)
	if err != nil {
		return securefs.CommitBoundary{}, err
	}
	defer parent.Close()
	boundary, err := parent.PublishOutput(ctx, name, document, policy)
	if err != nil {
		return boundary, err
	}
	if !commitComplete(boundary) {
		return boundary, securefs.ErrUnsupportedInspection
	}
	return boundary, nil
}

func withInstalledConfigLockUsing(ctx context.Context, path string, fn func(context.Context, configApplyTransaction) Result, filesystem installedConfigFilesystem) (Result, error) {
	parent, installedName, policy, err := validateInstalledMutableOutput(path, securefs.Identity{}, filesystem)
	if err != nil {
		return Result{}, err
	}
	defer parent.Close()
	if configDirectoryLeafReserved(installedName) {
		return Result{}, errConfigApplyReservedLockName
	}
	directoryIdentity := parent.Identity()
	if directoryIdentity == (securefs.Identity{}) {
		return Result{}, installedPathError{stage: config.PathStageConfigDirectory, err: securefs.ErrIdentityChanged}
	}

	var result Result
	err = parent.WithExclusiveLock(ctx, configApplyLockName, policy, func(securefs.LockedFile) error {
		result = fn(ctx, configApplyTransaction{
			directoryIdentity: directoryIdentity,
			publish: func(publishContext context.Context, publishPath string, document []byte) (securefs.CommitBoundary, error) {
				return publishInstalledConfigUsing(publishContext, publishPath, document, directoryIdentity, filesystem)
			},
		})
		return nil
	})
	if err != nil {
		if ctx.Err() != nil {
			return Result{}, ctx.Err()
		}
		return Result{}, installedPathError{stage: config.PathStageConfigDirectory, err: err}
	}
	return result, nil
}

func restoreInstalledConfig(ctx context.Context, deps configApplyDependencies, publish func(context.Context, string, []byte) (securefs.CommitBoundary, error), path string, previous []byte, expectedDirectory securefs.Identity) bool {
	boundary, err := publish(context.WithoutCancel(ctx), path, previous)
	if err != nil || !commitComplete(boundary) {
		return false
	}
	restored, err := deps.load(path, config.ValidateOperational)
	if err != nil {
		return false
	}
	equal := configApplyLoadedInDirectory(restored, expectedDirectory) && bytes.Equal(restored.Document(), previous)
	return restored.Close() == nil && equal
}

func configApplyLoadedInDirectory(loaded *config.Loaded, expected securefs.Identity) bool {
	return expected == (securefs.Identity{}) || loaded.ConfigDirectoryIdentity() == expected
}

func commitComplete(boundary securefs.CommitBoundary) bool {
	return boundary.NamespacePublished && boundary.TargetDurable
}

func configApplyInstalledFailure(err error) Result {
	if stage, ok := config.PathStageOf(err); ok && config.IsInstalledPathStage(stage) {
		return configApplyFailure("installed_path_security stage=" + string(stage))
	}
	return configApplyFailure("preflight_failed")
}

func installedPathStage(err error) (config.PathStage, bool) {
	var staged installedPathError
	if !errors.As(err, &staged) || !config.IsInstalledPathStage(staged.stage) {
		return "", false
	}
	return staged.stage, true
}

func configApplyFailure(outcome string) Result {
	return Result{ExitCode: 1, Stderr: []byte(fmt.Sprintf("config apply error: %s\n", outcome))}
}

func configApplyDraftWithinInstalledDirectory(installed, draft string) bool {
	directory := filepath.Clean(filepath.Dir(installed))
	draft = filepath.Clean(draft)
	if runtime.GOOS == "windows" {
		directory = strings.ToLower(directory)
		draft = strings.ToLower(draft)
	}
	relative, err := filepath.Rel(directory, draft)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func sameConfigApplyPath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
