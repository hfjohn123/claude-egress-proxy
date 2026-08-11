package app

import (
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

type configApplyDependencies struct {
	defaults  func() (config.DefaultPaths, error)
	load      func(string, config.ValidationMode) (*config.Loaded, error)
	readDraft func(string) (config.Draft, error)
	validate  func(*config.Loaded, config.Draft) error
	publish   func(context.Context, string, []byte) (securefs.CommitBoundary, error)
}

type installedPathError struct {
	stage string
	err   error
}

func (e installedPathError) Error() string { return e.err.Error() }
func (e installedPathError) Unwrap() error { return e.err }

func NewConfigApplyHandler() Handler {
	return newConfigApplyHandler(configApplyDependencies{
		defaults:  config.PlatformDefaults,
		load:      config.Load,
		readDraft: config.ReadDraft,
		validate:  config.ValidateReplacement,
		publish:   publishInstalledConfig,
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
		if sameConfigApplyPath(path, invocation.ConfigInput) || sameConfigApplyPath(filepath.Dir(path), filepath.Dir(invocation.ConfigInput)) {
			return configApplyFailure("draft_invalid")
		}
		if deps.load == nil || deps.readDraft == nil || deps.validate == nil || deps.publish == nil {
			return configApplyFailure("preflight_failed")
		}

		draft, err := deps.readDraft(invocation.ConfigInput)
		if err != nil {
			return configApplyFailure("draft_invalid")
		}
		current, err := deps.load(path, config.ValidateOperational)
		if err != nil {
			return configApplyInstalledFailure(err)
		}
		if draft.Identity() == current.ConfigIdentity() {
			_ = current.Close()
			return configApplyFailure("draft_invalid")
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

		boundary, err := deps.publish(ctx, path, draft.Document())
		if err != nil || !commitComplete(boundary) {
			if boundary.NamespacePublished {
				if !restoreInstalledConfig(ctx, deps, path, previous) {
					return configApplyFailure("rollback_failed")
				}
				return configApplyFailure("publish_failed")
			}
			if stage, ok := installedPathStage(err); ok {
				return configApplyFailure("installed_path_security stage=" + stage)
			}
			return configApplyFailure("publish_failed")
		}

		candidate, err := deps.load(path, config.ValidateOperational)
		if err == nil {
			err = candidate.Close()
		}
		if err != nil {
			if !restoreInstalledConfig(ctx, deps, path, previous) {
				return configApplyFailure("rollback_failed")
			}
			return configApplyFailure("post_publish_failed rollback=restored")
		}
		return Result{Stdout: []byte("state=applied\nrestart_required=true\n")}
	}
}

func publishInstalledConfig(ctx context.Context, path string, document []byte) (securefs.CommitBoundary, error) {
	policies, err := config.PlatformSecurityPolicies()
	if err != nil {
		return securefs.CommitBoundary{}, err
	}
	checkout, err := config.CheckoutIdentity()
	if err != nil {
		return securefs.CommitBoundary{}, securefs.ErrIdentityChanged
	}
	policy := policies.ConfigFile
	policy.Presence = securefs.Optional
	policy.Kind = securefs.RegularFile
	policy.MaxBytes = int64(contract.V1().ConfigBytes)
	parent, name, _, err := securefs.ValidateMutableOutput(path, checkout, policies.ConfigDirectory, policy)
	if err != nil {
		stage := "config_directory"
		if outputStage, ok := securefs.OutputStageOf(err); ok && outputStage == securefs.OutputStageLeaf {
			stage = "config_file"
		}
		return securefs.CommitBoundary{}, installedPathError{stage: stage, err: err}
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

func restoreInstalledConfig(ctx context.Context, deps configApplyDependencies, path string, previous []byte) bool {
	boundary, err := deps.publish(context.WithoutCancel(ctx), path, previous)
	if err != nil || !commitComplete(boundary) {
		return false
	}
	restored, err := deps.load(path, config.ValidateOperational)
	if err != nil {
		return false
	}
	return restored.Close() == nil
}

func commitComplete(boundary securefs.CommitBoundary) bool {
	return boundary.NamespacePublished && boundary.TargetDurable
}

func configApplyInstalledFailure(err error) Result {
	if stage, ok := config.PathStageOf(err); ok && validConfigApplyStage(stage) {
		return configApplyFailure("installed_path_security stage=" + stage)
	}
	return configApplyFailure("preflight_failed")
}

func installedPathStage(err error) (string, bool) {
	var staged installedPathError
	if !errors.As(err, &staged) || !validConfigApplyStage(staged.stage) {
		return "", false
	}
	return staged.stage, true
}

func validConfigApplyStage(stage string) bool {
	switch stage {
	case "config_directory", "config_file", "state_directory":
		return true
	default:
		return false
	}
}

func configApplyFailure(outcome string) Result {
	return Result{ExitCode: 1, Stderr: []byte(fmt.Sprintf("config apply error: %s\n", outcome))}
}

func sameConfigApplyPath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
