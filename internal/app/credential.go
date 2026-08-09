package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/config"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type credentialCommands interface {
	Add(context.Context, string, io.Reader, time.Time) (credential.Record, [32]byte, error)
	Revoke(context.Context, credential.RecordID) (credential.Record, error)
	Purge(context.Context, credential.RecordID) error
	List(context.Context) ([]credential.Record, error)
}

type credentialDependencies struct {
	defaults func() (string, error)
	open     func(context.Context, string) (credentialCommands, func(), error)
	entropy  io.Reader
	now      func() time.Time
}

func NewCredentialHandler() Handler {
	return newCredentialHandler(credentialDependencies{
		defaults: func() (string, error) {
			defaults, err := config.PlatformDefaults()
			return defaults.Config, err
		},
		open: openCredentialCommands, entropy: rand.Reader, now: timebase.Real{}.Now,
	})
}

func openCredentialCommands(_ context.Context, path string) (credentialCommands, func(), error) {
	loaded, err := config.Load(path, config.ValidatePure)
	if err != nil {
		return nil, nil, err
	}
	policies, err := config.PlatformSecurityPolicies()
	if err != nil {
		_ = loaded.Close()
		return nil, nil, err
	}
	checkout, err := config.CheckoutIdentity()
	if err != nil {
		_ = loaded.Close()
		return nil, nil, err
	}
	rootPolicy := policies.StateDirectory
	rootPolicy.ExcludedAncestor = checkout
	root, err := securefs.OpenMutableRoot(loaded.Config().StateRootPath(), rootPolicy)
	if err != nil {
		_ = loaded.Close()
		return nil, nil, err
	}
	repository, err := credential.OpenRepository(root, loaded.Config().InstanceID(), policies.StateFile)
	if err != nil {
		_ = root.Close()
		_ = loaded.Close()
		return nil, nil, err
	}
	closeAll := func() {
		_ = root.Close()
		_ = loaded.Close()
	}
	return repository, closeAll, nil
}

func newCredentialHandler(deps credentialDependencies) Handler {
	return func(ctx context.Context, invocation cli.Invocation) Result {
		if deps.defaults == nil || deps.open == nil || deps.entropy == nil || deps.now == nil {
			return credentialFailure(credential.ErrUnavailable)
		}
		path := invocation.ConfigPath
		if path == "" {
			var err error
			path, err = deps.defaults()
			if err != nil {
				return credentialFailure(err)
			}
		}
		repository, closeRepository, err := deps.open(ctx, path)
		if err != nil || repository == nil || closeRepository == nil {
			return credentialFailure(err)
		}
		defer closeRepository()
		output := bytes.Buffer{}
		switch invocation.Command {
		case cli.CredentialAdd:
			record, secret, commandErr := repository.Add(ctx, invocation.Device, deps.entropy, deps.now().UTC())
			if commandErr != nil {
				return credentialFailure(commandErr)
			}
			fmt.Fprintf(&output, "record_id=%s\ndevice_identifier=%s\nsecret=%s\n", record.ID, record.Device, base64.RawURLEncoding.EncodeToString(secret[:]))
		case cli.CredentialRevoke:
			id, parseErr := credential.ParseRecordID(invocation.RecordID)
			if parseErr != nil {
				return credentialFailure(parseErr)
			}
			record, commandErr := repository.Revoke(ctx, id)
			if commandErr != nil {
				return credentialFailure(commandErr)
			}
			fmt.Fprintf(&output, "record_id=%s\nstate=revoked\n", record.ID)
		case cli.CredentialPurge:
			id, parseErr := credential.ParseRecordID(invocation.RecordID)
			if parseErr != nil {
				return credentialFailure(parseErr)
			}
			if commandErr := repository.Purge(ctx, id); commandErr != nil {
				return credentialFailure(commandErr)
			}
			fmt.Fprintf(&output, "record_id=%s\nstate=purged\n", id)
		case cli.CredentialList:
			records, commandErr := repository.List(ctx)
			if commandErr != nil {
				return credentialFailure(commandErr)
			}
			output.WriteString("record_id\tdevice_identifier\tcreated_at\tstate\n")
			for _, record := range records {
				fmt.Fprintf(&output, "%s\t%s\t%s\t%s\n", record.ID, record.Device, record.CreatedAt.UTC().Format(time.RFC3339Nano), record.State)
			}
		default:
			return credentialFailure(credential.ErrInvalid)
		}
		return Result{Stdout: output.Bytes(), OutputFailed: []byte("credential error: output_failed\n")}
	}
}

func credentialFailure(err error) Result {
	message := "store_unavailable"
	switch {
	case errors.Is(err, credential.ErrDeviceExists):
		message = "already_exists"
	case errors.Is(err, credential.ErrRecordNotFound):
		message = "not_found"
	case errors.Is(err, credential.ErrAlreadyRevoked):
		message = "already_revoked"
	case errors.Is(err, credential.ErrRecordActive):
		message = "not_revoked"
	case errors.Is(err, credential.ErrRollbackConflict):
		message = "rollback_conflict"
	case errors.Is(err, credential.ErrGenerationExhausted):
		message = "generation_exhausted"
	}
	return Result{ExitCode: 1, Stderr: []byte("credential error: " + message + "\n")}
}
