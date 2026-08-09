package app

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/cli"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
)

type fakeCredentialCommands struct {
	records []credential.Record
	secret  [32]byte
	err     error
}

func (f *fakeCredentialCommands) Add(context.Context, string, io.Reader, time.Time) (credential.Record, [32]byte, error) {
	return f.records[0], f.secret, f.err
}
func (f *fakeCredentialCommands) Revoke(context.Context, credential.RecordID) (credential.Record, error) {
	return f.records[0], f.err
}
func (f *fakeCredentialCommands) Purge(context.Context, credential.RecordID) error { return f.err }
func (f *fakeCredentialCommands) List(context.Context) ([]credential.Record, error) {
	return f.records, f.err
}

func TestCredentialHandlerExactSuccessOutput(t *testing.T) {
	id, _ := credential.ParseRecordID("00112233445566778899aabbccddeeff")
	record := credential.Record{ID: id, Device: "laptop", CreatedAt: time.Date(2026, 8, 9, 1, 2, 3, 4, time.UTC), State: credential.Active}
	secret := [32]byte{}
	for i := range secret {
		secret[i] = byte(i)
	}
	for _, test := range []struct {
		name    string
		command cli.Command
		want    string
	}{
		{"add", cli.CredentialAdd, "record_id=00112233445566778899aabbccddeeff\ndevice_identifier=laptop\nsecret=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\n"},
		{"revoke", cli.CredentialRevoke, "record_id=00112233445566778899aabbccddeeff\nstate=revoked\n"},
		{"purge", cli.CredentialPurge, "record_id=00112233445566778899aabbccddeeff\nstate=purged\n"},
		{"list", cli.CredentialList, "record_id\tdevice_identifier\tcreated_at\tstate\n00112233445566778899aabbccddeeff\tlaptop\t2026-08-09T01:02:03.000000004Z\tactive\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			closed := false
			handler := newCredentialHandler(credentialDependencies{
				defaults: func() (string, error) { return "/config.yaml", nil },
				open: func(context.Context, string) (credentialCommands, func(), error) {
					return &fakeCredentialCommands{records: []credential.Record{record}, secret: secret}, func() { closed = true }, nil
				},
				entropy: strings.NewReader(strings.Repeat("x", 48)), now: func() time.Time { return record.CreatedAt },
			})
			result := handler(context.Background(), cli.Invocation{Command: test.command, Device: "laptop", RecordID: id.String()})
			if result.ExitCode != 0 || string(result.Stdout) != test.want || len(result.Stderr) != 0 || string(result.OutputFailed) != "credential error: output_failed\n" || !closed {
				t.Fatalf("result=%+v closed=%v", result, closed)
			}
		})
	}
}

func TestCredentialHandlerMapsClosedOperationalErrors(t *testing.T) {
	id, _ := credential.ParseRecordID("00112233445566778899aabbccddeeff")
	for _, test := range []struct {
		err  error
		want string
	}{
		{credential.ErrDeviceExists, "credential error: already_exists\n"},
		{credential.ErrRecordNotFound, "credential error: not_found\n"},
		{credential.ErrAlreadyRevoked, "credential error: already_revoked\n"},
		{credential.ErrRecordActive, "credential error: not_revoked\n"},
		{credential.ErrRollbackConflict, "credential error: rollback_conflict\n"},
		{credential.ErrGenerationExhausted, "credential error: generation_exhausted\n"},
		{errors.New("private detail"), "credential error: store_unavailable\n"},
	} {
		handler := newCredentialHandler(credentialDependencies{
			defaults: func() (string, error) { return "/config.yaml", nil },
			open: func(context.Context, string) (credentialCommands, func(), error) {
				return &fakeCredentialCommands{records: []credential.Record{{ID: id}}, err: test.err}, func() {}, nil
			},
			entropy: strings.NewReader(strings.Repeat("x", 48)), now: time.Now,
		})
		result := handler(context.Background(), cli.Invocation{Command: cli.CredentialRevoke, RecordID: id.String()})
		if result.ExitCode != 1 || len(result.Stdout) != 0 || string(result.Stderr) != test.want {
			t.Fatalf("error=%v result=%+v", test.err, result)
		}
	}
}
