package certmgr

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

const maxACMEStateBytes = 1 << 20

var (
	ErrACMEStateAbsent  = errors.New("acme state absent")
	ErrACMEStateInvalid = errors.New("acme state invalid")
)

// ACMEState is the restricted, independently persisted ACME account and
// serving material. It is deliberately separate from credential state.
type ACMEState struct {
	AccountKeyPEM  []byte `json:"account_key_pem"`
	CertificatePEM []byte `json:"certificate_pem"`
	PrivateKeyPEM  []byte `json:"private_key_pem"`
}

// ACMEStore persists one bounded state document. Production callers provide a
// pinned securefs root; Path remains only for isolated filesystem tests.
type ACMEStore struct {
	Path    string
	Root    securefs.ReadRoot
	Mutable securefs.MutableRoot
	Name    string
	Policy  securefs.FilePolicy
}

func (s ACMEStore) Valid() bool {
	return s.secure() || filepath.IsAbs(s.Path)
}

func (s ACMEStore) secure() bool {
	return s.Root != nil && s.Name != "" && filepath.Base(s.Name) == s.Name && s.Policy.Kind == securefs.RegularFile && s.Policy.MaxBytes == maxACMEStateBytes
}

func (s ACMEStore) Load() (ACMEState, error) {
	if s.secure() {
		if err := s.Root.RecheckIdentity(); err != nil {
			return ACMEState{}, ErrACMEStateInvalid
		}
		optional := s.Policy
		optional.Presence = securefs.Optional
		state, err := s.Root.Inspect(s.Name, optional)
		if err != nil {
			return ACMEState{}, ErrACMEStateInvalid
		}
		if !state.Present {
			return ACMEState{}, ErrACMEStateAbsent
		}
		required := s.Policy
		required.Presence = securefs.Required
		data, readState, err := s.Root.ReadFile(s.Name, required)
		if err != nil || readState.Identity != state.Identity || int64(len(data)) != state.Size {
			return ACMEState{}, ErrACMEStateInvalid
		}
		return decodeACMEState(data)
	}
	if !filepath.IsAbs(s.Path) {
		return ACMEState{}, ErrACMEStateInvalid
	}
	info, err := os.Lstat(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return ACMEState{}, ErrACMEStateAbsent
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0 || info.Size() > maxACMEStateBytes {
		return ACMEState{}, ErrACMEStateInvalid
	}
	data, err := os.ReadFile(s.Path)
	if err != nil || len(data) > maxACMEStateBytes {
		return ACMEState{}, ErrACMEStateInvalid
	}
	return decodeACMEState(data)
}

func (s ACMEStore) Save(ctx context.Context, state ACMEState) error {
	if ctx == nil || ctx.Err() != nil || len(state.AccountKeyPEM) == 0 || len(state.CertificatePEM) == 0 || len(state.PrivateKeyPEM) == 0 {
		return ErrACMEStateInvalid
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxACMEStateBytes {
		return ErrACMEStateInvalid
	}
	if s.secure() {
		if s.Mutable == nil {
			return ErrACMEStateInvalid
		}
		policy := s.Policy
		policy.Presence = securefs.Optional
		boundary, err := s.Mutable.PublishOutput(ctx, s.Name, data, policy)
		if err != nil || !boundary.NamespacePublished || !boundary.TargetDurable {
			return ErrACMEStateInvalid
		}
		return nil
	}
	if !filepath.IsAbs(s.Path) {
		return ErrACMEStateInvalid
	}
	parent := filepath.Dir(s.Path)
	if info, err := os.Stat(parent); err != nil || !info.IsDir() {
		return ErrACMEStateInvalid
	}
	if info, err := os.Lstat(s.Path); err == nil && (!info.Mode().IsRegular() || info.Mode()&fs.ModeSymlink != 0) {
		return ErrACMEStateInvalid
	}
	temp, err := os.CreateTemp(parent, ".acme-")
	if err != nil {
		return ErrACMEStateInvalid
	}
	tempName := temp.Name()
	defer os.Remove(tempName)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return ErrACMEStateInvalid
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return ErrACMEStateInvalid
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return ErrACMEStateInvalid
	}
	if err := temp.Close(); err != nil {
		return ErrACMEStateInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempName, s.Path); err != nil {
		return ErrACMEStateInvalid
	}
	return nil
}

func (s ACMEStore) Close() error {
	if s.Mutable != nil {
		return s.Mutable.Close()
	}
	return nil
}

func decodeACMEState(data []byte) (ACMEState, error) {
	if len(data) == 0 || len(data) > maxACMEStateBytes {
		return ACMEState{}, ErrACMEStateInvalid
	}
	var state ACMEState
	if json.Unmarshal(data, &state) != nil || len(state.AccountKeyPEM) == 0 || len(state.CertificatePEM) == 0 || len(state.PrivateKeyPEM) == 0 {
		return ACMEState{}, ErrACMEStateInvalid
	}
	return state, nil
}
