package certmgr

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// ACMEStore persists one bounded state document with owner-only permissions.
type ACMEStore struct{ Path string }

func (s ACMEStore) Load() (ACMEState, error) {
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
	var state ACMEState
	if json.Unmarshal(data, &state) != nil || len(state.AccountKeyPEM) == 0 || len(state.CertificatePEM) == 0 || len(state.PrivateKeyPEM) == 0 {
		return ACMEState{}, ErrACMEStateInvalid
	}
	return state, nil
}

func (s ACMEStore) Save(ctx context.Context, state ACMEState) error {
	if ctx == nil || ctx.Err() != nil || !filepath.IsAbs(s.Path) || len(state.AccountKeyPEM) == 0 || len(state.CertificatePEM) == 0 || len(state.PrivateKeyPEM) == 0 {
		return ErrACMEStateInvalid
	}
	data, err := json.Marshal(state)
	if err != nil || len(data) > maxACMEStateBytes {
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
