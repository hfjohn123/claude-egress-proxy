package config

import (
	"errors"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

type Draft struct {
	config   Config
	document []byte
	identity securefs.Identity
}

func (d Draft) Config() Config              { return cloneConfig(d.config) }
func (d Draft) Document() []byte            { return append([]byte(nil), d.document...) }
func (d Draft) Identity() securefs.Identity { return d.identity }

func ReadDraft(path string) (Draft, error) {
	return ReadDraftExcluding(path, securefs.Identity{})
}

func ReadDraftExcluding(path string, excludedAncestor securefs.Identity) (Draft, error) {
	access := securefs.IdentityOnlyPermissions()
	filePolicy := securefs.FilePolicy{
		Presence: securefs.Required,
		Kind:     securefs.RegularFile,
		Access:   access,
		MaxBytes: int64(contract.V1().ConfigBytes),
	}
	parent, name, state, err := securefs.ValidateOutput(path, excludedAncestor, securefs.RootPolicy{Access: access}, filePolicy)
	if err != nil {
		return Draft{}, pathFailure(PathStageDraftFile, mapDraftRead(err))
	}
	defer parent.Close()

	document, readState, err := parent.ReadFile(name, filePolicy)
	if err != nil {
		return Draft{}, pathFailure(PathStageDraftFile, mapDraftRead(err))
	}
	if readState.Identity != state.Identity {
		return Draft{}, pathFailure(PathStageDraftFile, typed(ErrPathSecurity, contract.D004))
	}
	cfg, err := Decode(document)
	if err != nil {
		if errors.Is(err, ErrValue) {
			return Draft{}, typed(ErrValue, contract.D003)
		}
		return Draft{}, typed(ErrSyntax, contract.D002)
	}
	return Draft{config: cfg, document: append([]byte(nil), document...), identity: state.Identity}, nil
}

func mapDraftRead(err error) error {
	if errors.Is(err, securefs.ErrUnsupportedInspection) {
		return typed(ErrPlatform, contract.D010)
	}
	return typed(ErrPathSecurity, contract.D004)
}
