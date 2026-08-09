//go:build windows

package securefs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/sys/windows"
)

func platformPublishOutput(ctx context.Context, op platformRoot, rootPolicy RootPolicy, target string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	r, ok := op.(*windowsRoot)
	if !ok {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := winOutputRoot(r, rootPolicy); err != nil {
		return CommitBoundary{}, err
	}
	if err := ctx.Err(); err != nil {
		return CommitBoundary{}, err
	}
	state, err := r.inspect(target, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if err != nil {
		return CommitBoundary{}, err
	}
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	temp := fmt.Sprintf(".%s.%x.tmp", target, token)
	if winOutputRoot(r, rootPolicy) != nil {
		return CommitBoundary{}, ErrIdentityChanged
	}
	h, err := winOpenState(r.fd, temp, true, policy)
	if err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	info, err := winInfo(h)
	id, idErr := winIdentity(h, info)
	if err != nil || idErr != nil || winCheck(h, info, RegularFile, policy.Access) != nil {
		_ = windows.CloseHandle(h)
		return CommitBoundary{}, ErrUnsafePath
	}
	owned := true
	defer func() {
		if h != 0 {
			_ = windows.CloseHandle(h)
		}
		if owned {
			_ = winDeleteOwnedTemp(r, rootPolicy, temp, id, policy)
		}
	}()
	var wrote uint32
	if err := windows.WriteFile(h, data, &wrote, nil); err != nil || int(wrote) != len(data) {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := ctx.Err(); err != nil {
		return CommitBoundary{}, err
	}
	if winOutputRoot(r, rootPolicy) != nil || !winTempCurrent(r, temp, id, policy) {
		return CommitBoundary{}, ErrIdentityChanged
	}
	now, inspectErr := r.inspect(target, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if inspectErr != nil || now.Present != state.Present || now.Present && now.Identity != state.Identity {
		return CommitBoundary{}, ErrIdentityChanged
	}
	// The commit is handle-based: the retained, validated temp handle is moved
	// into the directory namespace, never whichever object happens to occupy the
	// temp pathname. The final path checks are deliberately adjacent to it.
	if err := winOutputCommitHook(ctx); err != nil || !winTempCurrent(r, temp, id, policy) {
		return CommitBoundary{}, ErrIdentityChanged
	}
	now, inspectErr = r.inspect(target, FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
	if inspectErr != nil || now.Present != state.Present || now.Present && now.Identity != state.Identity {
		return CommitBoundary{}, ErrIdentityChanged
	}
	if err := winRenameHandle(h, r.fd, target, state.Present); err != nil {
		if errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
			return CommitBoundary{}, ErrAlreadyExists
		}
		return CommitBoundary{}, ErrUnsafePath
	}
	owned = false
	if err := ctx.Err(); err != nil {
		return CommitBoundary{NamespacePublished: true}, err
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
	}
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}

func winOutputRoot(r *windowsRoot, policy RootPolicy) error {
	if r.recheck() != nil {
		return ErrIdentityChanged
	}
	info, err := winInfo(r.fd)
	if err != nil {
		return ErrUnsafePath
	}
	id, err := winIdentity(r.fd, info)
	if err != nil || id != r.id {
		return ErrIdentityChanged
	}
	return winCheck(r.fd, info, Directory, policy.Access)
}
func winTempCurrent(r *windowsRoot, name string, id Identity, policy FilePolicy) bool {
	h, err := winOpenState(r.fd, name, false, policy)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	current, idErr := winIdentity(h, info)
	return err == nil && idErr == nil && current == id && winCheck(h, info, RegularFile, policy.Access) == nil
}

func winDeleteOwnedTemp(r *windowsRoot, rootPolicy RootPolicy, name string, id Identity, policy FilePolicy) error {
	if winOutputRoot(r, rootPolicy) != nil {
		return ErrIdentityChanged
	}
	h, err := winOpenState(r.fd, name, false, policy)
	if err != nil {
		return ErrIdentityChanged
	}
	defer windows.CloseHandle(h)
	info, err := winInfo(h)
	current, idErr := winIdentity(h, info)
	if err != nil || idErr != nil || current != id || winCheck(h, info, RegularFile, policy.Access) != nil {
		return ErrIdentityChanged
	}
	return winMarkDelete(h)
}
