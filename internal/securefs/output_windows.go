//go:build windows

package securefs

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformPublishOutput(ctx context.Context, op platformRoot, rootPolicy RootPolicy, target string, data []byte, policy FilePolicy) (CommitBoundary, error) {
	r, ok := op.(*windowsRoot)
	if !ok || r.recheck() != nil {
		return CommitBoundary{}, ErrUnsafePath
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
			_ = winDeleteOwnedTemp(r, temp, id, policy)
		}
	}()
	var wrote uint32
	if err := windows.WriteFile(h, data, &wrote, nil); err != nil || int(wrote) != len(data) {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := windows.FlushFileBuffers(h); err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	if err := windows.CloseHandle(h); err != nil {
		return CommitBoundary{}, ErrUnsafePath
	}
	h = 0
	if err := ctx.Err(); err != nil {
		return CommitBoundary{}, err
	}
	tempPath, targetPath := filepath.Join(r.path, temp), filepath.Join(r.path, target)
	a, _ := windows.UTF16PtrFromString(tempPath)
	b, _ := windows.UTF16PtrFromString(targetPath)
	if state.Present {
		proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("ReplaceFileW")
		result, _, _ := proc.Call(uintptr(unsafe.Pointer(b)), uintptr(unsafe.Pointer(a)), 0, 0, 0, 0)
		if result == 0 {
			return CommitBoundary{}, ErrUnsafePath
		}
	} else if err := windows.MoveFileEx(a, b, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return CommitBoundary{}, ErrAlreadyExists
		}
		return CommitBoundary{}, ErrUnsafePath
	}
	owned = false
	if err := ctx.Err(); err != nil {
		return CommitBoundary{NamespacePublished: true}, err
	}
	targetHandle, err := winOpenState(r.fd, target, false, policy)
	if err != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
	}
	err = windows.FlushFileBuffers(targetHandle)
	_ = windows.CloseHandle(targetHandle)
	if err != nil {
		return CommitBoundary{NamespacePublished: true}, ErrUnsafePath
	}
	return CommitBoundary{NamespacePublished: true, TargetDurable: true}, nil
}

func winDeleteOwnedTemp(r *windowsRoot, name string, id Identity, policy FilePolicy) error {
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
