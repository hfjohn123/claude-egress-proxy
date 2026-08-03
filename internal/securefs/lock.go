package securefs

import (
	"context"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

type LockedFile interface {
	Identity() Identity
	RecheckIdentity() error
	Size() (int64, error)
	ReadAt([]byte, int64) (int, error)
	WriteAt([]byte, int64) (int, error)
	Truncate(int64) error
	Sync() error
	Inspect(string, FilePolicy) (FileState, error)
	ReadFile(string, FilePolicy) ([]byte, FileState, error)
	CleanupReservedTemp(context.Context, string, string, FilePolicy) error
	Publish(context.Context, string, string, []byte, FilePolicy, PublishMode, Faults) (CommitBoundary, error)
}

func validMutableRootPolicy(policy RootPolicy) bool {
	return policy.Access.kind == permissionLinuxExact || policy.Access.kind == permissionWindowsRestricted
}
func validLockPolicy(policy FilePolicy) bool {
	return validFilePolicy(policy) && policy.Presence == Optional && policy.Kind == RegularFile && policy.Access.kind != permissionInvalid
}
func validReservedNames(target, temp string) bool {
	return validLeaf(target) && validLeaf(temp) && target != temp && temp == target+".new"
}

func waitForLockRetry(ctx context.Context, delay time.Duration) error {
	timer := timebase.Real{}.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C():
		return nil
	}
}
