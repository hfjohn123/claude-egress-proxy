package securefs

import (
	"context"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

// lockedGate prevents a callback-spawned goroutine from issuing a syscall on a
// lock handle after the callback has returned and the OS is free to reuse it.
type lockedGate struct {
	mu                 sync.Mutex
	cond               *sync.Cond
	closing            bool
	active             int
	afterGateAdmission func()
}

func newLockedGate() *lockedGate { g := &lockedGate{}; g.cond = sync.NewCond(&g.mu); return g }
func (g *lockedGate) begin() error {
	g.mu.Lock()
	if g.closing {
		g.mu.Unlock()
		return ErrClosed
	}
	g.active++
	hook := g.afterGateAdmission
	g.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}
func (g *lockedGate) end() {
	g.mu.Lock()
	g.active--
	if g.active == 0 {
		g.cond.Broadcast()
	}
	g.mu.Unlock()
}
func (g *lockedGate) close() {
	g.mu.Lock()
	g.closing = true
	for g.active != 0 {
		g.cond.Wait()
	}
	g.mu.Unlock()
}

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
func validMutableEntryPolicy(policy FilePolicy) bool {
	return validFilePolicy(policy) && policy.Kind == RegularFile &&
		(policy.Access.kind == permissionLinuxExact || policy.Access.kind == permissionWindowsRestricted)
}
func validLockPolicy(policy FilePolicy) bool {
	return validMutableEntryPolicy(policy) && policy.Presence == Optional
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
