//go:build windows && cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

var mutablePathForTest sync.Map

func mutableTestRoot(t *testing.T) MutableRoot {
	t.Helper()
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_TRAVERSE|windows.FILE_WRITE_ATTRIBUTES|0x0002|0x0004|0x0040)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	parent, err := OpenCreateCapableRoot(base, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatalf("OpenCreateCapableRoot: %v", err)
	}
	created, err := CreateRoot(parent, "restricted", RootPolicy{Access: policy})
	if err != nil {
		t.Fatalf("CreateRoot: %v", err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	if err := parent.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := OpenMutableRoot(filepath.Join(base, "restricted"), RootPolicy{Access: policy})
	if err != nil {
		t.Fatalf("OpenMutableRoot: %v", err)
	}
	t.Cleanup(func() { _ = r.Close() })
	mutablePathForTest.Store(r, filepath.Join(base, "restricted"))
	return r
}

func TestReplaceRetryUsesExactFiveAttemptSchedule(t *testing.T) {
	var attempts []int
	var waits []time.Duration
	faults := FaultsForTestWithRetry(nil, func(run func() error) error {
		attempts = append(attempts, len(attempts))
		return windows.ERROR_SHARING_VIOLATION
	}, func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil })
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	started := time.Now()
	err := r.WithExclusiveLock(context.Background(), "retry.lock", mutableFilePolicy(Optional, 32), func(l LockedFile) error {
		if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{}); err != nil {
			return err
		}
		boundary, err := l.Publish(context.Background(), "state", "state.new", []byte("new"), p, PresentTarget, faults)
		if err == nil || boundary != (CommitBoundary{}) {
			t.Fatalf("persistent sharing = (%+v, %v)", boundary, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 5 {
		t.Fatalf("replace attempts = %d, want 5", len(attempts))
	}
	if elapsed := time.Since(started); elapsed > 200*time.Millisecond {
		t.Fatalf("persistent virtual retry elapsed = %v, want <= 200ms", elapsed)
	}
	if !reflect.DeepEqual(waits, []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}) {
		t.Fatalf("waits=%v", waits)
	}
	if !errors.Is(faults.hit(BeforeTempWrite), nil) {
		t.Fatal("unexpected fault")
	}
}

func TestReplacePersistentSharingUsesRealRetryTimersWithinContract(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	calls := 0
	f := FaultsForTestWithReplace(nil, func(func() error) error {
		calls++
		return windows.ERROR_SHARING_VIOLATION
	})
	started := time.Now()
	err := r.WithExclusiveLock(context.Background(), "real-retry.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{}); err != nil {
			return err
		}
		boundary, err := l.Publish(context.Background(), "state", "state.new", []byte("new"), p, PresentTarget, f)
		if err == nil || boundary != (CommitBoundary{}) {
			t.Fatalf("persistent real retry = %+v,%v", boundary, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 5 {
		t.Fatalf("real retry calls = %d, want 5", calls)
	}
	if elapsed := time.Since(started); elapsed < 140*time.Millisecond || elapsed > 200*time.Millisecond {
		t.Fatalf("real retry elapsed = %v, want 150ms retry schedule within 200ms contract", elapsed)
	}
}

func TestReplaceRetrySucceedsAfterEachRetryDepth(t *testing.T) {
	for depth := 1; depth <= 4; depth++ {
		t.Run("depth-"+string(rune('0'+depth)), func(t *testing.T) {
			r := mutableTestRoot(t)
			p := mutableFilePolicy(Optional, 32)
			attempts := 0
			var waits []time.Duration
			f := FaultsForTestWithRetry(nil, func(run func() error) error {
				attempts++
				if attempts <= depth {
					return windows.ERROR_SHARING_VIOLATION
				}
				return run()
			}, func(_ context.Context, delay time.Duration) error {
				waits = append(waits, delay)
				return nil
			})
			err := r.WithExclusiveLock(context.Background(), "depth.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
				if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{}); err != nil {
					return err
				}
				boundary, err := l.Publish(context.Background(), "state", "state.new", []byte("new"), p, PresentTarget, f)
				if err != nil || boundary != (CommitBoundary{NamespacePublished: true, TargetDurable: true}) {
					t.Fatalf("depth %d result = %+v,%v", depth, boundary, err)
				}
				got, _, err := l.ReadFile("state", FilePolicy{Presence: Required, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes})
				if err != nil || string(got) != "new" {
					t.Fatalf("depth %d target = %q,%v", depth, got, err)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if attempts != depth+1 {
				t.Fatalf("depth %d attempts = %d, want %d", depth, attempts, depth+1)
			}
			wantWaits := []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}[:depth]
			if !reflect.DeepEqual(waits, wantWaits) {
				t.Fatalf("depth %d waits = %v, want %v", depth, waits, wantWaits)
			}
			var accumulated time.Duration
			for _, wait := range waits {
				accumulated += wait
			}
			wantAccumulated := []time.Duration{10 * time.Millisecond, 30 * time.Millisecond, 70 * time.Millisecond, 150 * time.Millisecond}[depth-1]
			if accumulated != wantAccumulated {
				t.Fatalf("depth %d accumulated waits = %v, want %v", depth, accumulated, wantAccumulated)
			}
		})
	}
}

func TestAfterPublicationNeverRetriesReplace(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	calls := 0
	f := FaultsForTestWithReplace(func(point FaultPoint) error {
		if point == AfterPublication {
			return errors.New("stop")
		}
		return nil
	}, func(run func() error) error { calls++; return run() })
	err := r.WithExclusiveLock(context.Background(), "once.lock", mutableFilePolicy(Optional, 32), func(l LockedFile) error {
		if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{}); err != nil {
			return err
		}
		b, err := l.Publish(context.Background(), "state", "state.new", []byte("new"), p, PresentTarget, f)
		if err == nil || !b.NamespacePublished {
			t.Fatalf("after publication = %+v,%v", b, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("replace calls=%d,want 1", calls)
	}
}

func TestReplaceNonSharingErrorDoesNotRetry(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	calls := 0
	waits := 0
	f := FaultsForTestWithRetry(nil, func(func() error) error { calls++; return windows.ERROR_ACCESS_DENIED }, func(context.Context, time.Duration) error { waits++; return nil })
	err := r.WithExclusiveLock(context.Background(), "nonsharing.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		_, e := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{})
		if e != nil {
			return e
		}
		boundary, e := l.Publish(context.Background(), "state", "state.new", []byte("new"), p, PresentTarget, f)
		if !errors.Is(e, ErrUnsafePath) || boundary != (CommitBoundary{}) {
			t.Fatalf("non-sharing result = %+v,%v", boundary, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	if waits != 0 {
		t.Fatalf("waits=%d", waits)
	}
}

func TestReplaceCancellationDuringRealRetryWaitStopsBeforePublication(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	firstAttempt := make(chan struct{})
	f := FaultsForTestWithReplace(nil, func(func() error) error {
		calls++
		if calls == 1 {
			close(firstAttempt)
		}
		return windows.ERROR_SHARING_VIOLATION
	})
	go func() {
		<-firstAttempt
		time.Sleep(time.Millisecond)
		cancel()
	}()
	err := r.WithExclusiveLock(context.Background(), "cancel.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		if _, e := l.Publish(context.Background(), "state", "state.new", []byte("old"), p, AbsentTarget, NoFaults{}); e != nil {
			return e
		}
		b, e := l.Publish(ctx, "state", "state.new", []byte("new"), p, PresentTarget, f)
		if !errors.Is(e, context.Canceled) || b != (CommitBoundary{}) {
			t.Fatalf("cancel=%+v,%v", b, e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestCallbackInvalidationWaitsForAdmittedMethod(t *testing.T) {
	r := mutableTestRoot(t)
	started := make(chan struct{})
	release := make(chan struct{})
	returned := make(chan error, 1)
	go func() {
		returned <- r.WithExclusiveLock(context.Background(), "gate.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
			x := l.(*windowsLockedFile)
			if err := x.gate.begin(); err != nil {
				return err
			}
			go func() { close(started); <-release; x.gate.end() }()
			<-started
			return nil
		})
	}()
	<-started
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case <-returned:
		t.Fatal("callback returned before admitted method")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-returned; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestCallbackInvalidationWaitsForRealPublicMethodAfterGateAdmission(t *testing.T) {
	r := mutableTestRoot(t)
	admitted := make(chan struct{})
	release := make(chan struct{})
	callbackReturned := make(chan struct{})
	methodDone := make(chan error, 1)
	lockedDone := make(chan error, 1)
	go func() {
		lockedDone <- r.WithExclusiveLock(context.Background(), "public-gate.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
			if err := BlockLockedMethodAfterAdmissionForTest(r, l, admitted, release); err != nil {
				return err
			}
			go func() { methodDone <- l.Sync() }()
			select {
			case <-admitted:
				close(callbackReturned)
				return nil
			case <-time.After(time.Second):
				return ErrUnsafePath
			}
		})
	}()
	<-callbackReturned
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-lockedDone:
		t.Fatalf("lock callback returned while Sync was admitted: %v", err)
	case err := <-closed:
		t.Fatalf("Close returned while Sync was admitted: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-methodDone; err != nil {
		t.Fatalf("admitted Sync = %v", err)
	}
	if err := <-lockedDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestCleanupRejectsWrongKindAndPreservesSimilarNames(t *testing.T) {
	r := mutableTestRoot(t)
	raw, _ := mutablePathForTest.Load(r)
	path := raw.(string)
	if err := os.Mkdir(filepath.Join(path, "state.new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "state.new.keep"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := mutableFilePolicy(Optional, 32)
	err := r.WithExclusiveLock(context.Background(), "cleanup.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		e := l.CleanupReservedTemp(context.Background(), "state", "state.new", p)
		if !errors.Is(e, ErrUnsafePath) {
			t.Fatalf("wrong-kind cleanup=%v", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, e := os.ReadFile(filepath.Join(path, "state.new.keep")); e != nil || string(got) != "keep" {
		t.Fatalf("similar preserved=%q,%v", got, e)
	}
}

func TestCleanupDeletesOnlyExactTempAndRejectsReparseThroughProductionFlow(t *testing.T) {
	r := mutableTestRoot(t)
	raw, _ := mutablePathForTest.Load(r)
	path := raw.(string)
	for _, name := range []string{"unrelated", "state.new.keep", "prefixstate.new", "state.newer"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	wrongPolicy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.WRITE_DAC)
	if err != nil {
		t.Fatal(err)
	}
	p := mutableFilePolicy(Optional, 32)
	err = r.WithExclusiveLock(context.Background(), "cleanup-policy.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		_, e := l.Publish(context.Background(), "state", "state.new", nil, p, AbsentTarget, FaultsForTest(func(point FaultPoint) error {
			if point == BeforeTempWrite {
				return errors.New("leave exact temp")
			}
			return nil
		}))
		if e == nil {
			t.Fatal("pre-write fault did not leave temp")
		}
		if e := l.CleanupReservedTemp(context.Background(), "state", "state.new", FilePolicy{Presence: Optional, Kind: RegularFile, Access: wrongPolicy, MaxBytes: 32}); e == nil {
			t.Fatal("wrong-policy reserved temp accepted")
		}
		if e := l.CleanupReservedTemp(context.Background(), "state", "state.new", p); e != nil {
			t.Fatalf("exact cleanup = %v", e)
		}
		if state, e := l.Inspect("state.new", FilePolicy{Presence: Optional, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes}); e != nil || state.Present {
			t.Fatalf("exact temp after cleanup = %+v,%v", state, e)
		}
		if _, e := l.Publish(context.Background(), "reparse", "reparse.new", nil, p, AbsentTarget, FaultsForTest(func(point FaultPoint) error {
			if point == BeforeTempWrite {
				return errors.New("leave reparse temp")
			}
			return nil
		})); e == nil {
			t.Fatal("reparse pre-write failure = nil")
		}
		if e := MarkInspectReparseForTest(r, "reparse.new"); e != nil {
			return e
		}
		if e := l.CleanupReservedTemp(context.Background(), "reparse", "reparse.new", p); !errors.Is(e, ErrUnsafePath) {
			t.Fatalf("reparse cleanup = %v", e)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unrelated", "state.new.keep", "prefixstate.new", "state.newer"} {
		if got, err := os.ReadFile(filepath.Join(path, name)); err != nil || string(got) != name {
			t.Fatalf("similar name %q = %q,%v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(path, "reparse.new")); err != nil {
		t.Fatalf("reparse temp was not preserved after rejection: %v", err)
	}
}

func TestLockedFileRejectsLockNameReplacement(t *testing.T) {
	r := mutableTestRoot(t)
	raw, _ := mutablePathForTest.Load(r)
	path := raw.(string)
	err := r.WithExclusiveLock(context.Background(), "replace.lock", mutableFilePolicy(Optional, 16), func(l LockedFile) error {
		if err := os.Rename(filepath.Join(path, "replace.lock"), filepath.Join(path, "replace.lock.old")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(path, "replace.lock"), []byte("replacement"), 0o600); err != nil {
			return err
		}
		if err := l.RecheckIdentity(); !errors.Is(err, ErrIdentityChanged) {
			t.Fatalf("replacement recheck = %v", err)
		}
		if err := l.Sync(); !errors.Is(err, ErrIdentityChanged) {
			t.Fatalf("replacement sync = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReplaceFileKeepsShareAllReaderOnOldBytes(t *testing.T) {
	r := mutableTestRoot(t)
	raw, _ := mutablePathForTest.Load(r)
	path := raw.(string)
	p := mutableFilePolicy(Optional, 32)
	var reader windows.Handle
	err := r.WithExclusiveLock(context.Background(), "reader.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old bytes"), p, AbsentTarget, NoFaults{}); err != nil {
			return err
		}
		name, err := windows.UTF16PtrFromString(filepath.Join(path, "state"))
		if err != nil {
			return err
		}
		reader, err = windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			return err
		}
		if _, err := l.Publish(context.Background(), "state", "state.new", []byte("new bytes"), p, PresentTarget, NoFaults{}); err != nil {
			return err
		}
		return nil
	})
	if reader != 0 {
		defer windows.CloseHandle(reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, len("old bytes"))
	var n uint32
	if err := windows.ReadFile(reader, buffer, &n, nil); err != nil || string(buffer[:n]) != "old bytes" {
		t.Fatalf("old reader bytes = %q,%v", buffer[:n], err)
	}
	if got, err := os.ReadFile(filepath.Join(path, "state")); err != nil || string(got) != "new bytes" {
		t.Fatalf("new open bytes = %q,%v", got, err)
	}
}

// TestMutableRootPinsWindowsNamespace catches path-based publication escaping
// through a renamed selected root or a renamed higher ancestor.
func TestMutableRootPinsWindowsNamespace(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	rootPolicy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_TRAVERSE|windows.FILE_WRITE_ATTRIBUTES|0x0002|0x0004|0x0040)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := OpenCreateCapableRoot(ancestor, RootPolicy{Access: IdentityOnlyPermissions()})
	if err != nil {
		t.Fatal(err)
	}
	created, err := CreateRoot(parent, "state", RootPolicy{Access: rootPolicy})
	if err != nil {
		t.Fatal(err)
	}
	_ = created.Close()
	_ = parent.Close()
	path := filepath.Join(ancestor, "state")
	r, err := OpenMutableRoot(path, RootPolicy{Access: rootPolicy})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if err := os.Rename(path, filepath.Join(ancestor, "moved-state")); err == nil {
		t.Fatal("selected-root rename succeeded while mutable root pinned")
	}
	if err := os.Rename(ancestor, filepath.Join(base, "moved-ancestor")); err == nil {
		t.Fatal("ancestor rename succeeded while mutable root pinned")
	}
}

// TestFailedMutableOpenReleasesTraversalPins catches an error path retaining a
// no-delete-share pin after a later path component is rejected.
func TestFailedMutableOpenReleasesTraversalPins(t *testing.T) {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_LIST_DIRECTORY)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := filepath.Join(ancestor, "not-a-directory")
	if err := os.WriteFile(bad, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMutableRoot(bad, RootPolicy{Access: policy}); err == nil {
		t.Fatal("mutable open of regular file succeeded")
	}
	if err := os.Rename(ancestor, filepath.Join(base, "renamed")); err != nil {
		t.Fatalf("failed mutable open leaked ancestor pin: %v", err)
	}
}
func mutableFilePolicy(p Presence, max int64) FilePolicy {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		panic(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		panic(err)
	}
	policy, err := WindowsRestrictedPermissions([]string{user.User.Sid.String()}, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE|windows.DELETE)
	if err != nil {
		panic(err)
	}
	return FilePolicy{Presence: p, Kind: RegularFile, Access: policy, MaxBytes: max}
}
