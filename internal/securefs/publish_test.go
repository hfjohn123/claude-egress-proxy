//go:build cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestPublishFaultBoundariesAndReservedTemp(t *testing.T) {
	for _, present := range []bool{false, true} {
		for _, point := range []FaultPoint{BeforeTempWrite, AfterTempFlush, AfterPublication, AfterTargetDurability} {
			t.Run(map[bool]string{false: "absent", true: "present"}[present]+"-"+string(rune('a'+point)), func(t *testing.T) {
				r := mutableTestRoot(t)
				policy := mutableFilePolicy(Optional, 64)
				if present {
					// Install the original only through the locked file below; this validates
					// that publication accepts a present, policy-valid target.
					policy.Presence = Optional
				}
				faults := FaultsForTest(func(got FaultPoint) error {
					if got == point {
						return errors.New("injected")
					}
					return nil
				})
				err := r.WithExclusiveLock(context.Background(), "state.lock", mutableFilePolicy(Optional, 256), func(l LockedFile) error {
					if present {
						if _, err := l.Publish(context.Background(), "state", "state.new", []byte("old"), policy, AbsentTarget, NoFaults{}); err != nil {
							return err
						}
					}
					boundary, err := l.Publish(context.Background(), "state", "state.new", []byte("new"), policy, map[bool]PublishMode{false: AbsentTarget, true: PresentTarget}[present], faults)
					if err == nil {
						t.Fatal("Publish fault = nil")
					}
					wantPublished := point == AfterPublication || point == AfterTargetDurability
					wantDurable := point == AfterTargetDurability || (!present && point == AfterPublication)
					if boundary != (CommitBoundary{NamespacePublished: wantPublished, TargetDurable: wantDurable}) {
						t.Fatalf("boundary = %+v", boundary)
					}
					// Every interruption leaves only complete old/new target bytes and
					// the one exact reserved remnant (never a partial target).
					target, targetState, readErr := l.ReadFile("state", FilePolicy{Presence: Required, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
					if wantPublished {
						if readErr != nil || string(target) != "new" || !targetState.Present {
							t.Fatalf("published target = (%q,%+v,%v)", target, targetState, readErr)
						}
					} else if present {
						if readErr != nil || string(target) != "old" {
							t.Fatalf("old target = (%q,%v)", target, readErr)
						}
					} else if _, inspectErr := l.Inspect("state", FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes}); inspectErr != nil {
						t.Fatalf("absent target inspect = %v", inspectErr)
					}
					tempState, tempErr := l.Inspect("state.new", FilePolicy{Presence: Optional, Kind: RegularFile, Access: policy.Access, MaxBytes: policy.MaxBytes})
					if tempErr != nil {
						t.Fatal(tempErr)
					}
					wantTemp := point == BeforeTempWrite || point == AfterTempFlush
					if tempState.Present != wantTemp {
						t.Fatalf("temp present = %v, want %v", tempState.Present, wantTemp)
					}
					if tempState.Present && point == AfterTempFlush && tempState.Size != 3 {
						t.Fatalf("flushed temp size = %d", tempState.Size)
					}
					return nil
				})
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestConcurrentAbsentPublishersYieldOneCompleteWinner(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 32)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, data := range [][]byte{[]byte("one"), []byte("two")} {
		wg.Add(1)
		go func(data []byte) {
			defer wg.Done()
			results <- r.WithExclusiveLock(context.Background(), "writers.lock", mutableFilePolicy(Optional, 32), func(l LockedFile) error {
				_, err := l.Publish(context.Background(), "state", "state.new", data, p, AbsentTarget, NoFaults{})
				return err
			})
		}(data)
	}
	wg.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("publisher error = %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("winners = %d, want 1", wins)
	}
	data, _, err := r.ReadFile("state", FilePolicy{Presence: Required, Kind: RegularFile, Access: p.Access, MaxBytes: p.MaxBytes})
	if err != nil || (string(data) != "one" && string(data) != "two") {
		t.Fatalf("final bytes = %q, %v", data, err)
	}
}

func TestMutableCloseWaitsForLockCallback(t *testing.T) {
	r := mutableTestRoot(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	lockedDone := make(chan error, 1)
	go func() {
		lockedDone <- r.WithExclusiveLock(context.Background(), "close.lock", mutableFilePolicy(Optional, 8), func(LockedFile) error { close(entered); <-release; return nil })
	}()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- r.Close() }()
	select {
	case err := <-closed:
		t.Fatalf("Close returned during callback: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-lockedDone; err != nil {
		t.Fatal(err)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := r.WithExclusiveLock(context.Background(), "later.lock", mutableFilePolicy(Optional, 8), func(LockedFile) error { return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-close lock = %v", err)
	}
}

func TestPublishRejectsNonReservedNamesAndOversizeData(t *testing.T) {
	r := mutableTestRoot(t)
	p := mutableFilePolicy(Optional, 2)
	err := r.WithExclusiveLock(context.Background(), "policy.lock", mutableFilePolicy(Optional, 8), func(l LockedFile) error {
		for _, pair := range [][2]string{{"a", "b.new"}, {"a", "a.tmp"}, {"a/b", "a/b.new"}} {
			if _, err := l.Publish(context.Background(), pair[0], pair[1], []byte("x"), p, AbsentTarget, NoFaults{}); !errors.Is(err, ErrUnsafePath) {
				t.Fatalf("names %q/%q = %v", pair[0], pair[1], err)
			}
		}
		if _, err := l.Publish(context.Background(), "a", "a.new", []byte("too"), p, AbsentTarget, NoFaults{}); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("oversize = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLockedFileInvalidatesAfterCallbackGoexit(t *testing.T) {
	r := mutableTestRoot(t)
	var held LockedFile
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = r.WithExclusiveLock(context.Background(), "goexit.lock", mutableFilePolicy(Optional, 16), func(l LockedFile) error {
			held = l
			runtime.Goexit()
			return nil
		})
	}()
	<-done
	if held == nil {
		t.Fatal("callback did not receive locked file")
	}
	if err := held.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-Goexit Sync = %v, want ErrClosed", err)
	}
}

func TestLockedFileClosesAfterCallbackAndBoundsOffsets(t *testing.T) {
	r := mutableTestRoot(t)
	var held LockedFile
	err := r.WithExclusiveLock(context.Background(), "state.lock", mutableFilePolicy(Optional, 3), func(l LockedFile) error {
		held = l
		if _, err := l.WriteAt([]byte("abc"), 0); err != nil {
			return err
		}
		if _, err := l.WriteAt([]byte("d"), 3); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("overflow write = %v", err)
		}
		if _, err := l.ReadAt(make([]byte, 1), -1); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("negative read = %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Sync(); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-callback Sync = %v", err)
	}
}
