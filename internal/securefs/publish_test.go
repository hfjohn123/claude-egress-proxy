//go:build cep_testcontrol

package securefs

import (
	"context"
	"errors"
	"testing"
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
					wantDurable := point == AfterTargetDurability
					if boundary != (CommitBoundary{NamespacePublished: wantPublished, TargetDurable: wantDurable}) {
						t.Fatalf("boundary = %+v", boundary)
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
