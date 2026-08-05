package credential

import (
	"context"
	"errors"
	"testing"
)

func TestWatcherReturnsCandidateWithoutRetainingSnapshot(t *testing.T) {
	var want ValidatedSnapshot
	w := NewWatcher(func(context.Context) (ValidatedSnapshot, error) { return want, nil })
	if got := w.Initial(context.Background()); !got.Available || got.Snapshot.Generation() != 0 {
		t.Fatalf("initial = %#v", got)
	}
	w = NewWatcher(func(context.Context) (ValidatedSnapshot, error) { return ValidatedSnapshot{}, errors.New("disk") })
	if got := w.PollOnce(context.Background()); got.Available || got.Err == nil {
		t.Fatalf("failure = %#v", got)
	}
}
