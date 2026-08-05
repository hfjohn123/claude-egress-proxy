package credential

import (
	"context"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestValidateOnlyRejectsPresentStoreWithoutCompleteJournal(t *testing.T) {
	var instance [16]byte
	snapshot, err := NewValidatedSnapshot(instance, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	store, err := EncodeCanonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, MaxBytes: 1 << 20}
	for _, journal := range [][]byte{nil, make([]byte, checkpointJournalBytes-1)} {
		r := fakeStoreReader{files: map[string][]byte{storeName: store}}
		if journal != nil {
			r.files[lockName] = journal
		}
		beforeStore := append([]byte(nil), r.files[storeName]...)
		beforeJournal := append([]byte(nil), r.files[lockName]...)
		got, err := inspectFiles(r, instance, policy)
		if err != nil {
			t.Fatal(err)
		}
		if got.State != StoreConflict {
			t.Fatalf("state = %v, want conflict", got.State)
		}
		inspector := &Inspector{root: r, instance: instance, policy: policy}
		if got, err := inspector.Inspect(context.Background(), ValidateOnly); err != nil || got.State != StoreConflict {
			t.Fatalf("validate-only = %#v, %v", got, err)
		}
		if string(r.files[storeName]) != string(beforeStore) || string(r.files[lockName]) != string(beforeJournal) {
			t.Fatal("validate-only mutated store members")
		}
	}
}

type fakeStoreReader struct{ files map[string][]byte }

func (fakeStoreReader) Identity() securefs.Identity { return securefs.Identity{} }
func (fakeStoreReader) RecheckIdentity() error      { return nil }

func (r fakeStoreReader) Inspect(name string, policy securefs.FilePolicy) (securefs.FileState, error) {
	b, ok := r.files[name]
	if !ok {
		if policy.Presence == securefs.Required {
			return securefs.FileState{}, securefs.ErrNotFound
		}
		return securefs.FileState{}, nil
	}
	return securefs.FileState{Present: true, Kind: securefs.RegularFile, Size: int64(len(b))}, nil
}
func (r fakeStoreReader) ReadFile(name string, policy securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	b, ok := r.files[name]
	if !ok {
		return nil, securefs.FileState{}, securefs.ErrNotFound
	}
	return append([]byte(nil), b...), securefs.FileState{Present: true, Kind: securefs.RegularFile, Size: int64(len(b))}, nil
}
