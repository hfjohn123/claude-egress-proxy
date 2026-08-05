package credential

import (
	"context"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

// A crash after target replacement but before the checkpoint write must never
// turn that uncheckpointed target into a usable high-water snapshot.
func TestCrashAfterStorePublicationIsRollbackConflictUntilCheckpointed(t *testing.T) {
	var instance [16]byte
	snapshot, err := NewValidatedSnapshot(instance, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeCanonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, MaxBytes: 1 << 20}
	state, err := inspectFiles(fakeStoreReader{files: map[string][]byte{storeName: data, lockName: make([]byte, checkpointJournalBytes-1)}}, instance, policy)
	if err != nil {
		t.Fatal(err)
	}
	if state.State != StoreConflict {
		t.Fatalf("state = %v, want conflict", state.State)
	}
}

func TestCrashAfterSuccessorPublicationReconcilesExactlyOneStep(t *testing.T) {
	var instance [16]byte
	predecessor, err := NewValidatedSnapshot(instance, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	predecessorBytes, err := EncodeCanonical(predecessor)
	if err != nil {
		t.Fatal(err)
	}
	successor, err := NewValidatedSnapshot(instance, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	successorBytes, err := EncodeCanonical(successor)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(predecessorBytes)
	slot, err := encodeCheckpoint(0, instance, 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	journal := make([]byte, checkpointJournalBytes)
	copy(journal, slot[:])
	root := &fakeMutableRoot{fakeStoreReader: fakeStoreReader{files: map[string][]byte{storeName: successorBytes, lockName: journal}}}
	policy := securefs.FilePolicy{Presence: securefs.Optional, Kind: securefs.RegularFile, MaxBytes: 1 << 20}
	repo := &Repository{root: root, instance: instance, policy: policy}
	got, err := repo.Inspect(context.Background(), Reconcile)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StoreCoherent || got.Snapshot.Generation() != 2 {
		t.Fatalf("reconcile = %#v", got)
	}
	var final [checkpointJournalBytes]byte
	copy(final[:], root.files[lockName])
	cp, ok := selectCheckpoint(final, instance)
	if !ok || cp.slot != 1 || cp.generation != 2 || cp.digest != sha256.Sum256(successorBytes) {
		t.Fatalf("checkpoint = %#v, %v", cp, ok)
	}
}

type fakeMutableRoot struct{ fakeStoreReader }

func (r *fakeMutableRoot) Close() error { return nil }
func (r *fakeMutableRoot) PublishOutput(context.Context, string, []byte, securefs.FilePolicy) (securefs.CommitBoundary, error) {
	return securefs.CommitBoundary{}, securefs.ErrUnsafePath
}
func (r *fakeMutableRoot) WithExclusiveLock(_ context.Context, _ string, _ securefs.FilePolicy, fn func(securefs.LockedFile) error) error {
	return fn(&fakeLockedFile{root: r})
}
func (r *fakeMutableRoot) AcquireRotationNamespace(context.Context, string, [3]string, securefs.FilePolicy) (securefs.RotationNamespace, error) {
	return nil, securefs.ErrUnsafePath
}

type fakeLockedFile struct{ root *fakeMutableRoot }

func (*fakeLockedFile) Identity() securefs.Identity { return securefs.Identity{} }
func (*fakeLockedFile) RecheckIdentity() error      { return nil }
func (f *fakeLockedFile) Size() (int64, error)      { return int64(len(f.root.files[lockName])), nil }
func (f *fakeLockedFile) ReadAt(p []byte, off int64) (int, error) {
	n := copy(p, f.root.files[lockName][off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
func (f *fakeLockedFile) WriteAt(p []byte, off int64) (int, error) {
	end := int(off) + len(p)
	if end > len(f.root.files[lockName]) {
		f.root.files[lockName] = append(f.root.files[lockName], make([]byte, end-len(f.root.files[lockName]))...)
	}
	return copy(f.root.files[lockName][off:], p), nil
}
func (f *fakeLockedFile) Truncate(n int64) error {
	f.root.files[lockName] = f.root.files[lockName][:n]
	return nil
}
func (*fakeLockedFile) Sync() error { return nil }
func (f *fakeLockedFile) Inspect(name string, p securefs.FilePolicy) (securefs.FileState, error) {
	return f.root.Inspect(name, p)
}
func (f *fakeLockedFile) ReadFile(name string, p securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	return f.root.ReadFile(name, p)
}
func (*fakeLockedFile) CleanupReservedTemp(context.Context, string, string, securefs.FilePolicy) error {
	return nil
}
func (*fakeLockedFile) Publish(context.Context, string, string, []byte, securefs.FilePolicy, securefs.PublishMode, securefs.Faults) (securefs.CommitBoundary, error) {
	return securefs.CommitBoundary{}, securefs.ErrUnsafePath
}
