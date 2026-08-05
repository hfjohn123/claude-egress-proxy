package credential

import (
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
