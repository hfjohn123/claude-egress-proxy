package credential

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

func TestCredentialMutationsAddRevokePurge(t *testing.T) {
	root, policy := credentialMutableTestRoot(t)
	var instance [16]byte
	instance[0] = 1
	repo, err := OpenRepository(root, instance, policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	record, secret, err := repo.Add(context.Background(), "laptop-1", bytes.NewReader(bytes.Repeat([]byte{7}, 48)), now)
	if err != nil {
		in, inspectErr := repo.Inspect(context.Background(), ValidateOnly)
		t.Fatalf("%v; inspection=%+v inspectErr=%v", err, in, inspectErr)
	}
	if record.Device != "laptop-1" || record.State != Active || record.CreatedAt != now || record.ID.IsZero() {
		t.Fatalf("add record = %+v", record)
	}
	if secret == ([32]byte{}) {
		t.Fatal("secret is zero")
	}
	snapshot, err := repo.ReadCoherent(context.Background())
	if err != nil || snapshot.Generation() != 1 || len(snapshot.Records()) != 1 {
		t.Fatalf("first snapshot = %+v, %v", snapshot, err)
	}
	revoked, err := repo.Revoke(context.Background(), record.ID)
	if err != nil || revoked.State != Revoked {
		t.Fatalf("revoke = %+v, %v", revoked, err)
	}
	snapshot, err = repo.ReadCoherent(context.Background())
	if err != nil || snapshot.Generation() != 2 || snapshot.Records()[0].State != Revoked {
		t.Fatalf("revoked snapshot = %+v, %v", snapshot, err)
	}
	if err := repo.Purge(context.Background(), record.ID); err != nil {
		t.Fatal(err)
	}
	snapshot, err = repo.ReadCoherent(context.Background())
	if err != nil || snapshot.Generation() != 3 || len(snapshot.Records()) != 0 {
		t.Fatalf("purged snapshot = %+v, %v", snapshot, err)
	}
}

func TestCredentialAddRejectsDuplicateWithoutPublication(t *testing.T) {
	root, policy := credentialMutableTestRoot(t)
	var instance [16]byte
	repo, err := OpenRepository(root, instance, policy)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	if _, _, err := repo.Add(context.Background(), "phone", bytes.NewReader(bytes.Repeat([]byte{1}, 48)), now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.Add(context.Background(), "phone", bytes.NewReader(bytes.Repeat([]byte{2}, 48)), now); err == nil {
		t.Fatal("duplicate add succeeded")
	}
	snapshot, err := repo.ReadCoherent(context.Background())
	if err != nil || snapshot.Generation() != 1 || len(snapshot.Records()) != 1 {
		t.Fatalf("duplicate changed state: %+v, %v", snapshot, err)
	}
}

func TestCredentialMutationStorageProbe(t *testing.T) {
	root, policy := credentialMutableTestRoot(t)
	var instance [16]byte
	var id RecordID
	for i := range id {
		id[i] = 7
	}
	var secret [32]byte
	secret[0] = 7
	record := Record{ID: id, Device: "laptop-1", CreatedAt: time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC), State: Active, Verifier: verifierDigest(id, "laptop-1", secret)}
	snapshot, err := NewValidatedSnapshot(instance, 1, []Record{record})
	if err != nil {
		t.Fatal(err)
	}
	data, err := EncodeCanonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	err = root.WithExclusiveLock(context.Background(), lockName, lockPolicy(policy), func(lock securefs.LockedFile) error {
		if err := writeVirginCheckpoint(lock, instance); err != nil {
			return err
		}
		if err := writeVirginCheckpoint(lock, instance); err != nil {
			return err
		}
		boundary, err := lock.Publish(context.Background(), storeName, storeTemp, data, policy, securefs.AbsentTarget, securefs.NoFaults{})
		if err != nil {
			return err
		}
		if !boundary.NamespacePublished || !boundary.TargetDurable {
			t.Fatalf("boundary = %+v", boundary)
		}
		return writeCheckpoint(lock, instance, snapshot, policy)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCredentialMutationRejectsExhaustedGenerationWithoutPublication(t *testing.T) {
	root, policy := credentialMutableTestRoot(t)
	var instance [16]byte
	instance[0] = 1
	repo, err := OpenRepository(root, instance, policy)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := NewValidatedSnapshot(instance, (1<<53)-1, nil)
	if err != nil {
		t.Fatal(err)
	}
	snapshot = snapshot.withPredecessor((1<<53)-2, sha256.Sum256([]byte("predecessor")))
	data, err := EncodeCanonical(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	err = root.WithExclusiveLock(context.Background(), lockName, lockPolicy(policy), func(lock securefs.LockedFile) error {
		if err := writeVirginCheckpoint(lock, instance); err != nil {
			return err
		}
		boundary, err := lock.Publish(context.Background(), storeName, storeTemp, data, policy, securefs.AbsentTarget, securefs.NoFaults{})
		if err != nil {
			return err
		}
		if !boundary.NamespacePublished || !boundary.TargetDurable {
			t.Fatalf("boundary = %+v", boundary)
		}
		return writeCheckpoint(lock, instance, snapshot, policy)
	})
	if err != nil {
		t.Fatal(err)
	}
	requiredStore := policy
	requiredStore.Presence = securefs.Required
	beforeStore, _, err := root.ReadFile(storeName, requiredStore)
	if err != nil {
		t.Fatal(err)
	}
	requiredLock := lockPolicy(policy)
	requiredLock.Presence = securefs.Required
	beforeLock, _, err := root.ReadFile(lockName, requiredLock)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = repo.Add(context.Background(), "phone", bytes.NewReader(bytes.Repeat([]byte{2}, 48)), time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))
	if !errors.Is(err, ErrGenerationExhausted) {
		t.Fatalf("Add error = %v, want ErrGenerationExhausted", err)
	}
	after, err := repo.ReadCoherent(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if after.Generation() != snapshot.Generation() || len(after.Records()) != 0 {
		t.Fatalf("state changed: generation=%d records=%d", after.Generation(), len(after.Records()))
	}
	afterStore, _, err := root.ReadFile(storeName, requiredStore)
	if err != nil {
		t.Fatal(err)
	}
	afterLock, _, err := root.ReadFile(lockName, requiredLock)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(afterStore, beforeStore) || !bytes.Equal(afterLock, beforeLock) {
		t.Fatal("exhausted mutation changed store or checkpoint bytes")
	}
}
