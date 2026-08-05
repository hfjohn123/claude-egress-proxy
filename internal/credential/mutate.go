package credential

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

var (
	ErrDeviceExists   = errors.New("credential: device exists")
	ErrRecordNotFound = errors.New("credential: record not found")
	ErrAlreadyRevoked = errors.New("credential: already revoked")
	ErrRecordActive   = errors.New("credential: record active")
)

// Add creates an active record and returns its one-time plaintext secret.
func (r *Repository) Add(ctx context.Context, device string, entropy io.Reader, now time.Time) (Record, [32]byte, error) {
	var zero [32]byte
	if r == nil || ctx == nil || entropy == nil || !validDevice(device) || !validTimestamp(now.UTC()) {
		return Record{}, zero, ErrInvalid
	}
	var material [48]byte
	if _, err := io.ReadFull(entropy, material[:]); err != nil {
		return Record{}, zero, ErrUnavailable
	}
	var id RecordID
	var secret [32]byte
	copy(id[:], material[:16])
	copy(secret[:], material[16:])
	if id.IsZero() {
		return Record{}, zero, ErrUnavailable
	}
	var added Record
	err := r.mutate(ctx, func(current ValidatedSnapshot) (ValidatedSnapshot, error) {
		if len(current.records) >= contract.V1().RecordLimit {
			return ValidatedSnapshot{}, ErrUnavailable
		}
		for _, record := range current.records {
			if record.Device == device || record.ID == id {
				return ValidatedSnapshot{}, ErrDeviceExists
			}
		}
		added = Record{ID: id, Device: device, CreatedAt: now.UTC(), State: Active, Verifier: verifierDigest(id, device, secret)}
		records := current.Records()
		records = append(records, added)
		return NewValidatedSnapshot(r.instance, current.Generation()+1, records)
	})
	if err != nil {
		return Record{}, zero, err
	}
	return added, secret, nil
}

func (r *Repository) Revoke(ctx context.Context, id RecordID) (Record, error) {
	if r == nil || ctx == nil || id.IsZero() {
		return Record{}, ErrInvalid
	}
	var revoked Record
	err := r.mutate(ctx, func(current ValidatedSnapshot) (ValidatedSnapshot, error) {
		records := current.Records()
		for i := range records {
			if records[i].ID != id {
				continue
			}
			if records[i].State == Revoked {
				return ValidatedSnapshot{}, ErrAlreadyRevoked
			}
			records[i].State = Revoked
			revoked = records[i]
			return NewValidatedSnapshot(r.instance, current.Generation()+1, records)
		}
		return ValidatedSnapshot{}, ErrRecordNotFound
	})
	return revoked, err
}

func (r *Repository) Purge(ctx context.Context, id RecordID) error {
	if r == nil || ctx == nil || id.IsZero() {
		return ErrInvalid
	}
	return r.mutate(ctx, func(current ValidatedSnapshot) (ValidatedSnapshot, error) {
		records := current.Records()
		for i := range records {
			if records[i].ID != id {
				continue
			}
			if records[i].State == Active {
				return ValidatedSnapshot{}, ErrRecordActive
			}
			records = append(records[:i:i], records[i+1:]...)
			return NewValidatedSnapshot(r.instance, current.Generation()+1, records)
		}
		return ValidatedSnapshot{}, ErrRecordNotFound
	})
}

// List returns a stable ID-sorted snapshot. Reconciliation is permitted.
func (r *Repository) List(ctx context.Context) ([]Record, error) {
	snapshot, err := r.ReadCoherent(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Records(), nil
}

func (r *Repository) mutate(ctx context.Context, change func(ValidatedSnapshot) (ValidatedSnapshot, error)) error {
	if r == nil || ctx == nil || change == nil {
		return ErrInvalid
	}
	return normalizeStoreError(r.root.WithExclusiveLock(ctx, lockName, lockPolicy(r.policy), func(lock securefs.LockedFile) error {
		in, err := inspectFiles(heldLockReader{LockedFile: lock}, r.instance, r.policy)
		if err != nil {
			return err
		}
		if in.State == StoreInterruptedBootstrap && in.Snapshot.Generation() == 0 {
			in.State = StoreVirgin
		} else if in.State == StoreSuccessor || in.State == StoreInterruptedBootstrap {
			if err := writeCheckpoint(lock, r.instance, in.Snapshot, r.policy); err != nil {
				return err
			}
			in.State = StoreCoherent
		}
		if in.State == StoreConflict {
			return ErrRollbackConflict
		}
		if in.State != StoreVirgin && in.State != StoreCoherent {
			return ErrNotReconciled
		}
		current := in.Snapshot
		if in.State == StoreVirgin {
			current, err = NewValidatedSnapshot(r.instance, 0, nil)
			if err != nil {
				return err
			}
		}
		successor, err := change(current)
		if err != nil {
			return err
		}
		return r.commitLocked(ctx, lock, successor)
	}))
}
