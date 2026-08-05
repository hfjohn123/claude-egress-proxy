package credential

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

const (
	storeName = "credentials.json"
	lockName  = "credentials.lock"
	storeTemp = "credentials.json.new"
)

var (
	ErrUnavailable         = errors.New("credential: store unavailable")
	ErrRollbackConflict    = errors.New("credential: rollback conflict")
	ErrGenerationExhausted = errors.New("credential: generation exhausted")
	ErrNotReconciled       = errors.New("credential: store not reconciled")
)

type InspectMode uint8

const (
	ValidateOnly InspectMode = iota
	Reconcile
)

type StoreState uint8

const (
	StoreVirgin StoreState = iota
	StoreInterruptedBootstrap
	StoreCoherent
	StoreConflict
	StoreSuccessor
)

// Inspection describes state without exposing mutable filesystem handles.
// Snapshot is present only for a complete canonical credentials.json.
type Inspection struct {
	State    StoreState
	Snapshot ValidatedSnapshot
}

// Inspector has no mutation capability: config validation can only inspect
// state and therefore cannot create a lock or repair an interrupted commit.
type Inspector struct {
	root     securefs.ReadRoot
	instance [16]byte
	policy   securefs.FilePolicy
}
type Repository struct {
	root     securefs.MutableRoot
	instance [16]byte
	policy   securefs.FilePolicy
}

func OpenInspector(root securefs.ReadRoot, instance [16]byte, policy securefs.FilePolicy) (*Inspector, error) {
	if root == nil || !validStorePolicy(policy) {
		return nil, ErrInvalid
	}
	return &Inspector{root: root, instance: instance, policy: policy}, nil
}
func OpenRepository(root securefs.MutableRoot, instance [16]byte, policy securefs.FilePolicy) (*Repository, error) {
	if root == nil || !validStorePolicy(policy) {
		return nil, ErrInvalid
	}
	return &Repository{root: root, instance: instance, policy: policy}, nil
}

func validStorePolicy(p securefs.FilePolicy) bool {
	return p.Presence == securefs.Optional && p.Kind == securefs.RegularFile &&
		p.MaxBytes == int64(contract.V1().StoreBytes) && securefs.IsRestrictedFilePolicy(p)
}
func (i *Inspector) Inspect(ctx context.Context, mode InspectMode) (Inspection, error) {
	if i == nil || ctx == nil || mode != ValidateOnly {
		return Inspection{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Inspection{}, err
	}
	return inspectFiles(i.root, i.instance, i.policy)
}
func (i *Inspector) ReadCoherent(ctx context.Context) (ValidatedSnapshot, error) {
	in, err := i.Inspect(ctx, ValidateOnly)
	if err != nil {
		return ValidatedSnapshot{}, err
	}
	if in.State != StoreCoherent {
		return ValidatedSnapshot{}, stateError(in.State)
	}
	return in.Snapshot, nil
}

func (r *Repository) Inspect(ctx context.Context, mode InspectMode) (Inspection, error) {
	if r == nil || ctx == nil || (mode != ValidateOnly && mode != Reconcile) {
		return Inspection{}, ErrInvalid
	}
	if mode == ValidateOnly {
		return inspectFiles(r.root, r.instance, r.policy)
	}
	var result Inspection
	err := r.root.WithExclusiveLock(ctx, lockName, lockPolicy(r.policy), func(lock securefs.LockedFile) error {
		var err error
		result, err = inspectFiles(heldLockReader{LockedFile: lock}, r.instance, r.policy)
		if err != nil {
			return err
		}
		if result.State != StoreSuccessor && result.State != StoreInterruptedBootstrap {
			return nil
		}
		if result.Snapshot.Generation() == 0 || result.Snapshot.Generation() > (1<<53)-1 {
			return ErrRollbackConflict
		}
		return writeCheckpoint(lock, r.instance, result.Snapshot, r.policy)
	})
	if err != nil {
		return Inspection{}, normalizeStoreError(err)
	}
	if result.State == StoreSuccessor || result.State == StoreInterruptedBootstrap {
		result.State = StoreCoherent
	}
	return result, nil
}
func (r *Repository) ReadCoherent(ctx context.Context) (ValidatedSnapshot, error) {
	in, err := r.Inspect(ctx, Reconcile)
	if err != nil {
		return ValidatedSnapshot{}, err
	}
	if in.State != StoreCoherent {
		return ValidatedSnapshot{}, stateError(in.State)
	}
	return in.Snapshot, nil
}

// CommitSuccessor publishes a canonical snapshot, then advances the inactive
// checkpoint slot. It accepts only the immediate next generation.
func (r *Repository) CommitSuccessor(ctx context.Context, successor ValidatedSnapshot) error {
	if r == nil || ctx == nil || successor.Instance() != r.instance {
		return ErrInvalid
	}
	if successor.Generation() == 0 || successor.Generation() > (1<<53)-1 {
		return ErrGenerationExhausted
	}
	return normalizeStoreError(r.root.WithExclusiveLock(ctx, lockName, lockPolicy(r.policy), func(lock securefs.LockedFile) error {
		return r.commitLocked(ctx, lock, successor)
	}))
}

func (r *Repository) commitLocked(ctx context.Context, lock securefs.LockedFile, successor ValidatedSnapshot) error {
	data, err := EncodeCanonical(successor)
	if err != nil {
		return ErrInvalid
	}
	in, err := inspectFiles(heldLockReader{LockedFile: lock}, r.instance, r.policy)
	if err != nil {
		return err
	}
	if in.State == StoreInterruptedBootstrap && in.Snapshot.Generation() == 0 {
		// WithExclusiveLock creates the persistent lock before this callback.
		// Its first empty incarnation is the safe virgin-store state.
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
	if in.State == StoreVirgin {
		// A permanent lock starts with an explicit generation-zero absence
		// checkpoint. This makes a crash between lock creation and first store
		// publication distinguishable from an unsafe missing target.
		if err := writeVirginCheckpoint(lock, r.instance); err != nil {
			return err
		}
	}
	current := uint64(0)
	if in.State == StoreCoherent {
		current = in.Snapshot.Generation()
	}
	if current >= (1<<53)-1 {
		return ErrGenerationExhausted
	}
	if successor.Generation() != current+1 {
		return ErrRollbackConflict
	}
	mode := securefs.AbsentTarget
	if current != 0 {
		mode = securefs.PresentTarget
	}
	boundary, err := lock.Publish(ctx, storeName, storeTemp, data, r.policy, mode, securefs.NoFaults{})
	if err != nil {
		return err
	}
	if !boundary.NamespacePublished || !boundary.TargetDurable {
		return ErrUnavailable
	}
	return writeCheckpoint(lock, r.instance, successor, r.policy)
}

type storeReader interface {
	Inspect(string, securefs.FilePolicy) (securefs.FileState, error)
	ReadFile(string, securefs.FilePolicy) ([]byte, securefs.FileState, error)
}

// heldLockReader reads the lock journal through its already locked handle.
// Reopening it through the root would violate the process's own byte-range
// lock on Windows. Other files still use the retained root beneath the lock.
type heldLockReader struct {
	securefs.LockedFile
}

func (r heldLockReader) Inspect(name string, policy securefs.FilePolicy) (securefs.FileState, error) {
	if name != lockName {
		return r.LockedFile.Inspect(name, policy)
	}
	if policy.Kind != securefs.RegularFile {
		return securefs.FileState{}, securefs.ErrUnsafePath
	}
	if policy.Presence == securefs.MustBeAbsent {
		return securefs.FileState{}, securefs.ErrAlreadyExists
	}
	size, err := r.Size()
	if err != nil {
		return securefs.FileState{}, err
	}
	if policy.MaxBytes > 0 && size > policy.MaxBytes {
		return securefs.FileState{}, securefs.ErrTooLarge
	}
	return securefs.FileState{Present: true, Identity: r.Identity(), Kind: securefs.RegularFile, Size: size}, nil
}

func (r heldLockReader) ReadFile(name string, policy securefs.FilePolicy) ([]byte, securefs.FileState, error) {
	if name != lockName {
		return r.LockedFile.ReadFile(name, policy)
	}
	if policy.Presence != securefs.Required || policy.Kind != securefs.RegularFile {
		return nil, securefs.FileState{}, securefs.ErrUnsafePath
	}
	state, err := r.Inspect(name, policy)
	if err != nil {
		return nil, securefs.FileState{}, err
	}
	data := make([]byte, state.Size)
	if len(data) == 0 {
		return data, state, nil
	}
	n, err := r.ReadAt(data, 0)
	if err != nil || n != len(data) {
		return nil, securefs.FileState{}, securefs.ErrUnsafePath
	}
	return data, state, nil
}

func inspectFiles(root storeReader, instance [16]byte, policy securefs.FilePolicy) (Inspection, error) {
	if root == nil {
		return Inspection{}, ErrInvalid
	}
	lockData, lockPresent, err := readOptional(root, lockName, lockPolicy(policy))
	if err != nil {
		return Inspection{}, normalizeStoreError(err)
	}
	storeData, storePresent, err := readOptional(root, storeName, policy)
	if err != nil {
		return Inspection{}, normalizeStoreError(err)
	}
	if !lockPresent && !storePresent {
		return Inspection{State: StoreVirgin}, nil
	}
	if !storePresent {
		if lockPresent && len(lockData) == checkpointJournalBytes {
			var journal [checkpointJournalBytes]byte
			copy(journal[:], lockData)
			if cp, ok := selectCheckpoint(journal, instance); ok && cp.generation == 0 && cp.digest == ([sha256.Size]byte{}) {
				return Inspection{State: StoreVirgin}, nil
			}
			// Once a nonzero checkpoint is durable, absence of its target is a
			// rollback or destruction signal, never an interrupted bootstrap.
			if _, ok := selectCheckpoint(journal, instance); ok {
				return Inspection{State: StoreConflict}, nil
			}
		}
		return Inspection{State: StoreInterruptedBootstrap}, nil
	}
	snapshot, err := DecodeCanonical(storeData, instance)
	if err != nil {
		return Inspection{State: StoreConflict}, nil
	}
	if !lockPresent || len(lockData) != checkpointJournalBytes {
		// A target without a complete authenticated history could be rollback
		// material. Never promote it to a new high-water checkpoint.
		return Inspection{State: StoreConflict, Snapshot: snapshot}, nil
	}
	var journal [checkpointJournalBytes]byte
	copy(journal[:], lockData)
	cp, valid := selectCheckpoint(journal, instance)
	if !valid {
		return Inspection{State: StoreConflict, Snapshot: snapshot}, nil
	}
	digest := sha256.Sum256(storeData)
	if cp.generation == snapshot.Generation() && cp.digest == digest {
		return Inspection{State: StoreCoherent, Snapshot: snapshot}, nil
	}
	if snapshot.Generation() == cp.generation+1 {
		return Inspection{State: StoreSuccessor, Snapshot: snapshot}, nil
	}
	return Inspection{State: StoreConflict, Snapshot: snapshot}, nil
}
func readOptional(root storeReader, name string, policy securefs.FilePolicy) ([]byte, bool, error) {
	state, err := root.Inspect(name, policy)
	if err != nil {
		return nil, false, err
	}
	if !state.Present {
		return nil, false, nil
	}
	required := policy
	required.Presence = securefs.Required
	b, _, err := root.ReadFile(name, required)
	return b, err == nil, err
}
func lockPolicy(store securefs.FilePolicy) securefs.FilePolicy {
	store.MaxBytes = checkpointJournalBytes
	store.Presence = securefs.Optional
	return store
}
func writeCheckpoint(lock securefs.LockedFile, instance [16]byte, snapshot ValidatedSnapshot, policy securefs.FilePolicy) error {
	data, err := EncodeCanonical(snapshot)
	if err != nil {
		return ErrInvalid
	}
	digest := sha256.Sum256(data)
	var journal [checkpointJournalBytes]byte
	size, err := lock.Size()
	if err != nil {
		return err
	}
	if size == checkpointJournalBytes {
		if n, err := lock.ReadAt(journal[:], 0); err != nil || n != len(journal) {
			return ErrUnavailable
		}
	}
	current, ok := selectCheckpoint(journal, instance)
	slot := uint8(0)
	if ok {
		slot = 1 - current.slot
	}
	raw, err := encodeCheckpoint(slot, instance, snapshot.Generation(), digest)
	if err != nil {
		return err
	}
	if err := lock.Truncate(checkpointJournalBytes); err != nil {
		return err
	}
	if n, err := lock.WriteAt(raw[:], int64(slot)*checkpointSlotBytes); err != nil || n != len(raw) {
		return ErrUnavailable
	}
	return lock.Sync()
}
func writeVirginCheckpoint(lock securefs.LockedFile, instance [16]byte) error {
	var zero [sha256.Size]byte
	raw, err := encodeCheckpoint(0, instance, 0, zero)
	if err != nil {
		return err
	}
	if err := lock.Truncate(checkpointJournalBytes); err != nil {
		return err
	}
	var blank [checkpointSlotBytes]byte
	if n, err := lock.WriteAt(blank[:], checkpointSlotBytes); err != nil || n != len(blank) {
		return ErrUnavailable
	}
	if n, err := lock.WriteAt(raw[:], 0); err != nil || n != len(raw) {
		return ErrUnavailable
	}
	return lock.Sync()
}
func stateError(state StoreState) error {
	if state == StoreVirgin {
		return nil
	}
	if state == StoreConflict {
		return ErrRollbackConflict
	}
	return ErrNotReconciled
}
func normalizeStoreError(err error) error {
	if err == nil || errors.Is(err, ErrInvalid) || errors.Is(err, ErrRollbackConflict) || errors.Is(err, ErrGenerationExhausted) || errors.Is(err, ErrNotReconciled) {
		return err
	}
	if errors.Is(err, io.EOF) {
		return ErrUnavailable
	}
	return ErrUnavailable
}
