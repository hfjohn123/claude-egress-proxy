package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

const (
	fileSinkMemberBytes = int64(10_485_760)
	fileSinkSetBytes    = 3 * fileSinkMemberBytes
)

var (
	ErrInvalidFileSink = errors.New("telemetry: invalid file sink")
	ErrRepairRequired  = errors.New("telemetry: file sink repair required")
)

type ValidationMode uint8

const (
	ValidationInvalid ValidationMode = iota
	CheckOnly
	RepairActiveTail
)

type fileReader interface {
	RecheckIdentity() error
	Inspect(string, securefs.FilePolicy) (securefs.FileState, error)
	ReadFile(string, securefs.FilePolicy) ([]byte, securefs.FileState, error)
}

// ValidateFileSink validates the closed three-generation record set. CheckOnly
// takes a complete before/after snapshot so callers can use it without
// changing the state they inspected.
func ValidateFileSink(ctx context.Context, root securefs.Root, base string, policy securefs.FilePolicy, mode ValidationMode) error {
	if ctx == nil || root == nil || !validFileSinkArgs(base, policy, mode) {
		return ErrInvalidFileSink
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := rejectFourthGeneration(root, base, policy); err != nil {
		return invalidFileSink(err)
	}
	if mode == CheckOnly {
		before, err := takeFileSinkSnapshot(root, base, policy)
		if err != nil {
			return invalidFileSink(err)
		}
		repair, err := validateFileSinkContents(root, base, policy)
		if err != nil {
			return invalidFileSink(err)
		}
		tombRepair, err := checkOnlyTombstone(root, base, policy)
		if err != nil {
			return invalidFileSink(err)
		}
		after, err := takeFileSinkSnapshot(root, base, policy)
		if err != nil {
			return invalidFileSink(err)
		}
		if !before.equal(after) {
			return invalidFileSink(securefs.ErrIdentityChanged)
		}
		if repair || tombRepair {
			return ErrRepairRequired
		}
		return nil
	}

	mutable, ok := root.(securefs.MutableRoot)
	if !ok {
		return ErrInvalidFileSink
	}
	ns, err := mutable.AcquireRotationNamespace(ctx, base, fileSinkLeaves(base), policy)
	if err != nil {
		return invalidFileSink(err)
	}
	defer ns.Close()
	if err := repairTombstone(ns); err != nil {
		return invalidFileSink(err)
	}
	return validateAndRepairNamespace(ns, base, policy)
}

func rejectFourthGeneration(r fileReader, base string, policy securefs.FilePolicy) error {
	state, err := r.Inspect(base+".3", optionalFilePolicy(policy))
	if err != nil {
		return err
	}
	if state.Present {
		return securefs.ErrUnsafePath
	}
	return nil
}

func checkOnlyTombstone(r fileReader, base string, policy securefs.FilePolicy) (bool, error) {
	state, err := r.Inspect(base+".delete", optionalFilePolicy(policy))
	if err != nil || !state.Present {
		return false, err
	}
	data, readState, err := r.ReadFile(base+".delete", requiredFilePolicy(policy))
	if err != nil {
		return false, err
	}
	if readState.Identity != state.Identity || readState.Size != state.Size || int64(len(data)) != state.Size {
		return false, securefs.ErrIdentityChanged
	}
	return len(data) != 0, nil
}

// OpenFileSink acquires the rotation namespace for the lifetime of the sink.
func OpenFileSink(ctx context.Context, root securefs.MutableRoot, base string, policy securefs.FilePolicy) (Sink, error) {
	if ctx == nil || root == nil || !validFileSinkArgs(base, policy, RepairActiveTail) {
		return nil, ErrInvalidFileSink
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := rejectFourthGeneration(root, base, policy); err != nil {
		return nil, invalidFileSink(err)
	}
	ns, err := root.AcquireRotationNamespace(ctx, base, fileSinkLeaves(base), policy)
	if err != nil {
		return nil, invalidFileSink(err)
	}
	fail := func(err error) (Sink, error) { _ = ns.Close(); return nil, invalidFileSink(err) }
	if err := repairTombstone(ns); err != nil {
		return fail(err)
	}
	if err := validateAndRepairNamespace(ns, base, policy); err != nil {
		return fail(err)
	}
	leaves := fileSinkLeaves(base)
	for _, name := range leaves[1:] {
		state, err := ns.Inspect(name, optionalFilePolicy(policy))
		if err != nil {
			return fail(err)
		}
		if !state.Present {
			f, err := ns.Create(name, absentFilePolicy(policy))
			if err != nil {
				return fail(err)
			}
			if err := f.Close(); err != nil {
				return fail(err)
			}
		}
	}
	active, err := openOrCreateActive(ns, base, policy)
	if err != nil {
		return fail(err)
	}
	return &fileSink{ns: ns, active: active, base: base, policy: policy}, nil
}

type fileSink struct {
	mu      sync.Mutex
	writeMu sync.Mutex
	ns      securefs.RotationNamespace
	active  securefs.RetainedFile
	base    string
	policy  securefs.FilePolicy
	failed  error
	closed  bool
}

func (s *fileSink) WriteRecord(record []byte) error {
	if !canonicalRecord(record) {
		return ErrInvalidRecord
	}
	line := make([]byte, len(record)+1)
	copy(line, record)
	line[len(record)] = '\n'

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return securefs.ErrClosed
	}
	if s.failed != nil {
		err := s.failed
		s.mu.Unlock()
		return err
	}
	active := s.active
	s.mu.Unlock()
	if active == nil {
		return s.permanentFailure(securefs.ErrClosed)
	}
	if err := active.RecheckIdentity(); err != nil {
		return s.permanentFailure(err)
	}
	size, err := active.Size()
	if err != nil {
		return s.permanentFailure(err)
	}
	if size < 0 || size > fileSinkMemberBytes {
		return s.permanentFailure(securefs.ErrTooLarge)
	}
	if size+int64(len(line)) > fileSinkMemberBytes {
		if err := s.rotate(active); err != nil {
			return s.permanentFailure(err)
		}
		s.mu.Lock()
		active = s.active
		s.mu.Unlock()
		size = 0
	}
	n, writeErr := active.WriteAt(line, size)
	if writeErr == nil && n != len(line) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		s.rollbackOwned(active, size)
		return s.permanentFailure(writeErr)
	}
	return nil
}

func (s *fileSink) rotate(old securefs.RetainedFile) error {
	if err := old.Close(); err != nil {
		return err
	}
	leaves := fileSinkLeaves(s.base)
	var ids [3]securefs.Identity
	for i, name := range leaves {
		state, err := s.ns.Inspect(name, requiredFilePolicy(s.policy))
		if err != nil || !state.Present {
			if err != nil {
				return err
			}
			return securefs.ErrNotFound
		}
		ids[i] = state.Identity
	}
	active, err := s.ns.Rotate(leaves, ids)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.closed || s.failed != nil {
		s.mu.Unlock()
		_ = active.Close()
		return securefs.ErrClosed
	}
	s.active = active
	s.mu.Unlock()
	return nil
}

func (s *fileSink) rollbackOwned(active securefs.RetainedFile, offset int64) {
	s.mu.Lock()
	owned := !s.closed && s.active == active
	s.mu.Unlock()
	if owned {
		_ = active.Truncate(offset)
	}
}

func (s *fileSink) permanentFailure(cause error) error {
	s.mu.Lock()
	if s.failed == nil {
		s.failed = cause
	}
	err := s.failed
	active, ns := s.active, s.ns
	s.active = nil
	s.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
	if ns != nil {
		_ = ns.Close()
	}
	return err
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	active, ns := s.active, s.ns
	s.active = nil
	s.mu.Unlock()
	var err error
	if active != nil {
		err = active.Close()
	}
	if ns != nil {
		if closeErr := ns.Close(); err == nil {
			err = closeErr
		}
	}
	return err
}

func validFileSinkArgs(base string, policy securefs.FilePolicy, mode ValidationMode) bool {
	return validFileSinkBase(base) && mode > ValidationInvalid && mode <= RepairActiveTail &&
		policy.Presence == securefs.Optional && policy.Kind == securefs.RegularFile && policy.MaxBytes == fileSinkMemberBytes && securefs.IsRestrictedFilePolicy(policy)
}

func validFileSinkBase(base string) bool {
	if base == "" || base == "." || base == ".." || strings.ContainsAny(base, "\\/\x00:") {
		return false
	}
	for _, suffix := range []string{".1", ".2", ".3", ".lock", ".delete"} {
		if strings.HasSuffix(base, suffix) {
			return false
		}
	}
	return true
}

func fileSinkLeaves(base string) [3]string { return [3]string{base, base + ".1", base + ".2"} }
func optionalFilePolicy(p securefs.FilePolicy) securefs.FilePolicy {
	p.Presence = securefs.Optional
	return p
}
func requiredFilePolicy(p securefs.FilePolicy) securefs.FilePolicy {
	p.Presence = securefs.Required
	return p
}
func absentFilePolicy(p securefs.FilePolicy) securefs.FilePolicy {
	p.Presence = securefs.MustBeAbsent
	return p
}
func invalidFileSink(err error) error { return fmt.Errorf("%w: %w", ErrInvalidFileSink, err) }

func openOrCreateActive(ns securefs.RotationNamespace, base string, policy securefs.FilePolicy) (securefs.RetainedFile, error) {
	state, err := ns.Inspect(base, optionalFilePolicy(policy))
	if err != nil {
		return nil, err
	}
	if state.Present {
		return ns.Open(base, requiredFilePolicy(policy))
	}
	return ns.Create(base, absentFilePolicy(policy))
}

func repairTombstone(ns securefs.RotationNamespace) error { return ns.RepairTombstone() }

func validateAndRepairNamespace(ns securefs.RotationNamespace, base string, policy securefs.FilePolicy) error {
	repair, err := validateFileSinkContents(ns, base, policy)
	if err != nil {
		return err
	}
	if !repair {
		return nil
	}
	active, err := ns.Open(base, requiredFilePolicy(policy))
	if err != nil {
		return err
	}
	defer active.Close()
	size, err := active.Size()
	if err != nil {
		return err
	}
	data, _, err := ns.ReadFile(base, requiredFilePolicy(policy))
	if err != nil {
		return err
	}
	if size != int64(len(data)) {
		return securefs.ErrIdentityChanged
	}
	cut := int64(bytes.LastIndexByte(data, '\n') + 1)
	if err := active.Truncate(cut); err != nil {
		return err
	}
	repair, err = validateFileSinkContents(ns, base, policy)
	if err != nil || repair {
		if err != nil {
			return err
		}
		return ErrRepairRequired
	}
	return nil
}

func validateFileSinkContents(r fileReader, base string, policy securefs.FilePolicy) (bool, error) {
	if err := r.RecheckIdentity(); err != nil {
		return false, err
	}
	leaves := fileSinkLeaves(base)
	states := [3]securefs.FileState{}
	var contents [3][]byte
	var total int64
	for i, name := range leaves {
		state, err := r.Inspect(name, optionalFilePolicy(policy))
		if err != nil {
			return false, err
		}
		states[i] = state
		if !state.Present {
			continue
		}
		data, readState, err := r.ReadFile(name, requiredFilePolicy(policy))
		if err != nil || readState.Identity != state.Identity || readState.Size != state.Size || int64(len(data)) != state.Size {
			if err != nil {
				return false, err
			}
			return false, securefs.ErrIdentityChanged
		}
		contents[i] = data
		total += int64(len(data))
		if total > fileSinkSetBytes {
			return false, securefs.ErrTooLarge
		}
	}
	if !permittedFileSinkPresence(states) {
		return false, securefs.ErrUnsafePath
	}
	for i := 1; i < len(leaves); i++ {
		if states[i].Present && !validCompleteLines(contents[i]) {
			return false, ErrInvalidRecord
		}
	}
	repair := false
	if states[0].Present {
		var ok bool
		repair, ok = validActiveLines(contents[0])
		if !ok {
			return false, ErrInvalidRecord
		}
	}
	if err := r.RecheckIdentity(); err != nil {
		return false, err
	}
	return repair, nil
}

func permittedFileSinkPresence(states [3]securefs.FileState) bool {
	a, b, c := states[0].Present, states[1].Present, states[2].Present
	return (!a && !b && !c) || (a && !b && !c) || (a && b && !c) || (a && !b && c) || (a && b && c) || (!a && b && !c) || (!a && b && c)
}

func validCompleteLines(data []byte) bool {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return len(data) == 0
	}
	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 1 || i > GeneratedRecordSchema.MaxBytes || !canonicalRecord(data[:i]) {
			return false
		}
		data = data[i+1:]
	}
	return true
}

func validActiveLines(data []byte) (repair, ok bool) {
	if len(data) == 0 {
		return false, true
	}
	last := bytes.LastIndexByte(data, '\n')
	if last < 0 {
		return len(data) <= GeneratedRecordSchema.MaxBytes, len(data) <= GeneratedRecordSchema.MaxBytes
	}
	if len(data)-last-1 > 2048 || !validCompleteLines(data[:last+1]) {
		return false, false
	}
	if last == len(data)-1 {
		return false, true
	}
	return true, true
}

type diskRecord struct {
	Timestamp           string  `json:"timestamp"`
	Level               string  `json:"level"`
	Event               string  `json:"event"`
	Reason              string  `json:"reason"`
	DestinationHostname *string `json:"destination_hostname"`
	DeviceIdentifier    *string `json:"device_identifier"`
	SourcePrefix        *string `json:"source_prefix"`
	DurationMillis      *uint64 `json:"duration_ms"`
	ClientToOrigin      *uint64 `json:"bytes_client_to_origin"`
	OriginToClient      *uint64 `json:"bytes_origin_to_client"`
}

func canonicalRecord(raw []byte) bool {
	if len(raw) < 1 || len(raw) > GeneratedRecordSchema.MaxBytes || strings.ContainsAny(string(raw), "\r\n") {
		return false
	}
	var got diskRecord
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.DisallowUnknownFields()
	if err := d.Decode(&got); err != nil || d.Decode(&struct{}{}) != io.EOF {
		return false
	}
	at, err := time.Parse(time.RFC3339Nano, got.Timestamp)
	if err != nil || got.Timestamp != at.UTC().Format(time.RFC3339Nano) {
		return false
	}
	level, known := generatedRecordLevel(got.Event, got.Reason)
	if !known || level != got.Level {
		return false
	}
	var sensitive *SensitiveMetadata
	if got.DestinationHostname != nil || got.DeviceIdentifier != nil || got.SourcePrefix != nil || got.DurationMillis != nil || got.ClientToOrigin != nil || got.OriginToClient != nil {
		if got.DestinationHostname == nil || got.DeviceIdentifier == nil || got.SourcePrefix == nil || got.DurationMillis == nil || got.ClientToOrigin == nil || got.OriginToClient == nil {
			return false
		}
		prefix, err := netipParsePrefix(*got.SourcePrefix)
		if err != nil {
			return false
		}
		sensitive = &SensitiveMetadata{DestinationHostname: *got.DestinationHostname, DeviceIdentifier: *got.DeviceIdentifier, SourcePrefix: prefix, DurationMillis: *got.DurationMillis, Bytes: contractByteTotals(*got.ClientToOrigin, *got.OriginToClient)}
	}
	want, err := build(at, got.Level, got.Event, got.Reason, sensitive)
	return err == nil && want.JSON() == string(raw)
}

// Kept as tiny wrappers so the JSON-validation code remains independent from
// the representation imports used by record construction.
func netipParsePrefix(s string) (netip.Prefix, error) { return netip.ParsePrefix(s) }
func contractByteTotals(in, out uint64) contract.ByteTotals {
	return contract.ByteTotals{ClientToOrigin: in, OriginToClient: out}
}

type fileSinkSnapshot struct{ entries [6]snapshotEntry }
type snapshotEntry struct {
	state  securefs.FileState
	digest [sha256.Size]byte
}

func takeFileSinkSnapshot(r fileReader, base string, policy securefs.FilePolicy) (fileSinkSnapshot, error) {
	var out fileSinkSnapshot
	if err := r.RecheckIdentity(); err != nil {
		return out, err
	}
	names := [6]string{base, base + ".1", base + ".2", base + ".3", base + ".lock", base + ".delete"}
	for i, name := range names {
		p := optionalFilePolicy(policy)
		if i == 4 {
			p.MaxBytes = 0
		}
		state, err := r.Inspect(name, p)
		if err != nil {
			return out, err
		}
		out.entries[i].state = state
		if state.Present {
			data, readState, err := r.ReadFile(name, requiredFilePolicy(p))
			if err != nil || readState.Identity != state.Identity || int64(len(data)) != state.Size {
				if err != nil {
					return out, err
				}
				return out, securefs.ErrIdentityChanged
			}
			if i == 3 || i == 4 && len(data) != 0 {
				return out, securefs.ErrUnsafePath
			}
			out.entries[i].digest = sha256.Sum256(data)
		}
	}
	if err := r.RecheckIdentity(); err != nil {
		return out, err
	}
	return out, nil
}

func (s fileSinkSnapshot) equal(other fileSinkSnapshot) bool { return s == other }
