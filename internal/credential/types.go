// Package credential owns immutable, canonical proxy credential snapshots.
package credential

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

var ErrInvalid = errors.New("credential: invalid")

type RecordID [16]byte

func ParseRecordID(text string) (RecordID, error) {
	var id RecordID
	if len(text) != 32 {
		return id, ErrInvalid
	}
	for _, b := range []byte(text) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return id, ErrInvalid
		}
	}
	_, err := hex.Decode(id[:], []byte(text))
	if err != nil {
		return RecordID{}, ErrInvalid
	}
	return id, nil
}
func (id RecordID) String() string { return hex.EncodeToString(id[:]) }
func (id RecordID) IsZero() bool   { return id == RecordID{} }

type State uint8

const (
	Active State = iota
	Revoked
)

func (s State) String() string {
	if s == Active {
		return "active"
	}
	if s == Revoked {
		return "revoked"
	}
	return ""
}

type Record struct {
	ID        RecordID
	Device    string
	CreatedAt time.Time
	State     State
	Verifier  [sha256.Size]byte
}

type ValidatedSnapshot struct {
	instance   [16]byte
	generation uint64
	records    []Record
	byID       [128]RecordID
	byDevice   [128]string
	dummy      Record
}

func NewValidatedSnapshot(instance [16]byte, generation uint64, records []Record) (ValidatedSnapshot, error) {
	if generation > (1<<53)-1 || len(records) > contract.V1().RecordLimit {
		return ValidatedSnapshot{}, ErrInvalid
	}
	s := ValidatedSnapshot{instance: instance, generation: generation, records: append([]Record(nil), records...)}
	for i := range s.records {
		r := &s.records[i]
		if r.ID.IsZero() || !validDevice(r.Device) || !validTimestamp(r.CreatedAt) || (r.State != Active && r.State != Revoked) {
			return ValidatedSnapshot{}, ErrInvalid
		}
		r.CreatedAt = r.CreatedAt.UTC()
		for j := 0; j < i; j++ {
			if s.records[j].ID == r.ID || s.records[j].Device == r.Device {
				return ValidatedSnapshot{}, ErrInvalid
			}
		}
	}
	sort.Slice(s.records, func(i, j int) bool { return s.records[i].ID.String() < s.records[j].ID.String() })
	for i, r := range s.records {
		s.byID[i] = r.ID
		s.byDevice[i] = r.Device
	}
	return s, nil
}
func (s ValidatedSnapshot) Instance() [16]byte { return s.instance }
func (s ValidatedSnapshot) Generation() uint64 { return s.generation }
func (s ValidatedSnapshot) Records() []Record  { return append([]Record(nil), s.records...) }

type AuthHandle struct {
	RecordID   RecordID
	Device     string
	Generation uint64
}
type AuthResult struct {
	Handle AuthHandle
	Result contract.AuthenticationResult
}

// AuthHandle returns a stable, snapshot-scoped handle for an active record.
func (s ValidatedSnapshot) AuthHandle(id RecordID) (AuthHandle, bool) {
	i := -1
	for n := range s.records {
		if s.byID[n] == id {
			i = n
			break
		}
	}
	if i < 0 || s.records[i].State != Active {
		return AuthHandle{}, false
	}
	r := s.records[i]
	return AuthHandle{RecordID: r.ID, Device: r.Device, Generation: s.generation}, true
}

func (s ValidatedSnapshot) recordForDevice(device string) (Record, bool) {
	record, found := s.dummy, false
	for i := range s.byDevice {
		if i < len(s.records) && s.byDevice[i] == device {
			record, found = s.records[i], true
		}
	}
	return record, found
}

func validDevice(text string) bool {
	if len(text) < 1 || len(text) > 64 {
		return false
	}
	for _, b := range []byte(text) {
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '.' || b == '_' || b == '~' || b == '-') {
			return false
		}
	}
	return true
}
func validTimestamp(v time.Time) bool {
	if v.IsZero() || v.Location() != time.UTC || v.Year() < 0 || v.Year() > 9999 {
		return false
	}
	text := v.Format(time.RFC3339Nano)
	return len(text) >= 20 && len(text) <= 30 && text[len(text)-1] == 'Z'
}
