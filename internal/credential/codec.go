package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

type storeRecord struct {
	ID        string `json:"id"`
	Device    string `json:"device"`
	CreatedAt string `json:"created_at"`
	State     string `json:"state"`
	Verifier  string `json:"verifier"`
}
type storeWire struct {
	Version    uint8         `json:"version"`
	Instance   string        `json:"instance"`
	Generation uint64        `json:"generation"`
	Records    []storeRecord `json:"records"`
}

func EncodeCanonical(snapshot ValidatedSnapshot) ([]byte, error) {
	if _, err := NewValidatedSnapshot(snapshot.instance, snapshot.generation, snapshot.records); err != nil {
		return nil, ErrInvalid
	}
	w := storeWire{Version: 1, Instance: hex.EncodeToString(snapshot.instance[:]), Generation: snapshot.generation, Records: make([]storeRecord, len(snapshot.records))}
	for i, r := range snapshot.records {
		w.Records[i] = storeRecord{r.ID.String(), r.Device, r.CreatedAt.UTC().Format(time.RFC3339Nano), r.State.String(), base64.RawStdEncoding.EncodeToString(r.Verifier[:])}
	}
	b, err := json.Marshal(w)
	if err != nil || len(b) > contract.V1().StoreBytes {
		return nil, ErrInvalid
	}
	return b, nil
}

func DecodeCanonical(raw []byte, instance [16]byte) (ValidatedSnapshot, error) {
	if len(raw) == 0 || len(raw) > contract.V1().StoreBytes || !validJSONNoDuplicates(raw) {
		return ValidatedSnapshot{}, ErrInvalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var w storeWire
	if err := dec.Decode(&w); err != nil {
		return ValidatedSnapshot{}, ErrInvalid
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ValidatedSnapshot{}, ErrInvalid
	}
	if w.Version != 1 || w.Instance != hex.EncodeToString(instance[:]) {
		return ValidatedSnapshot{}, ErrInvalid
	}
	records := make([]Record, len(w.Records))
	for i, r := range w.Records {
		id, err := ParseRecordID(r.ID)
		if err != nil {
			return ValidatedSnapshot{}, ErrInvalid
		}
		at, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if err != nil || at.Format(time.RFC3339Nano) != r.CreatedAt {
			return ValidatedSnapshot{}, ErrInvalid
		}
		var state State
		switch r.State {
		case "active":
			state = Active
		case "revoked":
			state = Revoked
		default:
			return ValidatedSnapshot{}, ErrInvalid
		}
		vb, err := base64.RawStdEncoding.DecodeString(r.Verifier)
		if err != nil || len(vb) != sha256.Size || base64.RawStdEncoding.EncodeToString(vb) != r.Verifier {
			return ValidatedSnapshot{}, ErrInvalid
		}
		copy(records[i].Verifier[:], vb)
		records[i].ID = id
		records[i].Device = r.Device
		records[i].CreatedAt = at.UTC()
		records[i].State = state
	}
	s, err := NewValidatedSnapshot(instance, w.Generation, records)
	if err != nil {
		return ValidatedSnapshot{}, ErrInvalid
	}
	canonical, err := EncodeCanonical(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ValidatedSnapshot{}, ErrInvalid
	}
	return s, nil
}

func validJSONNoDuplicates(raw []byte) bool {
	d := json.NewDecoder(bytes.NewReader(raw))
	if !scanJSONValue(d) {
		return false
	}
	_, err := d.Token()
	return err == io.EOF
}
func scanJSONValue(d *json.Decoder) bool {
	token, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok {
				return false
			}
			if _, found := seen[name]; found {
				return false
			}
			seen[name] = struct{}{}
			if !scanJSONValue(d) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !scanJSONValue(d) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	default:
		return false
	}
}
