// Package admintoken owns the independent metrics bearer-token artifact.
package admintoken

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
	"github.com/hfjohn123/claude-egress-proxy/internal/securefs"
)

const (
	storeName = "admin-token.json"
	lockName  = "admin-token.lock"
	storeTemp = "admin-token.json.new"
	domain    = "claude-egress-proxy/admin-token/v1\x00"
)

var ErrInvalid = errors.New("admin token: invalid")
var ErrUnavailable = errors.New("admin token: unavailable")

type Snapshot struct {
	instance [16]byte
	salt     [16]byte
	verifier [32]byte
}

func (s Snapshot) Instance() [16]byte { return s.instance }

// Inspector is intentionally read-only; startup/check never repairs state.
type Inspector struct {
	root     securefs.ReadRoot
	instance [16]byte
	policy   securefs.FilePolicy
}

// Store is the sole mutating capability for this artifact.
type Store struct {
	root     securefs.MutableRoot
	instance [16]byte
	policy   securefs.FilePolicy
	entropy  io.Reader
}

func OpenInspector(root securefs.ReadRoot, instance [16]byte, policy securefs.FilePolicy) (*Inspector, error) {
	if root == nil || !validPolicy(policy) {
		return nil, ErrInvalid
	}
	return &Inspector{root: root, instance: instance, policy: policy}, nil
}

func OpenStore(root securefs.MutableRoot, instance [16]byte, policy securefs.FilePolicy) (*Store, error) {
	if root == nil || !validPolicy(policy) {
		return nil, ErrInvalid
	}
	return &Store{root: root, instance: instance, policy: policy, entropy: rand.Reader}, nil
}

func validPolicy(p securefs.FilePolicy) bool {
	return p.Presence == securefs.Optional && p.Kind == securefs.RegularFile &&
		p.MaxBytes == int64(contract.V1().StoreBytes) && securefs.IsRestrictedFilePolicy(p)
}

func (i *Inspector) Load(ctx context.Context) (Snapshot, error) {
	if i == nil || ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return load(i.root, i.instance, i.policy)
}

// LoadVerifier applies the metrics-enabled startup gate. Disabled metrics do
// not touch the artifact; enabled metrics require a valid current artifact.
func LoadVerifier(ctx context.Context, root securefs.ReadRoot, instance [16]byte, policy securefs.FilePolicy, enabled bool) (Verifier, error) {
	if !enabled {
		return DummyVerifier(), nil
	}
	i, err := OpenInspector(root, instance, policy)
	if err != nil {
		return Verifier{}, err
	}
	snapshot, err := i.Load(ctx)
	if err != nil {
		return Verifier{}, err
	}
	return NewVerifier(snapshot), nil
}

func (s *Store) Load(ctx context.Context) (Snapshot, error) {
	if s == nil || ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return load(s.root, s.instance, s.policy)
}

// Rotate makes a fresh secret durable before returning it to its caller.
func (s *Store) Rotate(ctx context.Context) ([32]byte, error) {
	var secret [32]byte
	if s == nil || ctx == nil || s.entropy == nil {
		return secret, ErrInvalid
	}
	var material [48]byte
	if _, err := io.ReadFull(s.entropy, material[:]); err != nil {
		return secret, ErrUnavailable
	}
	copy(secret[:], material[16:])
	var salt [16]byte
	copy(salt[:], material[:16])
	if salt == ([16]byte{}) {
		return secret, ErrUnavailable
	}
	snap := Snapshot{instance: s.instance, salt: salt, verifier: digest(salt, secret)}
	body, err := encode(snap)
	if err != nil {
		return secret, ErrInvalid
	}
	err = s.root.WithExclusiveLock(ctx, lockName, lockPolicy(s.policy), func(lock securefs.LockedFile) error {
		state, err := lock.Inspect(storeName, s.policy)
		if err != nil {
			return err
		}
		if err := lock.CleanupReservedTemp(ctx, storeName, storeTemp, s.policy); err != nil {
			return err
		}
		mode := securefs.AbsentTarget
		if state.Present {
			mode = securefs.PresentTarget
		}
		boundary, err := lock.Publish(ctx, storeName, storeTemp, body, s.policy, mode, securefs.NoFaults{})
		if err != nil || !boundary.NamespacePublished || !boundary.TargetDurable {
			return ErrUnavailable
		}
		return nil
	})
	if err != nil {
		return secret, normalize(err)
	}
	return secret, nil
}

func load(root securefs.ReadRoot, instance [16]byte, policy securefs.FilePolicy) (Snapshot, error) {
	data, _, err := root.ReadFile(storeName, required(policy))
	if err != nil {
		return Snapshot{}, normalize(err)
	}
	s, err := decode(data, instance)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func required(p securefs.FilePolicy) securefs.FilePolicy   { p.Presence = securefs.Required; return p }
func lockPolicy(p securefs.FilePolicy) securefs.FilePolicy { p.Presence = securefs.Optional; return p }
func normalize(err error) error {
	if errors.Is(err, ErrInvalid) || errors.Is(err, ErrUnavailable) {
		return err
	}
	return ErrUnavailable
}

type artifact struct {
	Version  uint8  `json:"version"`
	Instance string `json:"instance"`
	Salt     string `json:"salt"`
	Verifier string `json:"verifier"`
}

func encode(s Snapshot) ([]byte, error) {
	b, err := json.Marshal(artifact{1, hex.EncodeToString(s.instance[:]), base64.RawStdEncoding.EncodeToString(s.salt[:]), base64.RawStdEncoding.EncodeToString(s.verifier[:])})
	if err != nil || len(b) > contract.V1().StoreBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func decode(raw []byte, instance [16]byte) (Snapshot, error) {
	if len(raw) == 0 || len(raw) > contract.V1().StoreBytes || !validJSONNoDuplicates(raw) {
		return Snapshot{}, ErrInvalid
	}
	var a artifact
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&a) != nil || d.Decode(&struct{}{}) != io.EOF || a.Version != 1 || a.Instance != hex.EncodeToString(instance[:]) {
		return Snapshot{}, ErrInvalid
	}
	var s Snapshot
	s.instance = instance
	salt, err := base64.RawStdEncoding.DecodeString(a.Salt)
	if err != nil || len(salt) != len(s.salt) || base64.RawStdEncoding.EncodeToString(salt) != a.Salt {
		return Snapshot{}, ErrInvalid
	}
	copy(s.salt[:], salt)
	v, err := base64.RawStdEncoding.DecodeString(a.Verifier)
	if err != nil || len(v) != len(s.verifier) || base64.RawStdEncoding.EncodeToString(v) != a.Verifier {
		return Snapshot{}, ErrInvalid
	}
	copy(s.verifier[:], v)
	canonical, err := encode(s)
	if err != nil || !bytes.Equal(raw, canonical) {
		return Snapshot{}, ErrInvalid
	}
	return s, nil
}
func digest(salt [16]byte, secret [32]byte) [32]byte {
	input := digestInput(salt, secret)
	return sha256.Sum256(input[:])
}
func digestInput(salt [16]byte, secret [32]byte) [len(domain) + 16 + 32]byte {
	var input [len(domain) + 16 + 32]byte
	copy(input[:], domain)
	copy(input[len(domain):], salt[:])
	copy(input[len(domain)+16:], secret[:])
	return input
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
	t, err := d.Token()
	if err != nil {
		return false
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return false
			}
			key, ok := k.(string)
			if !ok {
				return false
			}
			if _, found := seen[key]; found {
				return false
			}
			seen[key] = struct{}{}
			if !scanJSONValue(d) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim('}')
	case '[':
		for d.More() {
			if !scanJSONValue(d) {
				return false
			}
		}
		end, e := d.Token()
		return e == nil && end == json.Delim(']')
	default:
		return false
	}
}
