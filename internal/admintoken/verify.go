package admintoken

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

type Result struct{ Authorized bool }

// Verifier is immutable. Rotation affects only a subsequent startup load.
type Verifier struct {
	salt     [16]byte
	verifier [32]byte
	hash     func([]byte) [32]byte
	compare  func([]byte, []byte) int
}

func NewVerifier(snapshot Snapshot) Verifier {
	return Verifier{salt: snapshot.salt, verifier: snapshot.verifier}
}
func DummyVerifier() Verifier { return Verifier{} }
func (v Verifier) Verify(header []byte) Result {
	var secret [32]byte
	ok := parseBearer(header, &secret)
	input := digestInput(v.salt, secret)
	hash := v.hash
	if hash == nil {
		hash = sha256.Sum256
	}
	d := hash(input[:])
	compare := v.compare
	if compare == nil {
		compare = subtle.ConstantTimeCompare
	}
	equal := compare(d[:], v.verifier[:])
	return Result{Authorized: ok && equal == 1}
}
func parseBearer(header []byte, secret *[32]byte) bool {
	if len(header) != len("Bearer ")+43 || len(header) < 7 || string(header[:6]) != "Bearer" || header[6] != ' ' {
		return false
	}
	n, err := base64.RawURLEncoding.Decode(secret[:], header[7:])
	if err != nil || n != len(secret) {
		return false
	}
	// Canonical spelling is a grammar check, not a secret comparison. Keep the
	// verifier's single constant-time comparison reserved for the digest.
	var canonical [43]byte
	base64.RawURLEncoding.Encode(canonical[:], secret[:])
	return string(canonical[:]) == string(header[7:])
}
