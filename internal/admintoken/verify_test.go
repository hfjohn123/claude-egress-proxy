package admintoken

import (
	"encoding/base64"
	"testing"
)

func TestVerifierUsesOneHashAndCompareForAllHeaders(t *testing.T) {
	secret := [32]byte{1, 2, 3}
	salt := [16]byte{9}
	s := Snapshot{salt: salt, verifier: digest(salt, secret)}
	valid := []byte("Bearer " + base64.RawURLEncoding.EncodeToString(secret[:]))
	for _, header := range [][]byte{nil, []byte("Basic bad"), []byte("Bearer x"), append([]byte(nil), valid...)} {
		hashes, compares := 0, 0
		v := NewVerifier(s)
		v.hash = func(b []byte) [32]byte { hashes++; return digest(salt, secret) }
		v.compare = func(a, b []byte) int {
			compares++
			if string(header) == string(valid) {
				return 1
			}
			return 0
		}
		got := v.Verify(header)
		if got.Authorized != (string(header) == string(valid)) || hashes != 1 || compares != 1 {
			t.Fatalf("header=%q authorized=%v hashes=%d compares=%d", header, got.Authorized, hashes, compares)
		}
	}
}

func TestDecodeRejectsWrongInstanceAndNoncanonicalJSON(t *testing.T) {
	instance := [16]byte{1}
	s := Snapshot{instance: instance, salt: [16]byte{2}, verifier: [32]byte{3}}
	b, err := encode(s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decode(b, [16]byte{4}); err == nil {
		t.Fatal("wrong instance accepted")
	}
	if _, err := decode(append(b, '\n'), instance); err == nil {
		t.Fatal("noncanonical artifact accepted")
	}
}
