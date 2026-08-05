package credential

import (
	"encoding/base64"
	"testing"
	"time"
)

func TestVerifierAcceptsValidBasic(t *testing.T) {
	var instance [16]byte
	id := mustRecordID(t, "00112233445566778899aabbccddeeff")
	secret := [32]byte{1, 2, 3}
	digest := verifierDigest(id, "laptop", secret)
	s, err := NewValidatedSnapshot(instance, 1, []Record{{ID: id, Device: "laptop", CreatedAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC), State: Active, Verifier: digest}})
	if err != nil {
		t.Fatal(err)
	}
	header := []byte("Basic " + base64.StdEncoding.EncodeToString([]byte("laptop:"+base64.RawURLEncoding.EncodeToString(secret[:]))))
	got, result := (Verifier{}).Verify(s, header)
	if got != id || result.String() != "valid" {
		t.Fatalf("got %s %s", got.String(), result)
	}
}

func TestVerifierRejectsMalformedUniformly(t *testing.T) {
	var instance [16]byte
	s, err := NewValidatedSnapshot(instance, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, header := range [][]byte{nil, []byte(""), []byte("Bearer x"), []byte("Basic bad")} {
		id, result := (Verifier{}).Verify(s, header)
		if !id.IsZero() || result.String() != "invalid" {
			t.Fatalf("header %q got %s %s", header, id.String(), result)
		}
	}
}
