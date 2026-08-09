package credential

import (
	"bytes"
	"testing"
	"time"
)

func TestCanonicalEncodeDecodeRoundTrip(t *testing.T) {
	var instance [16]byte
	instance[15] = 9
	s, err := NewValidatedSnapshot(instance, 53, []Record{{ID: mustRecordID(t, "00112233445566778899aabbccddeeff"), Device: "phone", CreatedAt: time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC), State: Active, Verifier: [32]byte{8}}})
	if err != nil {
		t.Fatal(err)
	}
	s = s.withPredecessor(52, [32]byte{7})
	raw, err := EncodeCanonical(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeCanonical(raw, instance)
	if err != nil {
		t.Fatal(err)
	}
	again, err := EncodeCanonical(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, again) {
		t.Fatalf("not canonical: %q != %q", raw, again)
	}
}

func TestDecodeCanonicalRejectsWhitespace(t *testing.T) {
	var instance [16]byte
	_, err := DecodeCanonical([]byte(" {\"version\":1}"), instance)
	if err == nil {
		t.Fatal("accepted noncanonical JSON")
	}
}
