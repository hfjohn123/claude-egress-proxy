package credential

import (
	"testing"
	"time"
)

func TestCanonicalModelAcceptsClosedValues(t *testing.T) {
	var instance [16]byte
	instance[0] = 1
	created := time.Date(2026, 8, 2, 3, 4, 5, 6, time.UTC)
	record := Record{ID: mustRecordID(t, "00112233445566778899aabbccddeeff"), Device: "laptop-1", CreatedAt: created, State: Active, Verifier: [32]byte{1}}
	if _, err := NewValidatedSnapshot(instance, 1, []Record{record}); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalModelRejectsInvalidRecord(t *testing.T) {
	var instance [16]byte
	_, err := NewValidatedSnapshot(instance, 0, []Record{{Device: "bad device"}})
	if err == nil {
		t.Fatal("accepted invalid record")
	}
}

func mustRecordID(t *testing.T, text string) RecordID {
	t.Helper()
	id, err := ParseRecordID(text)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
