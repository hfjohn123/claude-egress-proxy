package credential

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"
)

func TestJournalSlotRoundTripIsByteExact(t *testing.T) {
	var instance [16]byte
	for i := range instance {
		instance[i] = byte(i + 1)
	}
	digest := sha256.Sum256([]byte("canonical-store"))
	slot, err := encodeCheckpoint(1, instance, 42, digest)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(slot[:8]); got != "CEPCRED1" {
		t.Fatalf("magic = %q", got)
	}
	if slot[8] != 1 || slot[9] != 1 {
		t.Fatalf("header = %x", slot[:10])
	}
	if got := binary.BigEndian.Uint64(slot[32:40]); got != 42 {
		t.Fatalf("generation = %d", got)
	}
	if _, ok := decodeCheckpoint(slot, instance); !ok {
		t.Fatal("valid checkpoint rejected")
	}
	for _, offset := range []int{10, 72, 96} {
		bad := slot
		bad[offset] ^= 1
		if _, ok := decodeCheckpoint(bad, instance); ok {
			t.Fatalf("tamper at %d accepted", offset)
		}
	}
}

func TestSelectCheckpointRejectsEqualGenerationConflict(t *testing.T) {
	var instance [16]byte
	a := sha256.Sum256([]byte("a"))
	b := sha256.Sum256([]byte("b"))
	zero, err := encodeCheckpoint(0, instance, 7, a)
	if err != nil {
		t.Fatal(err)
	}
	one, err := encodeCheckpoint(1, instance, 7, b)
	if err != nil {
		t.Fatal(err)
	}
	var journal [256]byte
	copy(journal[:128], zero[:])
	copy(journal[128:], one[:])
	if _, ok := selectCheckpoint(journal, instance); ok {
		t.Fatal("equal generation conflict accepted")
	}
}

func TestSelectCheckpointRejectsSlotInWrongPhysicalPosition(t *testing.T) {
	var instance [16]byte
	digest := sha256.Sum256([]byte("store"))
	slot, err := encodeCheckpoint(1, instance, 1, digest)
	if err != nil {
		t.Fatal(err)
	}
	var journal [checkpointJournalBytes]byte
	copy(journal[:checkpointSlotBytes], slot[:]) // slot 1 forged into slot 0.
	if _, ok := selectCheckpoint(journal, instance); ok {
		t.Fatal("wrong physical slot accepted")
	}
}
