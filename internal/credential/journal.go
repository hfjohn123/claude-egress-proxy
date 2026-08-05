package credential

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
)

const checkpointSlotBytes = 128
const checkpointJournalBytes = checkpointSlotBytes * 2

type checkpoint struct {
	slot       uint8
	instance   [16]byte
	generation uint64
	digest     [sha256.Size]byte
}

// encodeCheckpoint freezes the v1 on-disk checkpoint layout.  The journal is
// not a serialization format: each slot is independently self-authenticating.
func encodeCheckpoint(slot uint8, instance [16]byte, generation uint64, digest [sha256.Size]byte) ([checkpointSlotBytes]byte, error) {
	var raw [checkpointSlotBytes]byte
	if slot > 1 || generation > (1<<53)-1 {
		return raw, ErrInvalid
	}
	copy(raw[:8], "CEPCRED1")
	raw[8], raw[9] = 1, slot
	copy(raw[16:32], instance[:])
	binary.BigEndian.PutUint64(raw[32:40], generation)
	copy(raw[40:72], digest[:])
	checksum := sha256.Sum256(raw[:96])
	copy(raw[96:], checksum[:])
	return raw, nil
}

func decodeCheckpoint(raw [checkpointSlotBytes]byte, instance [16]byte) (checkpoint, bool) {
	var out checkpoint
	if string(raw[:8]) != "CEPCRED1" || raw[8] != 1 || raw[9] > 1 || !allZero(raw[10:16]) || !bytes.Equal(raw[16:32], instance[:]) || !allZero(raw[72:96]) {
		return out, false
	}
	if binary.BigEndian.Uint64(raw[32:40]) > (1<<53)-1 {
		return out, false
	}
	want := sha256.Sum256(raw[:96])
	if !bytes.Equal(raw[96:], want[:]) {
		return out, false
	}
	out.slot = raw[9]
	copy(out.instance[:], raw[16:32])
	out.generation = binary.BigEndian.Uint64(raw[32:40])
	copy(out.digest[:], raw[40:72])
	return out, true
}

// selectCheckpoint returns the newest valid checkpoint. Equal generations are
// safe only when they identify identical store bytes; otherwise recovery must
// not guess which history is authoritative.
func selectCheckpoint(journal [checkpointJournalBytes]byte, instance [16]byte) (checkpoint, bool) {
	var slots [2]checkpoint
	valid := [2]bool{}
	for i := range slots {
		var raw [checkpointSlotBytes]byte
		copy(raw[:], journal[i*checkpointSlotBytes:(i+1)*checkpointSlotBytes])
		slots[i], valid[i] = decodeCheckpoint(raw, instance)
	}
	if !valid[0] && !valid[1] {
		return checkpoint{}, false
	}
	if valid[0] && !valid[1] {
		return slots[0], true
	}
	if !valid[0] {
		return slots[1], true
	}
	if slots[0].generation == slots[1].generation && slots[0].digest != slots[1].digest {
		return checkpoint{}, false
	}
	if slots[1].generation > slots[0].generation {
		return slots[1], true
	}
	return slots[0], true
}

func allZero(b []byte) bool {
	var v byte
	for _, x := range b {
		v |= x
	}
	return v == 0
}
