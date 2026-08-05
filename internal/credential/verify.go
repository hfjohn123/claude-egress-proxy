package credential

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

type Verifier struct {
	hash    func([]byte) [32]byte
	compare func([]byte, []byte) int
}

const credentialDomain = "claude-egress-proxy/credential/v1\x00"

func (v Verifier) Verify(snapshot ValidatedSnapshot, header []byte) (RecordID, contract.AuthenticationResult) {
	device, secret, grammar := parseBasic(header)
	record, found := snapshot.recordForDevice(device)
	digest := verifierDigest(record.ID, device, secret, v.hash)
	compare := v.compare
	if compare == nil {
		compare = subtle.ConstantTimeCompare
	}
	equal := compare(digest[:], record.Verifier[:])
	if grammar && found && record.State == Active && equal == 1 {
		return record.ID, mustAuthentication("valid")
	}
	return RecordID{}, mustAuthentication("invalid")
}

func mustAuthentication(text string) contract.AuthenticationResult {
	v, ok := contract.ParseAuthenticationResult(text)
	if !ok {
		panic("credential: contract")
	}
	return v
}

func verifierDigest(id RecordID, device string, secret [32]byte, hook ...func([]byte) [32]byte) [32]byte {
	var input [len(credentialDomain) + 16 + 1 + 64 + 32]byte
	copy(input[:], credentialDomain)
	p := len(credentialDomain)
	copy(input[p:p+16], id[:])
	p += 16
	input[p] = byte(len(device))
	p++
	copy(input[p:p+64], device)
	p += 64
	copy(input[p:], secret[:])
	if len(hook) != 0 && hook[0] != nil {
		return hook[0](input[:])
	}
	return verifierHash(input[:])
}

func verifierHash(input []byte) [32]byte { return sha256.Sum256(input) }

func parseBasic(header []byte) (string, [32]byte, bool) {
	var zero [32]byte
	// 64-byte device + ':' + 43-byte secret encodes to at most 144 bytes.
	if len(header) < 7 || len(header) > 150 || !basicScheme(header[:5]) || header[5] != ' ' {
		return "", zero, false
	}
	encoded := header[6:]
	raw, err := base64.StdEncoding.DecodeString(string(encoded))
	if err != nil {
		return "", zero, false
	}
	var canonical [144]byte
	length := base64.StdEncoding.EncodedLen(len(raw))
	base64.StdEncoding.Encode(canonical[:length], raw)
	if length != len(encoded) || subtle.ConstantTimeCompare(canonical[:length], encoded) != 1 {
		return "", zero, false
	}
	colon := -1
	for i, b := range raw {
		if b == ':' {
			if colon >= 0 {
				return "", zero, false
			}
			colon = i
		}
	}
	if colon < 1 || colon+44 != len(raw) || !validDevice(string(raw[:colon])) {
		return "", zero, false
	}
	var secret [32]byte
	n, err := base64.RawURLEncoding.Decode(secret[:], raw[colon+1:])
	if err != nil || n != len(secret) {
		return "", zero, false
	}
	var secretCanonical [43]byte
	base64.RawURLEncoding.Encode(secretCanonical[:], secret[:])
	if subtle.ConstantTimeCompare(secretCanonical[:], raw[colon+1:]) != 1 {
		return "", zero, false
	}
	return string(raw[:colon]), secret, true
}

func basicScheme(input []byte) bool {
	return len(input) == 5 && (input[0] == 'B' || input[0] == 'b') && (input[1] == 'A' || input[1] == 'a') && (input[2] == 'S' || input[2] == 's') && (input[3] == 'I' || input[3] == 'i') && (input[4] == 'C' || input[4] == 'c')
}
