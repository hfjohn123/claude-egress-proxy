package credential

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"

	"github.com/hfjohn123/claude-egress-proxy/internal/contract"
)

type Verifier struct{}

const credentialDomain = "claude-egress-proxy/credential/v1\x00"

func (Verifier) Verify(snapshot ValidatedSnapshot, header []byte) (RecordID, contract.AuthenticationResult) {
	device, secret, grammar := parseBasic(header)
	record := snapshot.dummy
	found := false
	if grammar {
		if i, ok := snapshot.byDevice[device]; ok {
			record = snapshot.records[i]
			found = true
		}
	}
	digest := verifierDigest(record.ID, device, secret)
	equal := subtle.ConstantTimeCompare(digest[:], record.Verifier[:])
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
func verifierDigest(id RecordID, device string, secret [32]byte) [32]byte {
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
	return sha256.Sum256(input[:])
}
func parseBasic(header []byte) (string, [32]byte, bool) {
	var zero [32]byte
	s := string(header)
	if len(s) < 7 || !strings.EqualFold(s[:5], "Basic") || s[5] != ' ' || strings.Contains(s[6:], " ") {
		return "", zero, false
	}
	encoded := s[6:]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
		return "", zero, false
	}
	parts := strings.Split(string(raw), ":")
	if len(parts) != 2 || !validDevice(parts[0]) || len(parts[1]) != 43 {
		return "", zero, false
	}
	secret, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		return "", zero, false
	}
	copy(zero[:], secret)
	return parts[0], zero, true
}
