package credential

import "testing"

func FuzzCredentialDecode(f *testing.F) {
	f.Add([]byte(`{"version":1}`))
	var instance [16]byte
	f.Fuzz(func(t *testing.T, raw []byte) {
		_, _ = DecodeCanonical(raw, instance)
	})
}

func FuzzBasicVerifier(f *testing.F) {
	f.Add([]byte("Basic bGFwdG9wOkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE="))
	f.Fuzz(func(t *testing.T, header []byte) {
		_, _, _ = parseBasic(header)
	})
}
