package policy

import "testing"

func FuzzAuthority(f *testing.F) {
	for _, s := range []string{"api.anthropic.com:443", "[::1]:443", "bad:00", "BÜCHER.example.:443"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		a, e := ParseAuthority(raw)
		if e != SemanticNone && (a.Host() != "" || a.Port() != 0) {
			t.Fatal("error returned authority")
		}
		if e == SemanticNone && (!normalizedCanonical(a.Host()) || a.Port() != 443) {
			t.Fatal("success not canonical")
		}
	})
}
