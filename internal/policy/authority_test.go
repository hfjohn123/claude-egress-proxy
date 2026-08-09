package policy

import "testing"

func TestParseAuthorityPrecedenceAndNormalization(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want SemanticError
		host string
	}{
		{"BÜCHER.example.:443", SemanticNone, "xn--bcher-kva.example"},
		{"api.anthropic.com:444", SemanticPortDenied, ""},
		{"bad..host:444", SemanticMalformed, ""},
		{"[::1]:444", SemanticPortDenied, ""},
		{"127.0.0.1:443", SemanticAddressDenied, ""},
		{"[::1]:443", SemanticAddressDenied, ""},
		{"[2001:db8::1]:443", SemanticAddressDenied, ""},
		{"[2001:DB8::1]:443", SemanticMalformed, ""},
		{"[2001:0db8:0:0:0:0:0:1]:443", SemanticMalformed, ""},
		{"user@api.anthropic.com:443", SemanticMalformed, ""},
		{"api.anthropic.com:0443", SemanticMalformed, ""},
		{"api.anthropic.com:+443", SemanticMalformed, ""},
		{"api.anthropic.com:-443", SemanticMalformed, ""},
		{"api.anthropic.com:443/", SemanticMalformed, ""},
	} {
		got, e := ParseAuthority([]byte(tc.raw))
		if e != tc.want || got.Host() != tc.host {
			t.Fatalf("%q = (%q,%v), want (%q,%v)", tc.raw, got.Host(), e, tc.host, tc.want)
		}
	}
}
