package policy

import (
	"errors"
	"testing"
)

func TestLoadNormalizesAndKeepsPublicRulesPrivate(t *testing.T) {
	p, err := Load("web-desktop", CustomRules{ExactHosts: []string{"BÜCHER.example"}, Suffixes: []string{"files.claude.ai"}})
	if err != nil {
		t.Fatal(err)
	}
	if !p.MatchHost("xn--bcher-kva.example") || !p.MatchHost("x.files.claude.ai") {
		t.Fatal("normalized custom rule did not match")
	}
	if p.MatchHost("evilfiles.claude.ai") || p.MatchHost("CLAUDE.AI") {
		t.Fatal("noncanonical or deceptive host matched")
	}
	for _, h := range p.BuiltInRules().ExactHosts() {
		if h == "xn--bcher-kva.example" {
			t.Fatal("public rules leaked custom host")
		}
	}
}

func TestLoadRejectsInvalidCustomRules(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules CustomRules
		want  error
	}{
		{"wildcard", CustomRules{ExactHosts: []string{"*.example.com"}}, ErrInvalidRule},
		{"duplicate normalized", CustomRules{ExactHosts: []string{"BÜCHER.example", "xn--bcher-kva.example"}}, ErrDuplicateRule},
		{"public suffix", CustomRules{Suffixes: []string{"com"}, DangerousCustomSuffixes: true}, ErrDangerousSuffix},
		{"untrusted suffix", CustomRules{Suffixes: []string{"example.com"}}, ErrDangerousSuffix},
	} {
		_, err := Load("code", tc.rules)
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s = %v, want %v", tc.name, err, tc.want)
		}
	}
}
