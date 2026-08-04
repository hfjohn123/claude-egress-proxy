package policy

import (
	"errors"
	"strings"

	"golang.org/x/net/publicsuffix"
)

var (
	ErrUnknownProfile  = errors.New("unknown destination profile")
	ErrDuplicateRule   = errors.New("duplicate destination rule")
	ErrDangerousSuffix = errors.New("dangerous destination suffix")
	ErrRuleLimit       = errors.New("destination rule limit")
)

type CustomRules struct {
	ExactHosts              []string
	Suffixes                []string
	DangerousCustomSuffixes bool
}
type Rules struct{ exactHosts, suffixes []string }
type Policy struct {
	profile         string
	builtIn, custom Rules
}

func (r Rules) ExactHosts() []string { return append([]string(nil), r.exactHosts...) }
func (r Rules) Suffixes() []string   { return append([]string(nil), r.suffixes...) }
func (p Policy) Profile() string     { return p.profile }
func (p Policy) BuiltInRules() Rules { return p.builtIn }
func (p Policy) LocalRules() Rules {
	return Rules{exactHosts: sortedUnique(append(p.builtIn.ExactHosts(), p.custom.exactHosts...)), suffixes: sortedUnique(append(p.builtIn.Suffixes(), p.custom.suffixes...))}
}
func (p Policy) MatchHost(host string) bool {
	if !normalizedCanonical(host) {
		return false
	}
	return matches(p.LocalRules(), host)
}

func matches(r Rules, host string) bool {
	for _, v := range r.exactHosts {
		if host == v {
			return true
		}
	}
	for _, v := range r.suffixes {
		if host == v || strings.HasSuffix(host, "."+v) {
			return true
		}
	}
	return false
}

func Load(profile string, custom CustomRules) (Policy, error) {
	built, ok := generatedProfile(profile)
	if !ok {
		return Policy{}, ErrUnknownProfile
	}
	if len(custom.ExactHosts)+len(custom.Suffixes) > 128 {
		return Policy{}, ErrRuleLimit
	}
	seen := make(map[string]bool, len(built.exactHosts)+len(built.suffixes)+len(custom.ExactHosts)+len(custom.Suffixes))
	for _, h := range append(built.ExactHosts(), built.Suffixes()...) {
		seen[h] = true
	}
	var c Rules
	for _, raw := range custom.ExactHosts {
		n, err := NormalizeHostname(raw)
		if err != nil {
			return Policy{}, ErrInvalidRule
		}
		if seen[n] {
			return Policy{}, ErrDuplicateRule
		}
		seen[n] = true
		c.exactHosts = append(c.exactHosts, n)
	}
	for _, raw := range custom.Suffixes {
		if strings.ContainsAny(raw, "*[]") {
			return Policy{}, ErrInvalidRule
		}
		if !strings.Contains(strings.TrimSuffix(raw, "."), ".") {
			return Policy{}, ErrDangerousSuffix
		}
		n, err := NormalizeHostname(raw)
		if err != nil {
			return Policy{}, ErrInvalidRule
		}
		if seen[n] {
			return Policy{}, ErrDuplicateRule
		}
		public, _ := publicsuffix.PublicSuffix(n)
		if strings.Count(n, ".") < 1 || public == n {
			return Policy{}, ErrDangerousSuffix
		}
		if !custom.DangerousCustomSuffixes && !trustedSuffix(n) {
			return Policy{}, ErrDangerousSuffix
		}
		seen[n] = true
		c.suffixes = append(c.suffixes, n)
	}
	c.exactHosts = sortedUnique(c.exactHosts)
	c.suffixes = sortedUnique(c.suffixes)
	return Policy{profile: profile, builtIn: built, custom: c}, nil
}
func trustedSuffix(s string) bool {
	roots := []string{"anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com"}
	for _, root := range roots {
		if s == root || strings.HasSuffix(s, "."+root) {
			return true
		}
	}
	return false
}
