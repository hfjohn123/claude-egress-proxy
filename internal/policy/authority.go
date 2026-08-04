package policy

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"
)

type SemanticError uint8

const (
	SemanticNone SemanticError = iota
	SemanticMalformed
	SemanticPortDenied
	SemanticAddressDenied
)

type Authority struct {
	host string
	port uint16
}

func (a Authority) Host() string { return a.host }
func (a Authority) Port() uint16 { return a.port }
func ParseAuthority(raw []byte) (Authority, SemanticError) {
	if !utf8.Valid(raw) {
		return Authority{}, SemanticMalformed
	}
	s := string(raw)
	if strings.ContainsAny(s, "\\/@%?# \t\r\n") {
		return Authority{}, SemanticMalformed
	}
	host, port, literal, ok := splitAuthority(s)
	if !ok {
		return Authority{}, SemanticMalformed
	}
	if !canonicalPort(port) {
		return Authority{}, SemanticMalformed
	}
	n, _ := strconv.ParseUint(port, 10, 16)
	if literal {
		if n != 443 {
			return Authority{}, SemanticPortDenied
		}
		return Authority{}, SemanticAddressDenied
	}
	hn, err := NormalizeHostname(host)
	if err != nil {
		return Authority{}, SemanticMalformed
	}
	if n != 443 {
		return Authority{}, SemanticPortDenied
	}
	return Authority{hn, uint16(n)}, SemanticNone
}
func canonicalPort(port string) bool {
	if port == "" || port[0] == '0' {
		return false
	}
	for i := range port {
		if port[i] < '0' || port[i] > '9' {
			return false
		}
	}
	n, err := strconv.ParseUint(port, 10, 16)
	return err == nil && n != 0
}
func splitAuthority(s string) (string, string, bool, bool) {
	if strings.HasPrefix(s, "[") {
		i := strings.IndexByte(s, ']')
		if i < 0 || i+1 >= len(s) || s[i+1] != ':' || strings.Count(s, "[") != 1 || strings.Count(s, "]") != 1 {
			return "", "", false, false
		}
		h := s[1:i]
		_, e := netip.ParseAddr(h)
		if e == nil {
			a, _ := netip.ParseAddr(h)
			if a.Is4() {
				return "", "", false, false
			}
		}
		return h, s[i+2:], e == nil, e == nil
	}
	if strings.Count(s, ":") != 1 {
		return "", "", false, false
	}
	p := strings.LastIndexByte(s, ':')
	h := s[:p]
	if h == "" {
		return "", "", false, false
	}
	_, e := netip.ParseAddr(h)
	return h, s[p+1:], e == nil, true
}
