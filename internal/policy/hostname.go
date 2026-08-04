package policy

import (
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var ErrInvalidRule = errors.New("invalid destination rule")

var hostnameProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true), idna.Transitional(false))

func NormalizeHostname(raw string) (string, error) {
	if !utf8.ValidString(raw) || raw == "" || strings.ContainsAny(raw, "\\/@%?#*[]:\\ \t\r\n") {
		return "", ErrInvalidRule
	}
	ascii, err := hostnameProfile.ToASCII(raw)
	if err != nil {
		return "", ErrInvalidRule
	}
	ascii = strings.ToLower(ascii)
	if strings.HasSuffix(ascii, ".") {
		ascii = strings.TrimSuffix(ascii, ".")
		if strings.HasSuffix(ascii, ".") {
			return "", ErrInvalidRule
		}
	}
	if ascii == "" || len(ascii) > 253 {
		return "", ErrInvalidRule
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", ErrInvalidRule
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrInvalidRule
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", ErrInvalidRule
		}
	}
	return ascii, nil
}

func normalizedCanonical(raw string) bool {
	n, err := NormalizeHostname(raw)
	return err == nil && n == raw
}
