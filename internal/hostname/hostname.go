// Package hostname validates and canonicalizes DNS hostnames.
package hostname

import (
	"errors"
	"net/netip"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

var ErrInvalid = errors.New("invalid hostname")

var profile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(true), idna.ValidateLabels(true), idna.VerifyDNSLength(true), idna.Transitional(false))

func Normalize(raw string) (string, error) {
	if !utf8.ValidString(raw) || raw == "" || strings.ContainsAny(raw, "\\/@%?#*[]:\\ \t\r\n") {
		return "", ErrInvalid
	}
	ascii, err := profile.ToASCII(raw)
	if err != nil {
		return "", ErrInvalid
	}
	ascii = strings.ToLower(ascii)
	if strings.HasSuffix(ascii, ".") {
		ascii = strings.TrimSuffix(ascii, ".")
		if strings.HasSuffix(ascii, ".") {
			return "", ErrInvalid
		}
	}
	if ascii == "" || len(ascii) > 253 {
		return "", ErrInvalid
	}
	if _, err := netip.ParseAddr(ascii); err == nil {
		return "", ErrInvalid
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", ErrInvalid
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 {
			return "", ErrInvalid
		}
	}
	return ascii, nil
}
