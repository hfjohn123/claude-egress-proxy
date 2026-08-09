package policy

import (
	"errors"

	"github.com/hfjohn123/claude-egress-proxy/internal/hostname"
)

var ErrInvalidRule = errors.New("invalid destination rule")

func NormalizeHostname(raw string) (string, error) {
	normalized, err := hostname.Normalize(raw)
	if err != nil {
		return "", ErrInvalidRule
	}
	return normalized, nil
}

func normalizedCanonical(raw string) bool {
	n, err := NormalizeHostname(raw)
	return err == nil && n == raw
}
