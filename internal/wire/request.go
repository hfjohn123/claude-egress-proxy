// Package wire contains the deliberately small HTTP boundary shared by the
// public and administrative listeners.
package wire

import (
	"net/http"
	"strings"
)

// TargetForm is the syntactic form of an immutable HTTP request target.
type TargetForm uint8

const (
	TargetOrigin TargetForm = iota
	TargetAuthority
	TargetAbsolute
	TargetAsterisk
)

// Request is the normalized, handler-visible part of an HTTP request.
// RequestURI is retained verbatim and is the only input used for target routing.
type Request struct {
	Method     string
	RequestURI string
	Target     TargetForm
}

// Decision is a structural decision made before routing or authentication.
type Decision uint8

const (
	DecisionAllow Decision = iota
	DecisionBadRequest
	DecisionHTTPVersionNotSupported
)

// AdaptRequest preserves the target without authority normalization and applies
// only the common version and framing precedence.
func AdaptRequest(r *http.Request) (Request, Decision) {
	request := Request{Method: r.Method, RequestURI: r.RequestURI, Target: classifyTarget(r.RequestURI)}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		return request, DecisionHTTPVersionNotSupported
	}
	if _, present := r.Header["Content-Length"]; present || len(r.TransferEncoding) != 0 ||
		len(r.Header.Values("Expect")) != 0 || len(r.Header.Values("Upgrade")) != 0 ||
		connectionUpgrade(r.Header.Values("Connection")) || (r.Body != nil && r.Body != http.NoBody) {
		return request, DecisionBadRequest
	}
	return request, DecisionAllow
}

func classifyTarget(target string) TargetForm {
	if target == "*" {
		return TargetAsterisk
	}
	if strings.HasPrefix(target, "/") {
		return TargetOrigin
	}
	if i := strings.Index(target, "://"); i > 0 && isScheme(target[:i]) {
		return TargetAbsolute
	}
	return TargetAuthority
}

func isScheme(value string) bool {
	for i, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (i > 0 && ((r >= '0' && r <= '9') || r == '+' || r == '-' || r == '.')) {
			continue
		}
		return false
	}
	return value != ""
}

func connectionUpgrade(values []string) bool {
	for _, value := range values {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
				return true
			}
		}
	}
	return false
}

// TakeAuthorization obtains exactly one header value in independent bounded
// storage and always removes the field. The count is intentionally not policy.
func TakeAuthorization(header http.Header, field string) ([]byte, int) {
	values := header.Values(field)
	header.Del(field)
	if len(values) != 1 {
		return nil, len(values)
	}
	const maxAuthorizationBytes = 16 << 10
	value := values[0]
	if len(value) > maxAuthorizationBytes {
		value = value[:maxAuthorizationBytes]
	}
	return append([]byte(nil), value...), 1
}
