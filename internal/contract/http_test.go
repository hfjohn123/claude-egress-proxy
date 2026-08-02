package contract

import (
	"slices"
	"testing"
)

func TestFramesAreClosed(t *testing.T) {
	want := []string{
		"bad_request", "forbidden", "not_found", "method_not_allowed_connect", "method_not_allowed_get",
		"proxy_authentication_required", "too_many_requests", "request_header_fields_too_large", "internal_error",
		"bad_gateway", "service_unavailable", "gateway_timeout", "http_version_not_supported", "connect_established",
		"pac_ok", "health_ok", "ready_ok", "not_ready", "metrics_unauthorized", "metrics_ok",
	}
	if got := AllFrames(); !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	if _, ok := ParseFrame("sentinel.example"); ok {
		t.Fatal("open enum")
	}
}
