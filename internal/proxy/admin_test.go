package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hfjohn123/claude-egress-proxy/internal/admintoken"
	"github.com/hfjohn123/claude-egress-proxy/internal/admission"
	"github.com/hfjohn123/claude-egress-proxy/internal/credential"
	"github.com/hfjohn123/claude-egress-proxy/internal/session"
	"github.com/hfjohn123/claude-egress-proxy/internal/timebase"
)

func TestAdminRoutesPrecedeMetricsAuthentication(t *testing.T) {
	r := NewReadiness(session.NewCoordinator(credential.Verifier{}, nil))
	h := NewAdminHandler(AdminConfig{Admission: admission.NewAdmin(timebase.Real{}), Readiness: r, Verifier: admintoken.DummyVerifier()})
	for _, tc := range []struct {
		path, method string
		status       int
	}{
		{"/healthz", http.MethodGet, http.StatusOK}, {"/readyz", http.MethodGet, http.StatusServiceUnavailable},
		{"/metrics", http.MethodGet, http.StatusNotFound}, {"/missing", http.MethodGet, http.StatusNotFound},
		{"/healthz", http.MethodPost, http.StatusMethodNotAllowed},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Add("Authorization", "Bearer bad")
		h.ServeHTTP(rr, req)
		if rr.Code != tc.status {
			t.Fatalf("%s %s = %d, want %d", tc.method, tc.path, rr.Code, tc.status)
		}
	}
}
