package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The licensing domain mounts at the /v1 root; these checks pin the
// routing without needing a database (the exercised paths fail before
// touching it).
func TestLicensingMountedUnderV1(t *testing.T) {
	r := NewRouter(Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})

	// POST /v1/activations with a non-JSON body is a domain 400, proving
	// the request reached licensing rather than the SPA fallback.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/activations", strings.NewReader("nope")))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "bad_request") {
		t.Fatalf("/v1/activations = %d: %s", rec.Code, rec.Body.String())
	}

	// GET /v1/licence without the SP-Ed25519 header is a 401.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/licence", nil))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bad_auth_header") {
		t.Fatalf("/v1/licence = %d: %s", rec.Code, rec.Body.String())
	}

	// An unmatched /v1 path 404s inside the mounted licensing router —
	// it does not leak into the SPA fallback.
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/nothing-here", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("/v1/nothing-here = %d", rec.Code)
	}
}
