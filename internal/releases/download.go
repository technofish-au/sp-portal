// HMAC-signed download URLs (docs/fakeportal.md): an appliance mints a
// short-lived URL for a published release artifact, then downloads it —
// resumable via HTTP range requests. The credential is recorded in
// download_tokens (SHA-256 only) so issuance is auditable and the row
// is the revocation record.
package releases

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
	"github.com/technofish-au/sp-portal/internal/storage"
)

// mintRequest is POST /v1/releases/download-urls: a release by id, or by
// version+component when the caller knows what it wants.
type mintRequest struct {
	ReleaseID string `json:"release_id"`
	Version   string `json:"version"`
	Component string `json:"component"`
}

// mintDownloadURL handles POST /v1/releases/download-urls (SP-Ed25519):
// entitlement-checked minting of a signed URL for a published release.
// Expired/revoked licences may still mint URLs for releases published
// on/before the licence's end (the older-versions rule).
func (s *service) mintDownloadURL(w http.ResponseWriter, r *http.Request) {
	inst, _ := instauth.InstanceFrom(r.Context())

	var req mintRequest
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	rel, err := s.resolveRelease(r, req)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such release")
		return
	}
	if rel.PublishedAt == nil || rel.WithdrawnAt != nil {
		writeErr(w, http.StatusConflict, "not_published", "release is not published")
		return
	}
	cutoff, noLicence, err := s.entitlement(r.Context(), inst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
		return
	}
	if noLicence {
		writeErr(w, http.StatusForbidden, "no_licence", "instance has no licence")
		return
	}
	if !releaseAllowed(rel, cutoff) {
		writeErr(w, http.StatusForbidden, "entitlement_expired",
			"licence ended before this release was published")
		return
	}
	token, expires, err := s.mintToken(r.Context(), rel, inst.OrgID, inst.ID, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "token mint failed")
		return
	}
	path := fmt.Sprintf("/v1/releases/%s/download?t=%s", rel.ID, token)
	url := path
	if s.opts.PublicBaseURL != "" {
		url = s.opts.PublicBaseURL + path
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"url":        url,
		"expires_at": expires,
		"release": map[string]any{
			"id":         rel.ID,
			"version":    rel.Version,
			"component":  rel.Component,
			"sha256":     rel.Sha256,
			"size_bytes": rel.SizeBytes,
		},
	})
}

// resolveRelease finds the release a mint request names.
func (s *service) resolveRelease(r *http.Request, req mintRequest) (dbq.Release, error) {
	if req.ReleaseID != "" {
		return s.q.GetRelease(r.Context(), req.ReleaseID)
	}
	if req.Version == "" {
		return dbq.Release{}, errors.New("release_id or version required")
	}
	component := req.Component
	if component == "" {
		component = "platform"
	}
	return s.q.GetReleaseByVersion(r.Context(), dbq.GetReleaseByVersionParams{
		Component: component, Version: req.Version,
	})
}

// serveDownload handles GET /v1/releases/{id}/download?t=<credential>:
// validates the signed token, then serves the artifact with
// http.ServeContent — Range/If-Range resume support comes free. The
// first successful fetch stamps download_tokens.used_at; expiry, not
// used_at, is the gate so partial downloads can resume within the TTL.
func (s *service) serveDownload(w http.ResponseWriter, r *http.Request) {
	releaseID := chi.URLParam(r, "releaseID")
	tok, code := s.validateToken(r.Context(), releaseID, r.URL.Query().Get("t"))
	if code != "" {
		status := http.StatusUnauthorized
		if code == "token_expired" {
			status = http.StatusForbidden
		}
		writeErr(w, status, code, "download token rejected")
		return
	}
	rel, err := s.q.GetRelease(r.Context(), releaseID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such release")
		return
	}
	path, ok := s.storagePath(storage.Releases, rel.ArtifactPath)
	if !ok || rel.ArtifactPath == "" {
		writeErr(w, http.StatusNotFound, "no_artifact", "release has no artifact")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no_artifact", "artifact file missing")
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "artifact stat failed")
		return
	}
	// Record first use; failure is non-fatal — the download proceeds.
	_ = s.q.MarkDownloadTokenUsed(r.Context(), tok.ID)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", filepath.Base(rel.ArtifactPath)))
	http.ServeContent(w, r, filepath.Base(rel.ArtifactPath), info.ModTime(), f)
}
