// Support-bundle upload leg (docs/fakeportal.md): POST /v1/support-bundles
// is the SP-Ed25519-authed endpoint appliances POST diagnostic archives
// to. R5-4 ships the upload/validation/storage contract only; the
// processing UI is a later wave.
package releases

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
	"github.com/technofish-au/sp-portal/internal/storage"
)

// bundleExts maps accepted upload content types to a file suffix.
var bundleExts = map[string]string{
	"application/gzip":         ".tar.gz",
	"application/x-gtar":       ".tar.gz",
	"application/x-tar":        ".tar",
	"application/octet-stream": ".bin",
}

// uploadSupportBundle handles POST /v1/support-bundles (SP-Ed25519):
// streams the body to storage/support-bundles/<org>/<id><ext>, records
// the support_bundles row and answers 201. The instauth middleware
// already verified the body hash (MaxBody covers the upload cap).
func (s *service) uploadSupportBundle(w http.ResponseWriter, r *http.Request) {
	inst, _ := instauth.InstanceFrom(r.Context())

	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	ext, ok := bundleExts[ct]
	if !ok {
		writeErr(w, http.StatusUnsupportedMediaType, "unsupported_media_type",
			"Content-Type must be application/gzip, application/x-tar or application/octet-stream")
		return
	}
	id := newID()
	relPath := filepath.Join(inst.OrgID, id+ext)
	dest, ok := s.storagePath(storage.SupportBundles, relPath)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle path failed")
		return
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle store failed")
		return
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o640)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle store failed")
		return
	}
	size, err := io.Copy(out, io.LimitReader(r.Body, s.opts.SupportBundleMaxBytes+1))
	cerr := out.Close()
	if err != nil || cerr != nil {
		_ = os.Remove(dest)
		writeErr(w, http.StatusInternalServerError, "internal", "bundle store failed")
		return
	}
	if size == 0 {
		_ = os.Remove(dest)
		writeErr(w, http.StatusBadRequest, "bad_request", "bundle body is empty")
		return
	}
	if size > s.opts.SupportBundleMaxBytes {
		_ = os.Remove(dest)
		writeErr(w, http.StatusRequestEntityTooLarge, "body_too_large",
			"bundle exceeds the upload limit")
		return
	}
	expires := s.now().Add(s.opts.SupportBundleTTL)
	if err := s.q.InsertSupportBundle(r.Context(), dbq.InsertSupportBundleParams{
		ID:         id,
		OrgID:      inst.OrgID,
		InstanceID: sql.NullString{String: inst.ID, Valid: true},
		Path:       relPath,
		SizeBytes:  size,
		UploadedBy: sql.NullString{String: inst.ID, Valid: true},
		ExpiresAt:  &expires,
	}); err != nil {
		_ = os.Remove(dest)
		writeErr(w, http.StatusInternalServerError, "internal", "bundle record failed")
		return
	}
	// Instance-authed upload: no session actor, but the org is known.
	if err := audit.Write(r.Context(), s.q, audit.Entry{
		OrgID: inst.OrgID, Action: ActionSupportUploaded,
		TargetType: "support_bundle", TargetID: id, IP: clientIP(r),
		Detail: map[string]any{"instance_id": inst.ID, "size_bytes": size},
	}); err != nil && s.log != nil {
		s.log.Warn("audit write failed",
			slog.String("action", ActionSupportUploaded), slog.String("error", err.Error()))
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"size_bytes": size,
		"expires_at": expires,
	})
}

// --- staff access hooks (R5-5) -------------------------------------------
// The staff admin UI for bundles lands in a later wave; these are the
// audited list/download endpoints it will call.

// bundleView is the staff view of a support_bundles row.
func bundleView(b dbq.SupportBundle) map[string]any {
	return map[string]any{
		"id":          b.ID,
		"org_id":      b.OrgID,
		"instance_id": b.InstanceID,
		"size_bytes":  b.SizeBytes,
		"uploaded_by": b.UploadedBy,
		"uploaded_at": b.UploadedAt,
		"expires_at":  b.ExpiresAt,
	}
}

// listSupportBundles handles GET /v1/admin/support-bundles?org_id&limit&
// offset — the staff browse endpoint (” org lists all orgs).
func (s *service) listSupportBundles(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("org_id")
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	bundles, err := s.q.ListSupportBundles(r.Context(), dbq.ListSupportBundlesParams{
		Column1: org, OrgID: org,
		Limit: int32(limit), Offset: int32(offset),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle list failed")
		return
	}
	out := make([]map[string]any, 0, len(bundles))
	for _, b := range bundles {
		out = append(out, bundleView(b))
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": out})
}

// downloadSupportBundle handles GET /v1/admin/support-bundles/{id}/
// download: streams the stored archive to staff and audit-logs the
// access (support_bundle.downloaded) — bundle reads are always
// attributable.
func (s *service) downloadSupportBundle(w http.ResponseWriter, r *http.Request) {
	b, err := s.q.GetSupportBundle(r.Context(), chi.URLParam(r, "bundleID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such support bundle")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "bundle lookup failed")
		}
		return
	}
	path, ok := s.storagePath(storage.SupportBundles, b.Path)
	if !ok || b.Path == "" {
		writeErr(w, http.StatusNotFound, "no_artifact", "bundle has no file on record")
		return
	}
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, http.StatusNotFound, "no_artifact", "bundle file missing")
		return
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle stat failed")
		return
	}
	s.logAudit(r, ActionSupportDownloaded, "support_bundle", b.ID, map[string]any{
		"org_id": b.OrgID, "size_bytes": b.SizeBytes,
	})
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", filepath.Base(b.Path)))
	http.ServeContent(w, r, filepath.Base(b.Path), info.ModTime(), f)
}
