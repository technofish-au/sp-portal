// Support-bundle upload leg (docs/fakeportal.md): POST /v1/support-bundles
// is the SP-Ed25519-authed endpoint appliances POST diagnostic archives
// to. R5-4 ships the upload/validation/storage contract only; the
// processing UI is a later wave.
package releases

import (
	"database/sql"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"os"
	"path/filepath"

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
