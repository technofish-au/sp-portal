// The hosted apt repository: GET /apt/* with HTTP basic auth, where the
// credentials are the (instance-id, spapt_ token) pair licensing mints at
// activation (download_tokens kind "apt"). Files are served from
// storage/apt/ in the standard dists//pool/ repository layout.
//
// Licence gating (docs/fakeportal.md): an instance whose licence is
// expired or revoked may still fetch repository metadata and payload
// files whose version was published on/before the licence's end —
// appliances keep getting fixes they already paid for while updates are
// gated.
package releases

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/storage"
)

// aptRealm is the basic-auth realm apt clients see.
const aptRealm = `Basic realm="serverperch-apt"`

// serveApt handles GET /apt/*: basic-auth credential check, licence
// gating, then a plain file serve of storage/apt/<path>.
func (s *service) serveApt(w http.ResponseWriter, r *http.Request) {
	user, pass, ok := r.BasicAuth()
	if !ok || user == "" || pass == "" {
		s.aptAuthFail(w, "apt credentials required")
		return
	}
	inst, err := s.q.GetInstance(r.Context(), user)
	if err != nil {
		s.aptAuthFail(w, "unknown instance")
		return
	}
	sum := sha256.Sum256([]byte(pass))
	tok, err := s.q.GetDownloadTokenByHash(r.Context(), dbq.GetDownloadTokenByHashParams{
		TokenHash: hex.EncodeToString(sum[:]),
		Kind:      tokenKindApt,
	})
	if err != nil || tok.ExpiresAt.Before(s.now()) ||
		!tok.OrgID.Valid || tok.OrgID.String != inst.OrgID {
		s.aptAuthFail(w, "invalid apt credentials")
		return
	}
	// Resolve the request path under storage/apt/, refusing traversal.
	sub := path.Clean("/" + chi.URLParam(r, "*"))
	rel := strings.TrimPrefix(sub, "/")
	if rel == "" {
		writeErr(w, http.StatusNotFound, "not_found", "no such repository path")
		return
	}
	dest, ok := s.storagePath(storage.Apt, rel)
	if !ok {
		writeErr(w, http.StatusNotFound, "not_found", "no such repository path")
		return
	}
	info, err := os.Stat(dest)
	if err != nil || info.IsDir() {
		writeErr(w, http.StatusNotFound, "not_found", "no such repository path")
		return
	}
	if !s.aptEntitled(r, inst, rel, info.ModTime()) {
		writeErr(w, http.StatusForbidden, "entitlement_expired",
			"licence ended before this package version was published")
		return
	}
	// ServeFile handles range requests and conditional headers.
	http.ServeFile(w, r, dest)
}

// aptAuthFail answers 401 with the basic-auth challenge apt expects.
func (s *service) aptAuthFail(w http.ResponseWriter, msg string) {
	w.Header().Set("WWW-Authenticate", aptRealm)
	writeErr(w, http.StatusUnauthorized, "unauthorized", msg)
}

// aptEntitled applies the older-versions rule to a payload file:
// repository metadata (dists/, indices) is always served — clients need
// it to learn what exists — but files under pool/ are gated when the
// instance's licence has ended. The gate compares the package version's
// catalogue publish time to the licence cutoff; a file whose version is
// not in the catalogue falls back to its on-disk mtime.
func (s *service) aptEntitled(r *http.Request, inst dbq.Instance, rel string, mtime time.Time) bool {
	cutoff, noLicence, err := s.entitlement(r.Context(), inst)
	if err != nil || noLicence {
		return false
	}
	if cutoff == nil || !strings.HasPrefix(rel, "pool/") {
		return true
	}
	if ver := poolFileVersion(filepath.Base(rel)); ver != "" {
		if relRow, err := s.q.GetReleaseByVersion(r.Context(), dbq.GetReleaseByVersionParams{
			Component: "platform", Version: ver,
		}); err == nil {
			return relRow.PublishedAt != nil && !relRow.PublishedAt.After(*cutoff)
		}
		// Version not in the catalogue: fall through to the mtime rule.
	}
	return !mtime.After(*cutoff)
}

// poolFileVersion extracts the version from a Debian pool filename
// ("<name>_<version>_<arch>.<ext>"); "" when the name does not carry
// one.
func poolFileVersion(base string) string {
	parts := strings.Split(base, "_")
	if len(parts) != 3 {
		return ""
	}
	return parts[1]
}
