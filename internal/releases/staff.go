// Staff (platform-admin) handlers for the release catalogue: register
// (CI artifact upload), publish/withdraw, security flag + upgrade floor,
// offline-bundle generation and the storage prune sweep. All sit behind
// session auth + is_platform_admin (Mount's staff group).
package releases

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/bundles"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/storage"
)

// registerBody is the JSON leg of POST /admin/releases: registers an
// artifact already staged under storage_dir/releases/ (e.g. rsync'd by
// CI) — sha256/size are verified against the file when provided.
type registerBody struct {
	Version        string `json:"version"`
	Component      string `json:"component"`
	Channel        string `json:"channel"`
	Notes          string `json:"notes"`
	MinUpgradeFrom string `json:"min_upgrade_from"`
	Security       bool   `json:"security"`
	ArtifactPath   string `json:"artifact_path"`
	SHA256         string `json:"sha256"`
	SizeBytes      int64  `json:"size_bytes"`
}

// registerRelease handles POST /v1/admin/releases — the CI upload leg of
// the release pipeline. multipart/form-data uploads the artifact file
// inline (part "artifact"); application/json references a file already
// on disk under storage/releases/.
func (s *service) registerRelease(w http.ResponseWriter, r *http.Request) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	var rel dbq.Release
	var err error
	if strings.HasPrefix(ct, "multipart/") {
		rel, err = s.registerMultipart(w, r)
	} else {
		rel, err = s.registerJSON(w, r)
	}
	if err != nil {
		return // the leg already wrote the response
	}
	s.logAudit(r, ActionRegistered, "release", rel.ID, map[string]any{
		"version": rel.Version, "component": rel.Component,
		"channel": rel.Channel, "size_bytes": rel.SizeBytes,
	})
	writeJSON(w, http.StatusCreated, releaseView(rel))
}

// registerMultipart consumes the upload: form fields carry the metadata,
// file part "artifact" is streamed to
// storage/releases/<component>/<version>/<basename> while its SHA-256
// and size are computed.
func (s *service) registerMultipart(w http.ResponseWriter, r *http.Request) (dbq.Release, error) {
	var rel dbq.Release
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "malformed multipart body")
		return rel, err
	}
	file, header, err := r.FormFile("artifact")
	if err != nil {
		writeErr(w, http.StatusBadRequest, "artifact_required", "multipart file part \"artifact\" is required")
		return rel, err
	}
	defer func() { _ = file.Close() }()

	component := fieldDefault(r.FormValue("component"), "platform")
	channel := fieldDefault(r.FormValue("channel"), "stable")
	version := r.FormValue("version")
	base := filepath.Base(header.Filename)
	if base == "." || base == "/" || base == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "artifact filename is required")
		return rel, errors.New("empty filename")
	}
	relPath := filepath.Join(component, version, base)
	dest, ok := s.storagePath(storage.Releases, relPath)
	if !ok || version == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid version or filename")
		return rel, errors.New("bad path")
	}
	in := registerBody{
		Version:        version,
		Component:      component,
		Channel:        channel,
		Notes:          r.FormValue("notes"),
		MinUpgradeFrom: r.FormValue("min_upgrade_from"),
		Security:       r.FormValue("security") == "true" || r.FormValue("security") == "1",
	}
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return rel, err
	}
	// Check the duplicate before touching the artifact on disk — an
	// overwrite of the registered file must never happen silently.
	if _, err := s.q.GetReleaseByVersion(r.Context(), dbq.GetReleaseByVersionParams{
		Component: in.Component, Version: in.Version,
	}); err == nil {
		writeErr(w, http.StatusConflict, "release_exists",
			fmt.Sprintf("%s %s already registered", in.Component, in.Version))
		return rel, errors.New("duplicate")
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, "internal", "release lookup failed")
		return rel, err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "artifact store failed")
		return rel, err
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "artifact store failed")
		return rel, err
	}
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(out, h), file)
	cerr := out.Close()
	if err != nil || cerr != nil {
		_ = os.Remove(dest)
		writeErr(w, http.StatusInternalServerError, "internal", "artifact store failed")
		return rel, errors.New("copy failed")
	}
	in.ArtifactPath = relPath
	in.SHA256 = hex.EncodeToString(h.Sum(nil))
	in.SizeBytes = size
	return s.insertRelease(w, r, in)
}

// registerJSON handles the pre-staged leg: the artifact is already under
// storage/releases/ and the body describes it.
func (s *service) registerJSON(w http.ResponseWriter, r *http.Request) (dbq.Release, error) {
	var rel dbq.Release
	var in registerBody
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return rel, err
	}
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return rel, err
	}
	if in.ArtifactPath == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "artifact_path is required")
		return rel, errors.New("no path")
	}
	dest, ok := s.storagePath(storage.Releases, in.ArtifactPath)
	if !ok {
		writeErr(w, http.StatusBadRequest, "bad_request", "artifact_path escapes releases/")
		return rel, errors.New("bad path")
	}
	info, err := os.Stat(dest)
	if err != nil || info.IsDir() {
		writeErr(w, http.StatusBadRequest, "bad_request", "artifact_path not found under releases/")
		return rel, errors.New("no file")
	}
	sum, size, err := hashFile(dest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "artifact hash failed")
		return rel, err
	}
	if in.SHA256 != "" && !strings.EqualFold(in.SHA256, sum) {
		writeErr(w, http.StatusBadRequest, "sha256_mismatch",
			fmt.Sprintf("artifact sha256 is %s, not %s", sum, in.SHA256))
		return rel, errors.New("hash mismatch")
	}
	in.SHA256, in.SizeBytes = sum, size
	return s.insertRelease(w, r, in)
}

// insertRelease performs the shared tail of both register legs:
// defaults, the catalogue row insert (component+version unique) and the
// response release view.
func (s *service) insertRelease(w http.ResponseWriter, r *http.Request, in registerBody) (dbq.Release, error) {
	var rel dbq.Release
	if err := in.validate(); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return rel, err
	}
	if _, err := s.q.GetReleaseByVersion(r.Context(), dbq.GetReleaseByVersionParams{
		Component: in.Component, Version: in.Version,
	}); err == nil {
		writeErr(w, http.StatusConflict, "release_exists",
			fmt.Sprintf("%s %s already registered", in.Component, in.Version))
		return rel, errors.New("duplicate")
	} else if !errors.Is(err, sql.ErrNoRows) {
		writeErr(w, http.StatusInternalServerError, "internal", "release lookup failed")
		return rel, err
	}
	rel = dbq.Release{
		ID:             newID(),
		Version:        in.Version,
		Component:      in.Component,
		Channel:        in.Channel,
		Notes:          in.Notes,
		MinUpgradeFrom: in.MinUpgradeFrom,
		Security:       in.Security,
		ArtifactPath:   in.ArtifactPath,
		Sha256:         in.SHA256,
		SizeBytes:      in.SizeBytes,
	}
	if err := s.q.InsertRelease(r.Context(), dbq.InsertReleaseParams{
		ID:             rel.ID,
		Version:        rel.Version,
		Component:      rel.Component,
		Channel:        rel.Channel,
		Notes:          rel.Notes,
		MinUpgradeFrom: rel.MinUpgradeFrom,
		ArtifactPath:   rel.ArtifactPath,
		Sha256:         rel.Sha256,
		SizeBytes:      rel.SizeBytes,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "release insert failed")
		return rel, err
	}
	return rel, nil
}

// validate checks the shared metadata fields of a register request,
// applying component/channel defaults first.
func (in *registerBody) validate() error {
	in.Component = fieldDefault(in.Component, "platform")
	in.Channel = fieldDefault(in.Channel, "stable")
	if in.Version == "" || len(in.Version) > 64 {
		return errors.New("version is required (max 64 chars)")
	}
	if strings.ContainsAny(in.Version, "/\\") || strings.Contains(in.Version, "..") {
		return errors.New("version must not contain path separators")
	}
	switch in.Component {
	case "platform", "client", "docs":
	default:
		return errors.New("component must be platform, client or docs")
	}
	switch in.Channel {
	case "stable", "beta", "rc":
	default:
		return errors.New("channel must be stable, beta or rc")
	}
	if len(in.MinUpgradeFrom) > 64 {
		return errors.New("min_upgrade_from too long")
	}
	return nil
}

// listReleases handles GET /v1/admin/releases?limit&offset — newest first.
func (s *service) listReleases(w http.ResponseWriter, r *http.Request) {
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	rels, err := s.q.ListReleases(r.Context(), dbq.ListReleasesParams{
		Limit: int32(limit), Offset: int32(offset),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "list failed")
		return
	}
	views := make([]map[string]any, 0, len(rels))
	for _, rel := range rels {
		views = append(views, releaseView(rel))
	}
	writeJSON(w, http.StatusOK, map[string]any{"releases": views})
}

// getReleaseParam resolves {releaseID} to a row or writes 404.
func (s *service) getReleaseParam(w http.ResponseWriter, r *http.Request) (dbq.Release, bool) {
	rel, err := s.q.GetRelease(r.Context(), chi.URLParam(r, "releaseID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such release")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "release lookup failed")
		}
		return rel, false
	}
	return rel, true
}

// publishRelease handles POST /v1/admin/releases/{id}/publish: marks the
// release published (idempotent — the first publish time stands).
func (s *service) publishRelease(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.getReleaseParam(w, r)
	if !ok {
		return
	}
	if rel.WithdrawnAt != nil {
		writeErr(w, http.StatusConflict, "release_withdrawn", "withdrawn releases cannot be republished")
		return
	}
	if err := s.q.PublishRelease(r.Context(), rel.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "publish failed")
		return
	}
	s.logAudit(r, ActionPublished, "release", rel.ID, map[string]any{"version": rel.Version})
	rel, _ = s.getReleaseParam(w, r)
	writeJSON(w, http.StatusOK, releaseView(rel))
}

// withdrawRelease handles POST /v1/admin/releases/{id}/withdraw: pulls a
// published release from distribution (latest-release queries, download
// URL minting and apt gating all stop treating it as current).
func (s *service) withdrawRelease(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.getReleaseParam(w, r)
	if !ok {
		return
	}
	if rel.WithdrawnAt != nil {
		writeJSON(w, http.StatusOK, releaseView(rel)) // already withdrawn: idempotent
		return
	}
	if err := s.q.WithdrawRelease(r.Context(), rel.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "withdraw failed")
		return
	}
	s.logAudit(r, ActionWithdrawn, "release", rel.ID, map[string]any{"version": rel.Version})
	rel, _ = s.getReleaseParam(w, r)
	writeJSON(w, http.StatusOK, releaseView(rel))
}

// updateRelease handles PATCH /v1/admin/releases/{id}: staff metadata —
// the security flag and the min_upgrade_from floor. Absent fields keep
// their current value.
func (s *service) updateRelease(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.getReleaseParam(w, r)
	if !ok {
		return
	}
	var in struct {
		Security       *bool   `json:"security"`
		MinUpgradeFrom *string `json:"min_upgrade_from"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	security := rel.Security
	if in.Security != nil {
		security = *in.Security
	}
	floor := rel.MinUpgradeFrom
	if in.MinUpgradeFrom != nil {
		if len(*in.MinUpgradeFrom) > 64 {
			writeErr(w, http.StatusBadRequest, "bad_request", "min_upgrade_from too long")
			return
		}
		floor = *in.MinUpgradeFrom
	}
	if err := s.q.UpdateReleaseMeta(r.Context(), dbq.UpdateReleaseMetaParams{
		Security:       security,
		MinUpgradeFrom: floor,
		ID:             rel.ID,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "update failed")
		return
	}
	s.logAudit(r, ActionMetaUpdated, "release", rel.ID, map[string]any{
		"security": security, "min_upgrade_from": floor,
	})
	rel, _ = s.getReleaseParam(w, r)
	writeJSON(w, http.StatusOK, releaseView(rel))
}

// generateBundle handles POST /v1/admin/releases/{id}/offline-bundle:
// packs the release artifact into a signed .spb bundle under
// storage/offline-bundles/ (docs/offline-bundles.md).
func (s *service) generateBundle(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.getReleaseParam(w, r)
	if !ok {
		return
	}
	src, ok := s.storagePath(storage.Releases, rel.ArtifactPath)
	if !ok || rel.ArtifactPath == "" {
		writeErr(w, http.StatusConflict, "no_artifact", "release has no artifact on record")
		return
	}
	f, err := os.Open(src)
	if err != nil {
		writeErr(w, http.StatusConflict, "no_artifact", "artifact file missing under releases/")
		return
	}
	defer func() { _ = f.Close() }()

	name := fmt.Sprintf("serverperch-%s-%s.spb", rel.Component, rel.Version)
	dest, ok := s.storagePath(storage.OfflineBundles, name)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle path failed")
		return
	}
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle store failed")
		return
	}
	manifest := bundles.Manifest{
		Release: bundles.ReleaseInfo{
			Component:      rel.Component,
			Version:        rel.Version,
			Channel:        rel.Channel,
			MinUpgradeFrom: rel.MinUpgradeFrom,
			Security:       rel.Security,
		},
	}
	err = bundles.Build(out, manifest, []bundles.File{
		{Path: filepath.Base(rel.ArtifactPath), Data: f},
	}, s.signer)
	cerr := out.Close()
	if err != nil || cerr != nil {
		_ = os.Remove(dest)
		writeErr(w, http.StatusInternalServerError, "internal", "bundle build failed")
		return
	}
	sum, size, err := hashFile(dest)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle hash failed")
		return
	}
	s.logAudit(r, ActionBundleGenerated, "release", rel.ID, map[string]any{
		"bundle": name, "sha256": sum, "kid": s.signer.KID(),
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"bundle":            name,
		"path":              name,
		"sha256":            sum,
		"size_bytes":        size,
		"kid":               s.signer.KID(),
		"verification_keys": s.signer.VerificationKeys(),
	})
}

// listBundles handles GET /v1/admin/offline-bundles — the generated .spb
// files currently in storage/offline-bundles/.
func (s *service) listBundles(w http.ResponseWriter, r *http.Request) {
	dir := filepath.Join(s.opts.StorageRoot, storage.OfflineBundles)
	entries, err := os.ReadDir(dir)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "bundle list failed")
		return
	}
	out := []map[string]any{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".spb") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, map[string]any{
			"bundle":     e.Name(),
			"size_bytes": info.Size(),
			"created_at": info.ModTime().UTC(),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"bundles": out})
}

// pruneStorage handles POST /v1/admin/storage/prune: deletes files under
// storage/releases/ that no catalogue row references. include_withdrawn
// also drops artifacts of withdrawn releases. dry_run reports without
// deleting.
func (s *service) pruneStorage(w http.ResponseWriter, r *http.Request) {
	var in struct {
		DryRun           bool `json:"dry_run"`
		IncludeWithdrawn bool `json:"include_withdrawn"`
	}
	if r.Body != nil && r.ContentLength != 0 {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
			writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
			return
		}
	}
	referenced, err := s.q.ListReleaseArtifactPaths(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "catalogue lookup failed")
		return
	}
	keep := make(map[string]bool, len(referenced))
	for _, p := range referenced {
		keep[filepath.Clean(p)] = true
	}
	if in.IncludeWithdrawn {
		withdrawn, err := s.q.ListWithdrawnArtifactPaths(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "catalogue lookup failed")
			return
		}
		for _, p := range withdrawn {
			delete(keep, filepath.Clean(p))
		}
	}
	root := filepath.Join(s.opts.StorageRoot, storage.Releases)
	var removed []string
	var bytes int64
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || keep[filepath.Clean(rel)] {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		removed = append(removed, rel)
		bytes += info.Size()
		if !in.DryRun {
			return os.Remove(path)
		}
		return nil
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "prune sweep failed")
		return
	}
	s.logAudit(r, ActionStoragePruned, "storage", "releases", map[string]any{
		"removed": len(removed), "bytes": bytes,
		"dry_run": in.DryRun, "include_withdrawn": in.IncludeWithdrawn,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"removed": removed,
		"bytes":   bytes,
		"dry_run": in.DryRun,
	})
}

// hashFile returns the SHA-256 hex and size of path.
func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), size, nil
}

// queryInt parses an integer query parameter with a fallback.
func queryInt(r *http.Request, key string, def int) int {
	if v := r.URL.Query().Get(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// fieldDefault returns fallback for an empty form field.
func fieldDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}
