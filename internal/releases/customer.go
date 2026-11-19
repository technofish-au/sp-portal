// Customer-facing catalogue and download minting (R5-5): the portal
// downloads page lists published releases and mints the same HMAC-signed
// download URLs appliances get — but authorised by session + org
// membership + the org's licence entitlement rather than SP-Ed25519.
package releases

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// listPublished handles GET /v1/releases — the published catalogue any
// signed-in customer may browse (entitlement gates minting, not listing).
func (s *service) listPublished(w http.ResponseWriter, r *http.Request) {
	rels, err := s.q.ListPublishedReleases(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "release list failed")
		return
	}
	views := make([]map[string]any, 0, len(rels))
	for _, rel := range rels {
		views = append(views, releaseView(rel))
	}
	writeJSON(w, http.StatusOK, map[string]any{"releases": views})
}

// mintForUser handles POST /v1/releases/{releaseID}/download-url: the
// session-authed counterpart of the appliance mint endpoint. Body
// {org_id}; the caller must be an org member and the org's licences
// carry the entitlement (same older-versions rule as instances).
func (s *service) mintForUser(w http.ResponseWriter, r *http.Request) {
	sess, _ := accounts.SessionFrom(r.Context())
	var in struct {
		OrgID string `json:"org_id"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	if in.OrgID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "org_id is required")
		return
	}
	if _, err := s.acct.RequireOrgRole(r.Context(), sess.User.ID, in.OrgID,
		accounts.RoleOwner, accounts.RoleAdmin, accounts.RoleMember, accounts.RoleViewer); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "organisation membership required")
		return
	}
	rel, err := s.q.GetRelease(r.Context(), chi.URLParam(r, "releaseID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such release")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "release lookup failed")
		}
		return
	}
	if rel.PublishedAt == nil || rel.WithdrawnAt != nil {
		writeErr(w, http.StatusConflict, "not_published", "release is not published")
		return
	}
	cutoff, hasLicence, err := s.orgEntitlement(r.Context(), in.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
		return
	}
	if !hasLicence {
		writeErr(w, http.StatusForbidden, "no_licence", "organisation has no licence")
		return
	}
	if !releaseAllowed(rel, cutoff) {
		writeErr(w, http.StatusForbidden, "entitlement_expired",
			"licence ended before this release was published")
		return
	}
	token, expires, err := s.mintToken(r.Context(), rel, in.OrgID, sess.User.ID, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "token mint failed")
		return
	}
	s.logAudit(r, ActionDownloadMinted, "release", rel.ID, map[string]any{
		"org_id": in.OrgID, "version": rel.Version,
	})
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

// orgEntitlement collapses the org's licences into the same cutoff shape
// entitlement() produces for an instance: nil means fully entitled, a
// non-nil cutoff gates minting to releases published on/before it.
// hasLicence is false when the org holds no licences at all.
func (s *service) orgEntitlement(ctx context.Context, orgID string) (cutoff *time.Time, hasLicence bool, err error) {
	lics, err := s.q.ListLicencesByOrg(ctx, orgID)
	if err != nil {
		return nil, false, fmt.Errorf("releases: org licences: %w", err)
	}
	if len(lics) == 0 {
		return nil, false, nil
	}
	for _, lic := range lics {
		end := licenceEnd(lic, s.now())
		if end == nil {
			return nil, true, nil // a live licence fully entitles the org
		}
		if cutoff == nil || end.After(*cutoff) {
			cutoff = end // most lenient end wins
		}
	}
	return cutoff, true, nil
}

// licenceEnd is a licence's terminal time: the earliest past revocation
// or expiry. Nil means the licence is still live.
func licenceEnd(lic dbq.Licence, now time.Time) *time.Time {
	var end *time.Time
	for _, t := range []*time.Time{lic.RevokedAt, lic.ExpiresAt} {
		if t == nil || t.After(now) {
			continue // not yet terminal
		}
		if end == nil || t.Before(*end) {
			end = t
		}
	}
	return end
}
