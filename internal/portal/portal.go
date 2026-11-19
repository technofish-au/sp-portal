// Package portal serves the customer-facing portal API: an org member's
// view of their licences, registered appliances (instances) and check-in
// history, plus instance deactivation. All endpoints need a full session
// and membership of the owning org; mutations need a non-viewer role.
//
// The appliance-facing side of the same data (activation, check-ins,
// SP-Ed25519 auth) lives in internal/licensing — this package is the
// portal user's read/deactivate view over it.
package portal

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// allRoles permits any org member (read endpoints); writeRoles drops
// the read-only viewer.
var (
	allRoles   = []string{accounts.RoleOwner, accounts.RoleAdmin, accounts.RoleMember, accounts.RoleViewer}
	writeRoles = []string{accounts.RoleOwner, accounts.RoleAdmin, accounts.RoleMember}
)

// handlers carries the endpoint dependencies.
type handlers struct {
	acct *accounts.Service
	q    *dbq.Queries
}

// Routes returns the domain handler for standalone use (tests); Mount
// registers the same paths on the /v1 mux.
func Routes(db *sql.DB, acct *accounts.Service) http.Handler {
	r := chi.NewRouter()
	Mount(r, db, acct)
	return r
}

// Mount registers the domain's /v1 routes directly on r (chi refuses two
// Mount("/") calls — accounts already holds the /v1 root, so the domain
// registers its own paths, same pattern as internal/licensing).
//
//	GET  /licences                          ?org_id=
//	GET  /licences/{licenceID}
//	GET  /instances                         ?org_id=
//	GET  /instances/{instanceID}
//	GET  /instances/{instanceID}/reports    ?limit=
//	POST /instances/{instanceID}/deactivate
func Mount(r chi.Router, db *sql.DB, acct *accounts.Service) {
	h := &handlers{acct: acct, q: dbq.New(db)}
	r.Group(func(r chi.Router) {
		r.Use(acct.SessionMiddleware())
		r.Use(accounts.RequireAuth)
		r.Get("/licences", h.listLicences)
		r.Get("/licences/{licenceID}", h.getLicence)
		r.Get("/instances", h.listInstances)
		r.Get("/instances/{instanceID}", h.getInstance)
		r.Get("/instances/{instanceID}/reports", h.listReports)
		r.Post("/instances/{instanceID}/deactivate", h.deactivate)
	})
}

// memberOrg enforces org membership for read endpoints; writeOrg for
// mutations (viewer excluded).
func (h *handlers) memberOrg(w http.ResponseWriter, r *http.Request, orgID string) bool {
	sess, _ := accounts.SessionFrom(r.Context())
	if _, err := h.acct.RequireOrgRole(r.Context(), sess.User.ID, orgID, allRoles...); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "organisation membership required")
		return false
	}
	return true
}

func (h *handlers) writeOrg(w http.ResponseWriter, r *http.Request, orgID string) bool {
	sess, _ := accounts.SessionFrom(r.Context())
	if _, err := h.acct.RequireOrgRole(r.Context(), sess.User.ID, orgID, writeRoles...); err != nil {
		writeErr(w, http.StatusForbidden, "forbidden", "viewer role is read-only")
		return false
	}
	return true
}

// getLicenceParam resolves {licenceID} and checks org membership.
func (h *handlers) getLicenceParam(w http.ResponseWriter, r *http.Request) (dbq.Licence, bool) {
	lic, err := h.q.GetLicence(r.Context(), chi.URLParam(r, "licenceID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such licence")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
		}
		return lic, false
	}
	return lic, h.memberOrg(w, r, lic.OrgID)
}

// getInstanceParam resolves {instanceID} and checks org membership.
func (h *handlers) getInstanceParam(w http.ResponseWriter, r *http.Request) (dbq.Instance, bool) {
	inst, err := h.q.GetInstance(r.Context(), chi.URLParam(r, "instanceID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such instance")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "instance lookup failed")
		}
		return inst, false
	}
	return inst, h.memberOrg(w, r, inst.OrgID)
}

// licenceView is the customer-facing licence: key, plan, seat usage,
// computed status and the issued-document marker (doc status).
func licenceView(lic dbq.Licence, seats int64, now time.Time) map[string]any {
	return map[string]any{
		"id":            lic.ID,
		"org_id":        lic.OrgID,
		"licence_key":   lic.LicenceKey,
		"kind":          lic.Kind,
		"plan":          lic.Plan,
		"max_instances": lic.MaxInstances,
		"seats_used":    seats,
		"status":        licenceStatus(lic, now),
		"doc_issued":    lic.DocHash.Valid,
		"doc_hash":      docHash(lic),
		"issued_at":     lic.IssuedAt,
		"expires_at":    lic.ExpiresAt,
		"revoked_at":    lic.RevokedAt,
	}
}

// licenceStatus computes the displayed state: revoked wins over expired.
func licenceStatus(lic dbq.Licence, now time.Time) string {
	switch {
	case lic.RevokedAt != nil:
		return "revoked"
	case lic.ExpiresAt != nil && !lic.ExpiresAt.After(now):
		return "expired"
	default:
		return "active"
	}
}

// docHash renders the stored document hash as hex for display.
func docHash(lic dbq.Licence) string {
	if !lic.DocHash.Valid {
		return ""
	}
	return hex.EncodeToString([]byte(lic.DocHash.String))
}

// instanceView is the customer-facing appliance row.
func instanceView(inst dbq.Instance, licenceKey string) map[string]any {
	return map[string]any{
		"id":                inst.ID,
		"org_id":            inst.OrgID,
		"licence_id":        nullable(inst.LicenceID),
		"licence_key":       licenceKey,
		"name":              inst.Name,
		"instance_id":       inst.Fingerprint,
		"appliance_version": inst.ApplianceVersion,
		"status":            inst.Status,
		"suspected_clone":   inst.SuspectedCloneAt != nil,
		"last_seen_at":      inst.LastSeenAt,
		"created_at":        inst.CreatedAt,
	}
}

func nullable(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

// listLicences handles GET /v1/licences?org_id= — the org's licences with
// seat counts and document status.
func (h *handlers) listLicences(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "org_id is required")
		return
	}
	if !h.memberOrg(w, r, orgID) {
		return
	}
	lics, err := h.q.ListLicencesByOrg(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence list failed")
		return
	}
	now := time.Now().UTC()
	out := make([]map[string]any, 0, len(lics))
	for _, lic := range lics {
		seats, err := h.q.CountLicenceInstances(r.Context(), sql.NullString{String: lic.ID, Valid: true})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "seat count failed")
			return
		}
		out = append(out, licenceView(lic, seats, now))
	}
	writeJSON(w, http.StatusOK, map[string]any{"licences": out})
}

// getLicence handles GET /v1/licences/{licenceID} — detail plus the
// appliances bound to the licence.
func (h *handlers) getLicence(w http.ResponseWriter, r *http.Request) {
	lic, ok := h.getLicenceParam(w, r)
	if !ok {
		return
	}
	seats, err := h.q.CountLicenceInstances(r.Context(), sql.NullString{String: lic.ID, Valid: true})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "seat count failed")
		return
	}
	insts, err := h.q.ListInstancesByLicence(r.Context(), sql.NullString{String: lic.ID, Valid: true})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "instance list failed")
		return
	}
	views := make([]map[string]any, 0, len(insts))
	for _, inst := range insts {
		views = append(views, instanceView(inst, lic.LicenceKey))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"licence":   licenceView(lic, seats, time.Now().UTC()),
		"instances": views,
	})
}

// listInstances handles GET /v1/instances?org_id= — the org's registered
// appliances with clone flags and licence keys.
func (h *handlers) listInstances(w http.ResponseWriter, r *http.Request) {
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "org_id is required")
		return
	}
	if !h.memberOrg(w, r, orgID) {
		return
	}
	insts, err := h.q.ListInstancesByOrg(r.Context(), orgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "instance list failed")
		return
	}
	keys, err := h.licenceKeys(r, insts)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
		return
	}
	out := make([]map[string]any, 0, len(insts))
	for _, inst := range insts {
		out = append(out, instanceView(inst, keys[inst.LicenceID.String]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"instances": out})
}

// licenceKeys maps licence_id -> licence_key for the instances' licences.
func (h *handlers) licenceKeys(r *http.Request, insts []dbq.Instance) (map[string]string, error) {
	keys := map[string]string{}
	for _, inst := range insts {
		if !inst.LicenceID.Valid || keys[inst.LicenceID.String] != "" {
			continue
		}
		lic, err := h.q.GetLicence(r.Context(), inst.LicenceID.String)
		if err != nil {
			continue // unbound/dangling reference shows an empty key
		}
		keys[inst.LicenceID.String] = lic.LicenceKey
	}
	return keys, nil
}

// getInstance handles GET /v1/instances/{instanceID} — detail plus the
// bound licence summary.
func (h *handlers) getInstance(w http.ResponseWriter, r *http.Request) {
	inst, ok := h.getInstanceParam(w, r)
	if !ok {
		return
	}
	var licView map[string]any
	if inst.LicenceID.Valid {
		if lic, err := h.q.GetLicence(r.Context(), inst.LicenceID.String); err == nil {
			seats, _ := h.q.CountLicenceInstances(r.Context(), inst.LicenceID)
			licView = licenceView(lic, seats, time.Now().UTC())
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"instance": instanceView(inst, ""),
		"licence":  licView,
	})
}

// listReports handles GET /v1/instances/{instanceID}/reports?limit= —
// the check-in history from instance_reports, newest first.
func (h *handlers) listReports(w http.ResponseWriter, r *http.Request) {
	inst, ok := h.getInstanceParam(w, r)
	if !ok {
		return
	}
	limit := queryInt(r, "limit", 50)
	if limit < 1 || limit > 200 {
		limit = 50
	}
	reports, err := h.q.ListInstanceReports(r.Context(), dbq.ListInstanceReportsParams{
		InstanceID: inst.ID, Limit: int32(limit),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "report list failed")
		return
	}
	out := make([]map[string]any, 0, len(reports))
	for _, rep := range reports {
		out = append(out, map[string]any{
			"id":          rep.ID,
			"reported_at": rep.ReportedAt,
			"payload":     json.RawMessage(rep.Payload),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out})
}

// deactivate handles POST /v1/instances/{instanceID}/deactivate: marks
// the appliance decommissioned, freeing its licence seat. Idempotent.
func (h *handlers) deactivate(w http.ResponseWriter, r *http.Request) {
	inst, ok := h.getInstanceParam(w, r)
	if !ok {
		return
	}
	if !h.writeOrg(w, r, inst.OrgID) {
		return
	}
	if err := h.q.DecommissionInstance(r.Context(), inst.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "deactivate failed")
		return
	}
	sess, _ := accounts.SessionFrom(r.Context())
	_ = audit.Write(r.Context(), h.q, audit.Entry{
		OrgID: inst.OrgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionInstanceDeact, TargetType: "instance", TargetID: inst.ID,
	})
	inst.Status = "decommissioned"
	writeJSON(w, http.StatusOK, map[string]any{"instance": instanceView(inst, "")})
}

// writeJSON writes v as the JSON response body.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeErr writes the {error, message} envelope.
func writeErr(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"error": code, "message": message})
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
