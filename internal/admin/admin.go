// Package admin is the staff back-office API (is_platform_admin sessions
// with TOTP): cross-tenant org/user/licence/instance search, licence ops
// (issue, revoke, reissue), the fleet estate view and audit-log browsing.
// Release-catalogue admin lives in internal/releases; both mount under
// /v1/admin — chi merges the paths on one mux.
package admin

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// licenceKeyPfx prefixes staff-issued licence keys (trial keys are SPTL-).
const licenceKeyPfx = "SPL-"

// searchLimit caps each section of the combined search response.
const searchLimit = 20

// service carries the handlers' dependencies.
type service struct {
	db   *sql.DB
	q    *dbq.Queries
	acct *accounts.Service
}

// Routes returns the domain handler for standalone use (tests); Mount
// registers the same paths on the /v1 mux.
func Routes(db *sql.DB, acct *accounts.Service) http.Handler {
	r := chi.NewRouter()
	Mount(r, db, acct)
	return r
}

// Mount registers the domain's /v1/admin routes directly on r — same
// pattern as internal/licensing (accounts holds the /v1 root mount).
//
//	GET  /admin/search                     ?q=
//	GET  /admin/organisations/{orgID}
//	POST /admin/licences
//	POST /admin/licences/{licenceID}/revoke
//	POST /admin/licences/{licenceID}/reissue
//	GET  /admin/estate
//	GET  /admin/audit-log                  ?org_id&limit&offset
func Mount(r chi.Router, db *sql.DB, acct *accounts.Service) {
	s := &service{db: db, q: dbq.New(db), acct: acct}
	r.Group(func(r chi.Router) {
		r.Use(acct.SessionMiddleware())
		r.Use(accounts.RequireStaff)
		r.Get("/admin/search", s.search)
		r.Get("/admin/organisations/{orgID}", s.orgDetail)
		r.Post("/admin/licences", s.issueLicence)
		r.Post("/admin/licences/{licenceID}/revoke", s.revokeLicence)
		r.Post("/admin/licences/{licenceID}/reissue", s.reissueLicence)
		r.Get("/admin/estate", s.estate)
		r.Get("/admin/audit-log", s.auditLog)
	})
}

// --- views ---------------------------------------------------------------

func orgView(o dbq.Organisation) map[string]any {
	return map[string]any{
		"id":                 o.ID,
		"name":               o.Name,
		"slug":               o.Slug,
		"billing_email":      o.BillingEmail,
		"tax_id":             o.TaxID,
		"stripe_customer_id": nullable(o.StripeCustomerID),
		"created_at":         o.CreatedAt,
	}
}

// userView scrubs credential fields — staff never see hashes or TOTP
// secrets.
func userView(u dbq.User) map[string]any {
	return map[string]any{
		"id":                u.ID,
		"email":             u.Email,
		"display_name":      u.DisplayName,
		"is_platform_admin": u.IsPlatformAdmin,
		"totp_enabled":      u.TotpEnabled,
		"email_verified":    u.EmailVerifiedAt != nil,
		"disabled_at":       u.DisabledAt,
		"created_at":        u.CreatedAt,
	}
}

func licenceView(lic dbq.Licence, seats int64, now time.Time) map[string]any {
	status := "active"
	switch {
	case lic.RevokedAt != nil:
		status = "revoked"
	case lic.ExpiresAt != nil && !lic.ExpiresAt.After(now):
		status = "expired"
	}
	return map[string]any{
		"id":            lic.ID,
		"org_id":        lic.OrgID,
		"licence_key":   lic.LicenceKey,
		"kind":          lic.Kind,
		"plan":          lic.Plan,
		"max_instances": lic.MaxInstances,
		"seats_used":    seats,
		"status":        status,
		"doc_issued":    lic.DocHash.Valid,
		"doc_hash":      docHash(lic),
		"issued_at":     lic.IssuedAt,
		"expires_at":    lic.ExpiresAt,
		"revoked_at":    lic.RevokedAt,
	}
}

func docHash(lic dbq.Licence) string {
	if !lic.DocHash.Valid {
		return ""
	}
	return hex.EncodeToString([]byte(lic.DocHash.String))
}

func instanceView(inst dbq.Instance) map[string]any {
	return map[string]any{
		"id":                inst.ID,
		"org_id":            inst.OrgID,
		"licence_id":        nullable(inst.LicenceID),
		"name":              inst.Name,
		"instance_id":       inst.Fingerprint,
		"appliance_version": inst.ApplianceVersion,
		"status":            inst.Status,
		"suspected_clone":   inst.SuspectedCloneAt != nil,
		"last_seen_at":      inst.LastSeenAt,
		"created_at":        inst.CreatedAt,
	}
}

func auditView(a dbq.AuditLog) map[string]any {
	return map[string]any{
		"id":            a.ID,
		"org_id":        a.OrgID,
		"actor_user_id": a.ActorUserID,
		"actor_email":   a.ActorEmail,
		"action":        a.Action,
		"target_type":   a.TargetType,
		"target_id":     a.TargetID,
		"detail":        json.RawMessage(a.Detail),
		"ip":            a.Ip,
		"created_at":    a.CreatedAt,
	}
}

func nullable(s sql.NullString) any {
	if !s.Valid {
		return nil
	}
	return s.String
}

// --- search --------------------------------------------------------------

// search handles GET /v1/admin/search?q= — substring search across orgs,
// users, licences and instances in one response (searchLimit rows each).
func (s *service) search(w http.ResponseWriter, r *http.Request) {
	term := strings.TrimSpace(r.URL.Query().Get("q"))
	if term == "" {
		writeErr(w, http.StatusBadRequest, "bad_request", "q is required")
		return
	}
	like := "%" + term + "%"
	ctx := r.Context()
	now := time.Now().UTC()

	orgs, err := s.q.SearchOrganisations(ctx, dbq.SearchOrganisationsParams{
		Name: like, Slug: like, BillingEmail: like, ID: term, Limit: searchLimit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "org search failed")
		return
	}
	users, err := s.q.SearchUsers(ctx, dbq.SearchUsersParams{
		Email: like, DisplayName: like, ID: term, Limit: searchLimit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "user search failed")
		return
	}
	lics, err := s.q.SearchLicences(ctx, dbq.SearchLicencesParams{
		LicenceKey: like, ID: term, OrgID: term, Limit: searchLimit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence search failed")
		return
	}
	insts, err := s.q.SearchInstances(ctx, dbq.SearchInstancesParams{
		Name: like, Fingerprint: like, ID: term, Limit: searchLimit,
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "instance search failed")
		return
	}

	orgViews := make([]map[string]any, 0, len(orgs))
	for _, o := range orgs {
		orgViews = append(orgViews, orgView(o))
	}
	userViews := make([]map[string]any, 0, len(users))
	for _, u := range users {
		userViews = append(userViews, userView(u))
	}
	licViews := make([]map[string]any, 0, len(lics))
	for _, l := range lics {
		licViews = append(licViews, licenceView(l, 0, now))
	}
	instViews := make([]map[string]any, 0, len(insts))
	for _, i := range insts {
		instViews = append(instViews, instanceView(i))
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"organisations": orgViews,
		"users":         userViews,
		"licences":      licViews,
		"instances":     instViews,
	})
}

// orgDetail handles GET /v1/admin/organisations/{orgID} — the staff
// drill-down: org, members, licences with seat counts, instances and the
// latest subscription.
func (s *service) orgDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	org, err := s.q.GetOrganisation(ctx, chi.URLParam(r, "orgID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such organisation")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "org lookup failed")
		}
		return
	}
	members, err := s.q.ListOrgMembers(ctx, org.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "member list failed")
		return
	}
	lics, err := s.q.ListLicencesByOrg(ctx, org.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence list failed")
		return
	}
	insts, err := s.q.ListInstancesByOrg(ctx, org.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "instance list failed")
		return
	}
	now := time.Now().UTC()
	licViews := make([]map[string]any, 0, len(lics))
	for _, lic := range lics {
		seats, _ := s.q.CountLicenceInstances(ctx, sql.NullString{String: lic.ID, Valid: true})
		licViews = append(licViews, licenceView(lic, seats, now))
	}
	instViews := make([]map[string]any, 0, len(insts))
	for _, inst := range insts {
		instViews = append(instViews, instanceView(inst))
	}
	memberViews := make([]map[string]any, 0, len(members))
	for _, m := range members {
		memberViews = append(memberViews, map[string]any{
			"id":           m.ID,
			"email":        m.Email,
			"display_name": m.DisplayName,
			"role":         m.Role,
		})
	}
	var subView any
	if sub, err := s.q.GetLatestSubscriptionByOrg(ctx, org.ID); err == nil {
		subView = map[string]any{
			"id": sub.ID, "plan": sub.Plan, "status": sub.Status,
			"seats": sub.Seats, "current_period_end": sub.CurrentPeriodEnd,
			"stripe_subscription_id": sub.StripeSubscriptionID,
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"org":          orgView(org),
		"members":      memberViews,
		"licences":     licViews,
		"instances":    instViews,
		"subscription": subView,
	})
}

// --- licence ops -----------------------------------------------------------

// issueLicence handles POST /v1/admin/licences — a manual licence for an
// org (extend trials, perpetual licences, replacements).
func (s *service) issueLicence(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OrgID        string `json:"org_id"`
		Kind         string `json:"kind"`
		Plan         string `json:"plan"`
		MaxInstances int32  `json:"max_instances"`
		ExpiresAt    string `json:"expires_at"` // RFC3339; empty = never
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if _, err := s.q.GetOrganisation(r.Context(), in.OrgID); err != nil {
		writeErr(w, http.StatusNotFound, "not_found", "no such organisation")
		return
	}
	kind, plan := in.Kind, in.Plan
	if kind == "" {
		kind = "subscription"
	}
	if plan == "" {
		plan = "pro"
	}
	switch kind {
	case "trial", "subscription", "perpetual":
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "kind must be trial, subscription or perpetual")
		return
	}
	switch plan {
	case "trial", "starter", "pro", "enterprise":
	default:
		writeErr(w, http.StatusBadRequest, "bad_request", "plan must be trial, starter, pro or enterprise")
		return
	}
	if in.MaxInstances < 1 {
		in.MaxInstances = 1
	}
	var expires *time.Time
	if in.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, in.ExpiresAt)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "expires_at must be RFC3339")
			return
		}
		expires = &t
	}
	lic := dbq.Licence{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: in.OrgID,
		LicenceKey: newLicenceKey(), Kind: kind, Plan: plan,
		MaxInstances: in.MaxInstances, IssuedAt: time.Now().UTC(), ExpiresAt: expires,
	}
	if err := s.q.CreateLicence(r.Context(), dbq.CreateLicenceParams{
		ID: lic.ID, OrgID: lic.OrgID, LicenceKey: lic.LicenceKey,
		Kind: lic.Kind, Plan: lic.Plan, MaxInstances: lic.MaxInstances,
		IssuedAt: lic.IssuedAt, ExpiresAt: lic.ExpiresAt,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence insert failed")
		return
	}
	s.logAudit(r, audit.ActionLicenceIssued, "licence", lic.ID, map[string]any{
		"org_id": in.OrgID, "kind": kind, "plan": plan, "max_instances": in.MaxInstances,
	})
	writeJSON(w, http.StatusCreated, licenceView(lic, 0, time.Now().UTC()))
}

// getLicenceParam resolves {licenceID} or writes 404.
func (s *service) getLicenceParam(w http.ResponseWriter, r *http.Request) (dbq.Licence, bool) {
	lic, err := s.q.GetLicence(r.Context(), chi.URLParam(r, "licenceID"))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusNotFound, "not_found", "no such licence")
		} else {
			writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
		}
		return lic, false
	}
	return lic, true
}

// revokeLicence handles POST /v1/admin/licences/{id}/revoke (idempotent —
// the first revoke time stands).
func (s *service) revokeLicence(w http.ResponseWriter, r *http.Request) {
	lic, ok := s.getLicenceParam(w, r)
	if !ok {
		return
	}
	if lic.RevokedAt != nil {
		writeJSON(w, http.StatusOK, licenceView(lic, 0, time.Now().UTC()))
		return
	}
	if err := s.q.RevokeLicence(r.Context(), lic.ID); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "revoke failed")
		return
	}
	s.logAudit(r, audit.ActionLicenceRevoked, "licence", lic.ID,
		map[string]any{"org_id": lic.OrgID, "licence_key": lic.LicenceKey})
	lic, _ = s.getLicenceParam(w, r)
	writeJSON(w, http.StatusOK, licenceView(lic, 0, time.Now().UTC()))
}

// reissueLicence handles POST /v1/admin/licences/{id}/reissue: mints a
// replacement licence (fresh key, same org/kind/plan/seats/expiry) and
// revokes the original in one transaction — the swap customers get when
// a key leaks.
func (s *service) reissueLicence(w http.ResponseWriter, r *http.Request) {
	old, ok := s.getLicenceParam(w, r)
	if !ok {
		return
	}
	fresh := dbq.Licence{
		ID: uuid.Must(uuid.NewV7()).String(), OrgID: old.OrgID,
		SubscriptionID: old.SubscriptionID,
		LicenceKey:     newLicenceKey(), Kind: old.Kind, Plan: old.Plan,
		MaxInstances: old.MaxInstances, IssuedAt: time.Now().UTC(),
		ExpiresAt: old.ExpiresAt,
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "reissue failed")
		return
	}
	defer func() { _ = tx.Rollback() }()
	q := s.q.WithTx(tx)
	if err := q.CreateLicence(r.Context(), dbq.CreateLicenceParams{
		ID: fresh.ID, OrgID: fresh.OrgID, SubscriptionID: fresh.SubscriptionID,
		LicenceKey: fresh.LicenceKey, Kind: fresh.Kind, Plan: fresh.Plan,
		MaxInstances: fresh.MaxInstances, IssuedAt: fresh.IssuedAt,
		ExpiresAt: fresh.ExpiresAt,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "reissue failed")
		return
	}
	if old.RevokedAt == nil {
		if err := q.RevokeLicence(r.Context(), old.ID); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "reissue failed")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "reissue failed")
		return
	}
	s.logAudit(r, audit.ActionLicenceReissued, "licence", fresh.ID, map[string]any{
		"org_id": old.OrgID, "supersedes": old.ID, "licence_key": fresh.LicenceKey,
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"licence":    licenceView(fresh, 0, time.Now().UTC()),
		"supersedes": old.ID,
	})
}

// newLicenceKey mints a staff licence key (SPL-<32 hex-ish chars>).
func newLicenceKey() string {
	return licenceKeyPfx + strings.ToUpper(strings.ReplaceAll(uuid.Must(uuid.NewV7()).String(), "-", ""))
}

// --- estate + audit ------------------------------------------------------

// estate handles GET /v1/admin/estate — headline fleet numbers plus the
// live instance count per appliance version.
func (s *service) estate(w http.ResponseWriter, r *http.Request) {
	totals, err := s.q.EstateTotals(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "estate totals failed")
		return
	}
	versions, err := s.q.EstateVersionCounts(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "estate versions failed")
		return
	}
	versionViews := make([]map[string]any, 0, len(versions))
	for _, v := range versions {
		versionViews = append(versionViews, map[string]any{
			"appliance_version": v.ApplianceVersion,
			"instances":         v.Instances,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"totals": map[string]any{
			"organisations":    totals.Organisations,
			"users":            totals.Users,
			"live_licences":    totals.LiveLicences,
			"active_instances": totals.ActiveInstances,
			"suspected_clones": totals.SuspectedClones,
			"seen_24h":         totals.Seen24h,
			"seen_7d":          totals.Seen7d,
			"stale_7d":         totals.Stale7d,
		},
		"versions": versionViews,
	})
}

// auditLog handles GET /v1/admin/audit-log?org_id&limit&offset — the
// global audit browse (” org lists every org's entries).
func (s *service) auditLog(w http.ResponseWriter, r *http.Request) {
	org := r.URL.Query().Get("org_id")
	limit := queryInt(r, "limit", 100)
	if limit < 1 || limit > 500 {
		limit = 100
	}
	offset := queryInt(r, "offset", 0)
	if offset < 0 {
		offset = 0
	}
	rows, err := s.q.ListAuditLog(r.Context(), dbq.ListAuditLogParams{
		Column1: org,
		OrgID:   sql.NullString{String: org, Valid: org != ""},
		Limit:   int32(limit), Offset: int32(offset),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "audit list failed")
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		out = append(out, auditView(row))
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

// logAudit appends an audit_log row for the staff actor; failures are
// non-fatal (the state change already committed).
func (s *service) logAudit(r *http.Request, action, targetType, targetID string, detail any) {
	entry := audit.Entry{
		Action: action, TargetType: targetType, TargetID: targetID,
		Detail: detail, IP: clientIP(r),
	}
	if sess, ok := accounts.SessionFrom(r.Context()); ok {
		entry.ActorUserID = sess.User.ID
		entry.ActorEmail = sess.User.Email
	}
	_ = audit.Write(r.Context(), s.q, entry)
}

// clientIP returns the request's client IP for audit entries.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// decodeBody reads a small JSON request body.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "malformed JSON body")
		return false
	}
	return true
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
