// HTTP handlers for the licensing endpoints — activation, check-in,
// licence retrieval and offline (air-gapped) activation. The request and
// response shapes are the appliance contract documented in
// docs/fakeportal.md.
package licensing

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
)

// apiMessage is one entry of the check-in "messages" array: a machine
// code plus human-readable text.
type apiMessage struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type activationRequest struct {
	LicenceKey       string `json:"licence_key"`
	InstanceID       string `json:"instance_id"`
	PublicKey        string `json:"public_key"`
	Name             string `json:"name"`
	ApplianceVersion string `json:"appliance_version"`
}

type instanceView struct {
	ID             string `json:"id"`
	InstanceID     string `json:"instance_id"`
	Name           string `json:"name"`
	Status         string `json:"status"`
	SuspectedClone bool   `json:"suspected_clone"`
}

type aptView struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// activate handles POST /v1/activations: licence-key credential +
// appliance identity -> registered instance, signed licence document and
// apt credentials.
func (s *service) activate(w http.ResponseWriter, r *http.Request) {
	var req activationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	pub, err := req.validate()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	lic, code, errCode, msg, ok := s.usableLicence(r, req.LicenceKey)
	if !ok {
		writeErr(w, code, errCode, msg)
		return
	}
	inst, clone, err := registerInstance(r.Context(), s.q, s.keys, lic,
		req.InstanceID, req.Name, req.ApplianceVersion, pub)
	if err != nil {
		if errors.Is(err, ErrSeatLimit) {
			writeErr(w, http.StatusConflict, "seat_limit",
				fmt.Sprintf("licence allows %d instance(s)", lic.MaxInstances))
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal", "activation failed")
		return
	}
	doc, err := issueDocument(r.Context(), s.q, s.issuer, lic, inst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence document failed")
		return
	}
	user, pass, err := aptCredentials(r.Context(), s.q, lic, inst, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "apt credentials failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"instance":        s.instanceView(r, inst, clone),
		"licence":         json.RawMessage(doc),
		"apt_credentials": aptView{Username: user, Password: pass},
	})
}

func (req activationRequest) validate() (ed25519.PublicKey, error) {
	if req.LicenceKey == "" {
		return nil, errors.New("licence_key is required")
	}
	if req.InstanceID == "" || len(req.InstanceID) > 128 {
		return nil, errors.New("instance_id is required (max 128 chars)")
	}
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("public_key must be a base64 Ed25519 public key")
	}
	if len(req.Name) > 200 || len(req.ApplianceVersion) > 64 {
		return nil, errors.New("name or appliance_version too long")
	}
	return ed25519.PublicKey(pub), nil
}

// usableLicence resolves and validates the licence key, writing nothing.
// On failure it returns the HTTP status, error code and message for the
// response envelope.
func (s *service) usableLicence(r *http.Request, key string) (lic dbq.Licence, status int, errCode, msg string, ok bool) {
	lic, err := s.q.GetLicenceByKey(r.Context(), key)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return lic, http.StatusNotFound, "unknown_licence_key", "unknown licence key", false
		}
		return lic, http.StatusInternalServerError, "internal", "licence lookup failed", false
	}
	switch licenceProblem(lic, s.now()) {
	case "revoked":
		return lic, http.StatusForbidden, "licence_revoked", "licence is revoked", false
	case "expired":
		return lic, http.StatusForbidden, "licence_expired", "licence has expired", false
	}
	return lic, 0, "", "", true
}

// checkIn handles POST /v1/check-ins (instance-authed): records the
// appliance report and returns licence state, status, messages and the
// latest published release.
func (s *service) checkIn(w http.ResponseWriter, r *http.Request) {
	inst, _ := instauth.InstanceFrom(r.Context())

	var report struct {
		ApplianceVersion string     `json:"appliance_version"`
		ReportedAt       *time.Time `json:"reported_at"`
	}
	body, err := readBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	// Tolerate an empty body; a malformed one is a 400. The raw payload is
	// stored verbatim on instance_reports.
	payload := json.RawMessage(`{}`)
	if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
		if err := json.Unmarshal(trimmed, &report); err != nil {
			writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
			return
		}
		payload = trimmed
	}
	reportedAt := s.now()
	if report.ReportedAt != nil {
		reportedAt = report.ReportedAt.UTC()
	}
	if err := s.q.InsertInstanceReport(r.Context(), dbq.InsertInstanceReportParams{
		ID:         newID(),
		InstanceID: inst.ID,
		ReportedAt: reportedAt,
		Payload:    payload,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "report failed")
		return
	}
	if err := s.q.TouchInstance(r.Context(), dbq.TouchInstanceParams{
		ApplianceVersion: report.ApplianceVersion,
		ID:               inst.ID,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "instance update failed")
		return
	}
	inst.ApplianceVersion = firstNonEmpty(report.ApplianceVersion, inst.ApplianceVersion)
	s.respondWithLicenceState(w, r, inst, true)
}

// getLicence handles GET /v1/licence (instance-authed): the current
// licence document plus status — no report is recorded.
func (s *service) getLicence(w http.ResponseWriter, r *http.Request) {
	inst, _ := instauth.InstanceFrom(r.Context())
	s.respondWithLicenceState(w, r, inst, false)
}

// respondWithLicenceState is the shared check-in/licence response: a
// freshly signed document, computed status, messages and (for check-ins)
// the latest release and update entitlement.
func (s *service) respondWithLicenceState(w http.ResponseWriter, r *http.Request, inst dbq.Instance, withRelease bool) {
	ctx := r.Context()
	var lic dbq.Licence
	if inst.LicenceID.Valid {
		var err error
		lic, err = s.q.GetLicence(ctx, inst.LicenceID.String)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			writeErr(w, http.StatusInternalServerError, "internal", "licence lookup failed")
			return
		}
	}
	status, messages := s.statusAndMessages(ctx, inst, lic)

	var doc json.RawMessage
	if lic.ID != "" && licenceProblem(lic, s.now()) == "" {
		var err error
		doc, err = issueDocument(ctx, s.q, s.issuer, lic, inst)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal", "licence document failed")
			return
		}
	}
	resp := map[string]any{
		"status":   status,
		"licence":  doc,
		"messages": messages,
	}
	if withRelease {
		resp["latest_release"] = s.latestRelease(ctx)
		resp["entitled_updates"] = lic.ID != "" && licenceProblem(lic, s.now()) == ""
	}
	writeJSON(w, http.StatusOK, resp)
}

// statusAndMessages computes the reported status: suspected_clone wins
// (the durable flag set by activation's clone detection), then licence
// problems, then the instance's own status.
func (s *service) statusAndMessages(ctx context.Context, inst dbq.Instance, lic dbq.Licence) (string, []apiMessage) {
	messages := []apiMessage{}
	cloned, err := s.keys.CloneFlagged(ctx, inst.ID)
	if err == nil && cloned {
		messages = append(messages, apiMessage{
			Code:    "suspected_clone",
			Message: "a different signing key presented this instance identity; verify the appliance has not been cloned",
		})
		return "suspected_clone", messages
	}
	if lic.ID != "" {
		switch licenceProblem(lic, s.now()) {
		case "revoked":
			messages = append(messages, apiMessage{Code: "licence_revoked", Message: "licence is revoked"})
			return "revoked", messages
		case "expired":
			messages = append(messages, apiMessage{Code: "licence_expired", Message: "licence has expired"})
			return "expired", messages
		}
		if lic.ExpiresAt != nil && lic.ExpiresAt.Before(s.now().Add(30*24*time.Hour)) {
			messages = append(messages, apiMessage{
				Code:    "licence_expiring",
				Message: "licence expires within 30 days",
			})
		}
	}
	switch inst.Status {
	case "suspended":
		messages = append(messages, apiMessage{Code: "instance_suspended", Message: "instance is suspended"})
		return "suspended", messages
	case "decommissioned":
		messages = append(messages, apiMessage{Code: "instance_decommissioned", Message: "instance is decommissioned"})
		return "decommissioned", messages
	}
	return "active", messages
}

// latestRelease returns the newest published stable platform release or
// nil when none is published.
func (s *service) latestRelease(ctx context.Context) any {
	rel, err := s.q.LatestPublishedRelease(ctx, dbq.LatestPublishedReleaseParams{
		Component: "platform",
		Channel:   "stable",
	})
	if err != nil {
		return nil
	}
	return map[string]any{
		"version":          rel.Version,
		"channel":          rel.Channel,
		"published_at":     rel.PublishedAt,
		"security":         rel.Security,
		"min_upgrade_from": rel.MinUpgradeFrom,
	}
}

// offlineActivate handles POST /v1/offline/activations: a customer-facing
// flow producing a downloadable signed licence bundle for air-gapped
// appliances.
//
// CUSTOMER AUTH STUB: there is no portal session auth yet (the accounts
// wave owns it). Until then the credential is the licence_key plus its
// org_id — the handler verifies the pair matches. Replace with the real
// session/org-membership middleware when that wave lands.
func (s *service) offlineActivate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID            string `json:"org_id"`
		LicenceKey       string `json:"licence_key"`
		InstanceID       string `json:"instance_id"`
		PublicKey        string `json:"public_key"` // optional: bound when present
		Name             string `json:"name"`
		ApplianceVersion string `json:"appliance_version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "request body is not valid JSON")
		return
	}
	var pub ed25519.PublicKey
	if req.PublicKey != "" {
		raw, err := base64.StdEncoding.DecodeString(req.PublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			writeErr(w, http.StatusBadRequest, "bad_request", "public_key must be a base64 Ed25519 public key")
			return
		}
		pub = ed25519.PublicKey(raw)
	}
	if req.OrgID == "" || req.InstanceID == "" || len(req.InstanceID) > 128 {
		writeErr(w, http.StatusBadRequest, "bad_request", "org_id and instance_id are required")
		return
	}
	lic, code, errCode, msg, ok := s.usableLicence(r, req.LicenceKey)
	if !ok {
		writeErr(w, code, errCode, msg)
		return
	}
	// Stub "org membership" check: the presented org must own the licence.
	if lic.OrgID != req.OrgID {
		writeErr(w, http.StatusForbidden, "forbidden", "licence does not belong to this organisation")
		return
	}
	inst, clone, err := registerInstance(r.Context(), s.q, s.keys, lic,
		req.InstanceID, req.Name, req.ApplianceVersion, pub)
	if err != nil {
		if errors.Is(err, ErrSeatLimit) {
			writeErr(w, http.StatusConflict, "seat_limit",
				fmt.Sprintf("licence allows %d instance(s)", lic.MaxInstances))
			return
		}
		writeErr(w, http.StatusInternalServerError, "internal", "activation failed")
		return
	}
	doc, err := issueDocument(r.Context(), s.q, s.issuer, lic, inst)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "licence document failed")
		return
	}
	user, pass, err := aptCredentials(r.Context(), s.q, lic, inst, s.now())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "apt credentials failed")
		return
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="serverperch-licence-%s.json"`, inst.Fingerprint))
	writeJSON(w, http.StatusCreated, map[string]any{
		"bundle_version":    1,
		"instance":          s.instanceView(r, inst, clone),
		"licence":           json.RawMessage(doc),
		"verification_keys": s.issuer.VerificationKeys(),
		"apt_credentials":   aptView{Username: user, Password: pass},
	})
}

func (s *service) instanceView(r *http.Request, inst dbq.Instance, clone bool) instanceView {
	if !clone {
		if flagged, err := s.keys.CloneFlagged(r.Context(), inst.ID); err == nil {
			clone = flagged
		}
	}
	status := inst.Status
	if clone {
		status = "suspected_clone"
	}
	return instanceView{
		ID:             inst.ID,
		InstanceID:     inst.Fingerprint,
		Name:           inst.Name,
		Status:         status,
		SuspectedClone: clone,
	}
}

// readBody returns the full request body (bounded — the auth middleware
// already capped it at 1MiB for authed routes).
func readBody(r *http.Request) ([]byte, error) {
	var buf []byte
	if r.Body == nil {
		return nil, nil
	}
	buf, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
