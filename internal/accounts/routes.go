package accounts

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// Routes returns the accounts/organisations handler. It is mounted at the
// /v1 root (a single r.Mount line in internal/httpapi) and owns the
// /auth/* and /organisations* paths beneath it.
func Routes(s *Service) http.Handler {
	r := chi.NewRouter()
	r.Use(s.SessionMiddleware())

	// Public endpoints.
	r.Get("/auth/altcha", s.handleAltcha)
	r.Post("/auth/signup", s.handleSignup)
	r.Post("/auth/login", s.handleLogin)
	r.Post("/auth/logout", s.handleLogout)
	r.Get("/auth/verify-email", s.handleVerifyEmail)

	// Pending-stage endpoints (TOTP challenge finishers).
	r.Group(func(r chi.Router) {
		r.Use(RequirePending)
		r.Post("/auth/login/totp", s.handleLoginTOTP)
	})

	// Any-stage endpoints: pending sessions need /me and TOTP enrolment
	// (owners enrol before their session reaches StageFull).
	r.Group(func(r chi.Router) {
		r.Use(RequireSession)
		r.Get("/auth/me", s.handleMe)
		r.Post("/auth/resend-verification", s.handleResendVerification)
		r.Post("/auth/totp/setup", s.handleTOTPSetup)
		r.Post("/auth/totp/enable", s.handleTOTPEnable)
	})

	// Fully authenticated endpoints.
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth)
		r.Post("/auth/totp/disable", s.handleTOTPDisable)
		r.Get("/organisations", s.handleListOrgs)
		r.Get("/organisations/{orgID}", s.handleGetOrg)
		r.Get("/organisations/{orgID}/members", s.handleListMembers)
	})
	return r
}

// --- helpers ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]string{"error": code, "message": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON body")
		return false
	}
	return true
}

// clientIP returns the request's client IP for audit entries (direct
// peer only — the portal does not trust forwarded headers by default).
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// apiErr maps domain errors to HTTP responses.
func apiErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrEmailTaken):
		writeError(w, http.StatusConflict, "email_taken", err.Error())
	case errors.Is(err, ErrBadCredentials):
		writeError(w, http.StatusUnauthorized, "bad_credentials", err.Error())
	case errors.Is(err, ErrCaptchaFailed):
		writeError(w, http.StatusForbidden, "captcha_failed", err.Error())
	case errors.Is(err, ErrBadToken):
		writeError(w, http.StatusBadRequest, "bad_token", err.Error())
	case errors.Is(err, ErrBadTOTP):
		writeError(w, http.StatusUnauthorized, "bad_totp", err.Error())
	case errors.Is(err, ErrTOTPMissing), errors.Is(err, ErrTOTPRequiredOwner):
		writeError(w, http.StatusConflict, "totp_state", err.Error())
	case errors.Is(err, ErrValidation):
		writeError(w, http.StatusBadRequest, "validation", err.Error())
	case errors.Is(err, ErrForbidden):
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// publicUser is the user object handed to clients (no credential fields).
func publicUser(u dbq.User) map[string]any {
	return map[string]any{
		"id":           u.ID,
		"email":        u.Email,
		"display_name": u.DisplayName,
		"totp_enabled": u.TotpEnabled,
	}
}

// --- public auth endpoints --------------------------------------------

func (s *Service) handleAltcha(w http.ResponseWriter, r *http.Request) {
	if !s.CaptchaEnabled() {
		writeError(w, http.StatusNotFound, "captcha_disabled", "ALTCHA is not configured")
		return
	}
	ch, err := s.newChallenge()
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ch)
}

func (s *Service) handleSignup(w http.ResponseWriter, r *http.Request) {
	var in SignupInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.IP = clientIP(r)
	res, err := s.Signup(r.Context(), in)
	if err != nil {
		apiErr(w, err)
		return
	}
	s.setSessionCookie(w, mustEncode(s, res.Session), res.Session.Expires)
	writeJSON(w, http.StatusCreated, map[string]any{
		"status": string(res.Session.Stage),
		"user":   publicUser(res.User),
		"org": map[string]any{
			"id": res.Org.ID, "name": res.Org.Name, "slug": res.Org.Slug,
		},
	})
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in LoginInput
	if !decodeJSON(w, r, &in) {
		return
	}
	in.IP = clientIP(r)
	res, err := s.Login(r.Context(), in)
	if err != nil {
		apiErr(w, err)
		return
	}
	s.setSessionCookie(w, mustEncode(s, res.Session), res.Session.Expires)
	status := "ok"
	if res.Session.Stage == StagePendingTOTP {
		status = "totp_required"
	} else if res.Session.Stage == StagePendingSetup {
		status = "totp_setup_required"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": status,
		"user":   publicUser(res.User),
	})
}

// mustEncode returns the cookie value for sess (encoding cannot fail with
// a JSON-serialisable payload; an empty value is still safe).
func mustEncode(s *Service, sess Session) string {
	token, _ := s.EncodeSession(sess)
	return token
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	if sess, ok := SessionFrom(r.Context()); ok {
		s.logAudit(r, sess, "auth.logout", "user", sess.User.ID, nil)
	}
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	if err := s.VerifyEmail(r.Context(), r.URL.Query().Get("token"), clientIP(r)); err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// logAudit appends an audit entry for the session user, ignoring errors.
func (s *Service) logAudit(r *http.Request, sess Session, action, targetType, targetID string, detail any) {
	_ = s.audit(r.Context(), sess, action, targetType, targetID, detail, clientIP(r))
}

// --- pending-stage endpoints -------------------------------------------

func (s *Service) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	full, err := s.CompleteTOTPLogin(r.Context(), sess, strings.TrimSpace(in.Code), clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	s.setSessionCookie(w, mustEncode(s, full), full.Expires)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "user": publicUser(sess.User)})
}

// --- authenticated endpoints --------------------------------------------

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	verified, _ := s.EmailVerified(r.Context(), sess.User.ID)
	orgs, err := s.ListOrgs(r.Context(), sess.User.ID)
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":           publicUser(sess.User),
		"email_verified": verified,
		"organisations":  orgs,
	})
}

func (s *Service) handleResendVerification(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	if err := s.ResendVerification(r.Context(), sess); err != nil {
		apiErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	uri, secret, err := s.TOTPSetup(r.Context(), sess)
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"provisioning_uri": uri,
		"secret":           secret,
	})
}

func (s *Service) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	full, err := s.TOTPEnable(r.Context(), sess, strings.TrimSpace(in.Code), clientIP(r))
	if err != nil {
		apiErr(w, err)
		return
	}
	s.setSessionCookie(w, mustEncode(s, full), full.Expires)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Service) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	var in struct {
		Code string `json:"code"`
	}
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.TOTPDisable(r.Context(), sess, strings.TrimSpace(in.Code), clientIP(r)); err != nil {
		apiErr(w, err)
		return
	}
	s.clearSessionCookie(w) // fingerprint changed: force re-login
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleListOrgs(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	orgs, err := s.ListOrgs(r.Context(), sess.User.ID)
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"organisations": orgs})
}

func (s *Service) handleGetOrg(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	d, err := s.GetOrg(r.Context(), sess.User.ID, chi.URLParam(r, "orgID"))
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Service) handleListMembers(w http.ResponseWriter, r *http.Request) {
	sess, _ := SessionFrom(r.Context())
	orgID := chi.URLParam(r, "orgID")
	if _, err := s.RequireOrgRole(r.Context(), sess.User.ID, orgID, RoleOwner, RoleAdmin, RoleMember, RoleViewer); err != nil {
		apiErr(w, err)
		return
	}
	members, err := s.q.ListOrgMembers(r.Context(), orgID)
	if err != nil {
		apiErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"members": members})
}
