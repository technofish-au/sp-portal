package accounts

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// SessionCookie is the httpOnly session cookie name.
const SessionCookie = "sp_portal_session"

// Stage is how far through authentication a session is. Owners must
// complete TOTP (enrolment when not yet enabled, verification when it is)
// before their session reaches StageFull; members without TOTP go
// straight to StageFull.
type Stage string

// Session stages.
const (
	StagePendingTOTP  Stage = "totp"  // password verified, TOTP code outstanding
	StagePendingSetup Stage = "setup" // password verified, TOTP enrolment required (owner without TOTP)
	StageFull         Stage = "full"  // fully authenticated
)

// Session is the decoded, verified session cookie.
type Session struct {
	User    dbq.User
	Stage   Stage
	ID      string
	Expires time.Time
}

// EncodeSession mints the cookie value for an existing Session (used by
// handlers after a stage upgrade, and by tests).
func (s *Service) EncodeSession(sess Session) (string, error) {
	_, token, err := s.newSessionToken(sess.User, sess.Stage)
	return token, err
}

// Full reports whether the session is fully authenticated.
func (s Session) Full() bool { return s.Stage == StageFull }

// sessionPayload is the signed JSON inside the cookie.
type sessionPayload struct {
	UID   string `json:"u"`
	Stage Stage  `json:"s"`
	Exp   int64  `json:"e"`
	SID   string `json:"i"`
}

var errBadSession = errors.New("invalid session")

// fingerprint binds a session to the user's credential state so password
// changes, TOTP changes, email changes and disablement invalidate all
// outstanding cookies (there is no server-side session table).
func fingerprint(u dbq.User) []byte {
	h := sha256.New()
	h.Write([]byte(u.Email))
	h.Write([]byte{0})
	h.Write([]byte(u.PasswordHash))
	h.Write([]byte{0})
	if u.TotpEnabled {
		h.Write([]byte{1})
	}
	h.Write([]byte{0})
	if u.DisabledAt != nil {
		h.Write([]byte{1})
	}
	return h.Sum(nil)
}

// newSessionToken mints the signed cookie value for u at stage.
func (s *Service) newSessionToken(u dbq.User, stage Stage) (Session, string, error) {
	exp := s.now().Add(s.ttl)
	p := sessionPayload{UID: u.ID, Stage: stage, Exp: exp.Unix(), SID: uuid.Must(uuid.NewV7()).String()}
	raw, err := json.Marshal(p)
	if err != nil {
		return Session{}, "", err
	}
	body := base64.RawURLEncoding.EncodeToString(raw)
	sig := s.sign("sess", []byte(body), fingerprint(u))
	return Session{User: u, Stage: stage, ID: p.SID, Expires: exp}, body + "." + sig, nil
}

// verifySessionToken validates a cookie value against the current user
// row (fingerprint check) and expiry.
func (s *Service) verifySessionToken(value string, u dbq.User) (Session, error) {
	body, sig, ok := cut(value, '.')
	if !ok {
		return Session{}, errBadSession
	}
	want := s.sign("sess", []byte(body), fingerprint(u))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return Session{}, errBadSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, errBadSession
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Session{}, errBadSession
	}
	if p.UID != u.ID || u.DisabledAt != nil {
		return Session{}, errBadSession
	}
	exp := time.Unix(p.Exp, 0)
	if !exp.After(s.now()) {
		return Session{}, errBadSession
	}
	return Session{User: u, Stage: p.Stage, ID: p.SID, Expires: exp}, nil
}

// sign returns the base64url HMAC-SHA256 of the labelled parts.
func (s *Service) sign(label string, parts ...[]byte) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte("sp-portal\x00" + label + "\x00"))
	for _, p := range parts {
		mac.Write(p)
		mac.Write([]byte{0})
	}
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// cut splits s at the first sep (like strings.Cut for bytes-free callers).
func cut(s string, sep byte) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// setSessionCookie writes the session cookie; clearSessionCookie expires it.
func (s *Service) setSessionCookie(w http.ResponseWriter, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// ctxKey is the context key for the request's Session.
type ctxKey struct{}

// SessionFrom returns the request's session and true when one is present.
func SessionFrom(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(ctxKey{}).(Session)
	return s, ok
}

// SessionMiddleware resolves the session cookie to a Session on every
// request it wraps (public endpoints included — handlers decide whether
// they require it). It refreshes nothing; expired or invalid cookies
// simply yield no session.
func (s *Service) SessionMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if c, err := r.Cookie(SessionCookie); err == nil {
				if sess, serr := s.resolveSession(r.Context(), c.Value); serr == nil {
					r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// resolveSession reads the uid out of the cookie body, loads the user and
// verifies the signature/fingerprint against the current row.
func (s *Service) resolveSession(ctx context.Context, value string) (Session, error) {
	body, _, ok := cut(value, '.')
	if !ok {
		return Session{}, errBadSession
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return Session{}, errBadSession
	}
	var p sessionPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Session{}, errBadSession
	}
	u, err := s.q.GetUser(ctx, p.UID)
	if err != nil {
		return Session{}, errBadSession
	}
	return s.verifySessionToken(value, u)
}

// RequireAuth returns middleware that rejects requests without a StageFull
// session with 401 (or 403 when a pending-stage session needs a different
// step — the client uses "stage" to route to the right screen).
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "not_authenticated", "sign-in required")
			return
		}
		if !sess.Full() {
			writeError(w, http.StatusForbidden, "auth_incomplete", fmt.Sprintf("session pending %s", sess.Stage))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession accepts a session at any stage (it just must exist).
// TOTP enrolment and /auth/me hang off it — pending users need them.
func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := SessionFrom(r.Context()); !ok {
			writeError(w, http.StatusUnauthorized, "not_authenticated", "sign-in required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequirePending allows only pending-stage sessions (TOTP challenge and
// enrolment endpoints); everything else is 401/403.
func RequirePending(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := SessionFrom(r.Context())
		if !ok {
			writeError(w, http.StatusUnauthorized, "not_authenticated", "sign-in required")
			return
		}
		if sess.Full() {
			writeError(w, http.StatusForbidden, "already_authenticated", "session already complete")
			return
		}
		next.ServeHTTP(w, r)
	})
}
