package accounts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// teamEnv is the /v1 accounts mux over a throwaway MariaDB.
type teamEnv struct {
	handler http.Handler
	db      *sql.DB
	acct    *Service
}

func newTeamEnv(t *testing.T) *teamEnv {
	t.Helper()
	db := testutil.MariaDB(t)
	acct := NewMust(db, Options{
		Secret: []byte("test-auth-secret-0123456789abcdef"), SessionTTL: time.Hour,
	})
	r := chi.NewRouter()
	r.Route("/v1", func(r chi.Router) {
		r.Mount("/", Routes(acct))
	})
	return &teamEnv{handler: r, db: db, acct: acct}
}

func (e *teamEnv) insertOrg(t *testing.T) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := e.db.Exec(`INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)`,
		id, "Org", "org-"+id[len(id)-12:]); err != nil {
		t.Fatal(err)
	}
	return id
}

// insertUser returns (userID, cookie) for a user joined to orgID.
func (e *teamEnv) insertUser(t *testing.T, orgID, role string) (string, *http.Cookie) {
	t.Helper()
	u := dbq.User{ID: uuid.Must(uuid.NewV7()).String()}
	u.Email = "user-" + u.ID[len(u.ID)-8:] + "@test.dev"
	u.PasswordHash = "x" // the cookie fingerprint must match the DB row
	if _, err := e.db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash) VALUES (?, ?, 'T', 'x')`,
		u.ID, u.Email); err != nil {
		t.Fatal(err)
	}
	if orgID != "" {
		if _, err := e.db.Exec(
			`INSERT INTO memberships (id, org_id, user_id, role) VALUES (?, ?, ?, ?)`,
			uuid.Must(uuid.NewV7()).String(), orgID, u.ID, role); err != nil {
			t.Fatal(err)
		}
	}
	token, err := e.acct.EncodeSession(Session{User: u, Stage: StageFull})
	if err != nil {
		t.Fatal(err)
	}
	return u.ID, &http.Cookie{Name: SessionCookie, Value: token}
}

func (e *teamEnv) do(t *testing.T, method, path string, body any,
	cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	return rec
}

func TestInviteAcceptRoleRemove(t *testing.T) {
	env := newTeamEnv(t)
	orgID := env.insertOrg(t)
	ownerID, owner := env.insertUser(t, orgID, "owner")
	_, viewer := env.insertUser(t, orgID, "viewer")

	// Viewers cannot invite.
	rec := env.do(t, "POST", "/v1/organisations/"+orgID+"/invites",
		map[string]any{"email": "new@test.dev", "role": "member"}, viewer)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer invite = %d, want 403", rec.Code)
	}

	// Owner invites a new user; the membership is created at once.
	rec = env.do(t, "POST", "/v1/organisations/"+orgID+"/invites",
		map[string]any{"email": "new@test.dev", "role": "member"}, owner)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite = %d: %s", rec.Code, rec.Body)
	}
	invited, err := env.acct.q.GetUserByEmail(t.Context(), "new@test.dev")
	if err != nil {
		t.Fatalf("invited user: %v", err)
	}
	var role string
	if err := env.db.QueryRow(
		`SELECT role FROM memberships WHERE org_id = ? AND user_id = ?`, orgID, invited.ID).
		Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "member" {
		t.Fatalf("invite role = %q, want member", role)
	}

	// The emailed token accepts the invite: password + display name set,
	// email verified, a full session comes back on the cookie.
	tok := env.acct.issueInviteToken(invited)
	rec = env.do(t, "POST", "/v1/auth/accept-invite", map[string]any{
		"token": tok, "password": "a very good password", "display_name": "New User",
	}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("accept = %d: %s", rec.Code, rec.Body)
	}
	var accepted struct {
		Existing bool `json:"existing"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if accepted.Existing {
		t.Fatal("fresh account should not flag existing")
	}
	var hash, name string
	var verified any
	if err := env.db.QueryRow(
		`SELECT password_hash, display_name, email_verified_at FROM users WHERE id = ?`,
		invited.ID).Scan(&hash, &name, &verified); err != nil {
		t.Fatal(err)
	}
	if hash == "" || name != "New User" || verified == nil {
		t.Fatalf("after accept: hash set=%v name=%q verified=%v", hash != "", name, verified != nil)
	}

	// Re-accept with the now-credentialled account is a no-op.
	rec = env.do(t, "POST", "/v1/auth/accept-invite",
		map[string]any{"token": tok}, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("re-accept = %d", rec.Code)
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &accepted); err != nil {
		t.Fatal(err)
	}
	if !accepted.Existing {
		t.Fatal("second accept should flag existing")
	}
	var n int
	if err := env.db.QueryRow(
		`SELECT COUNT(*) FROM memberships WHERE org_id = ? AND user_id = ?`, orgID, invited.ID).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("memberships = %d, want 1", n)
	}

	// Role change: member -> admin by owner.
	rec = env.do(t, "PATCH", "/v1/organisations/"+orgID+"/members/"+invited.ID,
		map[string]any{"role": "admin"}, owner)
	if rec.Code != http.StatusOK {
		t.Fatalf("set role = %d: %s", rec.Code, rec.Body)
	}
	if err := env.db.QueryRow(
		`SELECT role FROM memberships WHERE org_id = ? AND user_id = ?`, orgID, invited.ID).
		Scan(&role); err != nil {
		t.Fatal(err)
	}
	if role != "admin" {
		t.Fatalf("role = %q, want admin", role)
	}

	// Last owner cannot demote themself (conflict).
	rec = env.do(t, "PATCH", "/v1/organisations/"+orgID+"/members/"+ownerID,
		map[string]any{"role": "member"}, owner)
	if rec.Code != http.StatusConflict {
		t.Fatalf("last-owner demotion = %d, want 409", rec.Code)
	}

	// Remove the (now admin) member; last-owner removal must fail.
	rec = env.do(t, "DELETE", "/v1/organisations/"+orgID+"/members/"+invited.ID, nil, owner)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("remove = %d: %s", rec.Code, rec.Body)
	}
	rec = env.do(t, "DELETE", "/v1/organisations/"+orgID+"/members/"+ownerID, nil, owner)
	if rec.Code != http.StatusConflict {
		t.Fatalf("remove last owner = %d, want 409", rec.Code)
	}
}

func TestInviteExistingMemberRejected(t *testing.T) {
	env := newTeamEnv(t)
	orgID := env.insertOrg(t)
	ownerID, owner := env.insertUser(t, orgID, "owner")
	var ownerEmail string
	if err := env.db.QueryRow(`SELECT email FROM users WHERE id = ?`, ownerID).
		Scan(&ownerEmail); err != nil {
		t.Fatal(err)
	}
	rec := env.do(t, "POST", "/v1/organisations/"+orgID+"/invites",
		map[string]any{"email": ownerEmail, "role": "member"}, owner)
	if rec.Code != http.StatusConflict {
		t.Fatalf("re-invite member = %d, want 409", rec.Code)
	}
}

func TestForgedInviteTokenRejected(t *testing.T) {
	env := newTeamEnv(t)
	rec := env.do(t, "POST", "/v1/auth/accept-invite",
		map[string]any{"token": "bogus.token", "password": "a very good password"}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged token = %d, want 400", rec.Code)
	}
}

func TestNotificationPrefs(t *testing.T) {
	env := newTeamEnv(t)
	orgID := env.insertOrg(t)
	_, cookie := env.insertUser(t, orgID, "member")

	// Defaults (no row): everything on.
	rec := env.do(t, "GET", "/v1/organisations/"+orgID+"/notification-prefs", nil, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("get prefs = %d", rec.Code)
	}
	var p struct {
		Prefs NotificationPrefs `json:"prefs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Prefs.VersionBehind || !p.Prefs.SecurityRelease ||
		!p.Prefs.LicenceExpiry || !p.Prefs.Billing {
		t.Fatalf("default prefs = %+v, want all true", p.Prefs)
	}

	rec = env.do(t, "PUT", "/v1/organisations/"+orgID+"/notification-prefs",
		map[string]bool{
			"notify_version_behind": true, "notify_security_release": false,
			"notify_licence_expiry": false, "notify_billing": false,
		}, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("put prefs = %d: %s", rec.Code, rec.Body)
	}
	rec = env.do(t, "GET", "/v1/organisations/"+orgID+"/notification-prefs", nil, cookie)
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Prefs.SecurityRelease || p.Prefs.LicenceExpiry || !p.Prefs.VersionBehind {
		t.Fatalf("saved prefs = %+v", p.Prefs)
	}
	// Billing mail is never opt-out — forced back on by SetNotificationPrefs.
	if !p.Prefs.Billing {
		t.Fatal("billing pref should be forced on")
	}

	// Cross-org access is rejected.
	other := env.insertOrg(t)
	rec = env.do(t, "GET", "/v1/organisations/"+other+"/notification-prefs", nil, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org prefs = %d, want 403", rec.Code)
	}
}

func TestMemberListAndOrgDetailShape(t *testing.T) {
	env := newTeamEnv(t)
	orgID := env.insertOrg(t)
	_, cookie := env.insertUser(t, orgID, "member")

	rec := env.do(t, "GET", "/v1/organisations/"+orgID+"/members", nil, cookie)
	var members struct {
		Members []map[string]any `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &members); err != nil {
		t.Fatalf("members: %v %s", err, rec.Body)
	}
	if len(members.Members) != 1 || members.Members[0]["email"] == nil ||
		members.Members[0]["role"] != "member" {
		t.Fatalf("members = %v", members)
	}
	if _, has := members.Members[0]["Email"]; has {
		t.Fatalf("snake_case keys expected: %v", members)
	}

	rec = env.do(t, "GET", "/v1/organisations/"+orgID, nil, cookie)
	var det struct {
		Org struct {
			ID   string `json:"id"`
			Slug string `json:"slug"`
		} `json:"org"`
		Role string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &det); err != nil {
		t.Fatalf("org detail: %v %s", err, rec.Body)
	}
	if det.Org.ID != orgID || det.Role != "member" {
		t.Fatalf("org detail = %+v", det)
	}
}
