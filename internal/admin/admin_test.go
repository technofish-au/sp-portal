// Integration tests for the staff back-office API (R5-5) against a real
// MariaDB (internal/testutil): search, org drill-down, licence issue/
// revoke/reissue, the estate view and the audit log.
package admin_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/admin"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

func testHandler(t *testing.T) (http.Handler, *sql.DB, *accounts.Service) {
	t.Helper()
	db := testutil.MariaDB(t)
	acct := accounts.NewMust(db, accounts.Options{
		Secret: []byte("test-auth-secret-0123456789abcdef"), SessionTTL: time.Hour,
	})
	return admin.Routes(db, acct), db, acct
}

// staffCookie mints a session cookie for an is_platform_admin user when
// admin is true, otherwise a plain customer session. RequireStaff also
// demands TOTP, so staff are created already enrolled.
func staffCookie(t *testing.T, db *sql.DB, acct *accounts.Service, admin bool) *http.Cookie {
	t.Helper()
	u := dbq.User{ID: uuid.Must(uuid.NewV7()).String()}
	u.Email = "user-" + u.ID[len(u.ID)-8:] + "@test.dev"
	u.PasswordHash = "x" // the cookie fingerprint must match the DB row
	u.IsPlatformAdmin = admin
	u.TotpEnabled = admin
	if _, err := db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash, is_platform_admin, totp_enabled)
		 VALUES (?, ?, 'Staff', 'x', ?, ?)`, u.ID, u.Email, admin, admin); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	token, err := acct.EncodeSession(accounts.Session{User: u, Stage: accounts.StageFull})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: accounts.SessionCookie, Value: token}
}

func insertOrg(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(`INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)`,
		id, name, "org-"+id[len(id)-12:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertLicence(t *testing.T, db *sql.DB, orgID string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO licences (id, org_id, licence_key, kind, plan, max_instances, expires_at)
		 VALUES (?, ?, ?, 'subscription', 'pro', 5, ?)`,
		id, orgID, "SPL-"+id[len(id)-12:], time.Now().Add(365*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	return id
}

func doReq(t *testing.T, h http.Handler, method, path string, body any,
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
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestStaffOnly(t *testing.T) {
	h, db, acct := testHandler(t)
	nonStaff := staffCookie(t, db, acct, false)
	for _, path := range []string{
		"/admin/search?q=x", "/admin/estate", "/admin/audit-log",
		"/admin/organisations/" + uuid.Must(uuid.NewV7()).String(),
	} {
		if rec := doReq(t, h, "GET", path, nil, nonStaff); rec.Code != http.StatusForbidden {
			t.Fatalf("non-staff %s = %d, want 403", path, rec.Code)
		}
	}
	// Staff without TOTP is also refused.
	u := dbq.User{ID: uuid.Must(uuid.NewV7()).String()}
	u.Email = "nototp-" + u.ID[len(u.ID)-8:] + "@test.dev"
	u.PasswordHash = "x"
	u.IsPlatformAdmin = true
	if _, err := db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash, is_platform_admin, totp_enabled)
		 VALUES (?, ?, 'S', 'x', 1, 0)`, u.ID, u.Email); err != nil {
		t.Fatal(err)
	}
	token, _ := acct.EncodeSession(accounts.Session{User: u, Stage: accounts.StageFull})
	rec := doReq(t, h, "GET", "/admin/estate", nil,
		&http.Cookie{Name: accounts.SessionCookie, Value: token})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("staff-without-totp estate = %d, want 403", rec.Code)
	}
}

func TestSearch(t *testing.T) {
	h, db, acct := testHandler(t)
	staff := staffCookie(t, db, acct, true)
	orgID := insertOrg(t, db, "Acme Searchable")
	licID := insertLicence(t, db, orgID)
	var key string
	if err := db.QueryRow(`SELECT licence_key FROM licences WHERE id = ?`, licID).Scan(&key); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, h, "GET", "/admin/search?q=Acme%20Searchable", nil, staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("search = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Organisations []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"organisations"`
		Licences []struct {
			ID string `json:"id"`
		} `json:"licences"`
		Users     []any `json:"users"`
		Instances []any `json:"instances"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Organisations) != 1 || out.Organisations[0].ID != orgID {
		t.Fatalf("org hits = %+v", out.Organisations)
	}

	// Licence-key search hits the licences section.
	rec = doReq(t, h, "GET", "/admin/search?q="+key, nil, staff)
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Licences) != 1 || out.Licences[0].ID != licID {
		t.Fatalf("licence hits = %+v", out.Licences)
	}

	// Missing q is a 400.
	if rec := doReq(t, h, "GET", "/admin/search", nil, staff); rec.Code != http.StatusBadRequest {
		t.Fatalf("empty search = %d, want 400", rec.Code)
	}
}

func TestOrgDetail(t *testing.T) {
	h, db, acct := testHandler(t)
	staff := staffCookie(t, db, acct, true)
	orgID := insertOrg(t, db, "Detail Org")
	licID := insertLicence(t, db, orgID)
	userID := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash) VALUES (?, ?, 'M', 'x')`,
		userID, "m-"+userID[len(userID)-8:]+"@test.dev"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO memberships (id, org_id, user_id, role) VALUES (?, ?, ?, 'owner')`,
		uuid.Must(uuid.NewV7()).String(), orgID, userID); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, h, "GET", "/admin/organisations/"+orgID, nil, staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("org detail = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Org struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"org"`
		Members []struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"members"`
		Licences []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"licences"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Org.ID != orgID || len(out.Members) != 1 || out.Members[0].Role != "owner" ||
		len(out.Licences) != 1 || out.Licences[0].ID != licID || out.Licences[0].Status != "active" {
		t.Fatalf("detail = %+v", out)
	}

	// Unknown org is a 404.
	rec = doReq(t, h, "GET", "/admin/organisations/"+uuid.Must(uuid.NewV7()).String(), nil, staff)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing org = %d, want 404", rec.Code)
	}
}

func TestLicenceOps(t *testing.T) {
	h, db, acct := testHandler(t)
	staff := staffCookie(t, db, acct, true)
	orgID := insertOrg(t, db, "Licence Org")

	// Issue.
	rec := doReq(t, h, "POST", "/admin/licences", map[string]any{
		"org_id": orgID, "kind": "perpetual", "plan": "enterprise", "max_instances": 10,
	}, staff)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d: %s", rec.Code, rec.Body)
	}
	var issued struct {
		ID         string `json:"id"`
		LicenceKey string `json:"licence_key"`
		Kind       string `json:"kind"`
		Status     string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(issued.LicenceKey, "SPL-") || issued.Status != "active" ||
		issued.Kind != "perpetual" {
		t.Fatalf("issued = %+v", issued)
	}
	// Issue writes an audit row.
	var action string
	if err := db.QueryRow(
		`SELECT action FROM audit_log WHERE target_id = ?`, issued.ID).Scan(&action); err != nil {
		t.Fatalf("issue audit: %v", err)
	}
	if action != "licence.issued" {
		t.Fatalf("audit action = %q", action)
	}

	// Bad kind/plan rejected; unknown org is a 404.
	if rec := doReq(t, h, "POST", "/admin/licences", map[string]any{
		"org_id": orgID, "kind": "bogus", "max_instances": 1,
	}, staff); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad kind = %d, want 400", rec.Code)
	}
	if rec := doReq(t, h, "POST", "/admin/licences", map[string]any{
		"org_id": uuid.Must(uuid.NewV7()).String(), "max_instances": 1,
	}, staff); rec.Code != http.StatusNotFound {
		t.Fatalf("missing org = %d, want 404", rec.Code)
	}

	// Reissue: new licence minted, old revoked atomically.
	oldID := insertLicence(t, db, orgID)
	rec = doReq(t, h, "POST", "/admin/licences/"+oldID+"/reissue", map[string]any{}, staff)
	if rec.Code != http.StatusCreated {
		t.Fatalf("reissue = %d: %s", rec.Code, rec.Body)
	}
	var reiss struct {
		Licence struct {
			ID         string `json:"id"`
			LicenceKey string `json:"licence_key"`
		} `json:"licence"`
		Supersedes string `json:"supersedes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reiss); err != nil {
		t.Fatal(err)
	}
	if reiss.Supersedes != oldID || reiss.Licence.ID == oldID {
		t.Fatalf("reissue = %+v", reiss)
	}
	var revokedAt any
	if err := db.QueryRow(`SELECT revoked_at FROM licences WHERE id = ?`, oldID).
		Scan(&revokedAt); err != nil {
		t.Fatal(err)
	}
	if revokedAt == nil {
		t.Fatal("reissue should revoke the old licence")
	}

	// Revoke idempotently.
	rec = doReq(t, h, "POST", "/admin/licences/"+reiss.Licence.ID+"/revoke", map[string]any{}, staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rec.Code, rec.Body)
	}
	var rev struct {
		Status    string `json:"status"`
		RevokedAt any    `json:"revoked_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rev); err != nil {
		t.Fatal(err)
	}
	if rev.Status != "revoked" || rev.RevokedAt == nil {
		t.Fatalf("revoked = %+v", rev)
	}
	if rec := doReq(t, h, "POST", "/admin/licences/"+reiss.Licence.ID+"/revoke", map[string]any{}, staff); rec.Code != http.StatusOK {
		t.Fatalf("second revoke = %d", rec.Code)
	}
}

func TestEstateAndAuditLog(t *testing.T) {
	h, db, acct := testHandler(t)
	staff := staffCookie(t, db, acct, true)
	orgID := insertOrg(t, db, "Estate Org")
	insertLicence(t, db, orgID)
	if _, err := db.Exec(
		`INSERT INTO instances (id, org_id, name, fingerprint, appliance_version, status, last_seen_at)
		 VALUES (?, ?, 'box', ?, '2.0.0', 'active', UTC_TIMESTAMP(6))`,
		uuid.Must(uuid.NewV7()).String(), orgID, "fp-"+uuid.Must(uuid.NewV7()).String()); err != nil {
		t.Fatal(err)
	}

	rec := doReq(t, h, "GET", "/admin/estate", nil, staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("estate = %d: %s", rec.Code, rec.Body)
	}
	var est struct {
		Totals struct {
			Organisations   int64 `json:"organisations"`
			ActiveInstances int64 `json:"active_instances"`
			Seen24h         int64 `json:"seen_24h"`
		} `json:"totals"`
		Versions []struct {
			Version   string `json:"appliance_version"`
			Instances int64  `json:"instances"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &est); err != nil {
		t.Fatal(err)
	}
	if est.Totals.Organisations < 1 || est.Totals.ActiveInstances < 1 || est.Totals.Seen24h < 1 {
		t.Fatalf("estate = %+v", est)
	}
	if len(est.Versions) != 1 || est.Versions[0].Version != "2.0.0" {
		t.Fatalf("versions = %+v", est.Versions)
	}

	// Audit log lists the licence.issued row from the licence insert
	// helper path — write one via the staff API instead for provenance.
	rec = doReq(t, h, "POST", "/admin/licences", map[string]any{
		"org_id": orgID, "max_instances": 1,
	}, staff)
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue = %d", rec.Code)
	}
	rec = doReq(t, h, "GET", "/admin/audit-log", nil, staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("audit = %d", rec.Code)
	}
	var log struct {
		Entries []struct {
			Action     string `json:"action"`
			ActorEmail string `json:"actor_email"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Entries) == 0 || log.Entries[0].Action != "licence.issued" {
		t.Fatalf("audit entries = %+v", log.Entries)
	}
	// Actor is the staff user.
	var staffEmail string
	if err := db.QueryRow(`SELECT email FROM users WHERE is_platform_admin = 1 LIMIT 1`).
		Scan(&staffEmail); err != nil {
		t.Fatal(err)
	}
	if log.Entries[0].ActorEmail != staffEmail {
		t.Fatalf("actor = %q want %q", log.Entries[0].ActorEmail, staffEmail)
	}
}
