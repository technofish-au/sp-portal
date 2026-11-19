// Integration tests for the customer portal API (licences, instances,
// reports, deactivate) against a real MariaDB (internal/testutil).
package portal_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/portal"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

func testHandler(t *testing.T) (http.Handler, *sql.DB, *accounts.Service) {
	t.Helper()
	db := testutil.MariaDB(t)
	acct := accounts.NewMust(db, accounts.Options{
		Secret: []byte("test-auth-secret-0123456789abcdef"), SessionTTL: time.Hour,
	})
	return portal.Routes(db, acct), db, acct
}

// memberCookie mints a session cookie for a fresh user joined to orgID.
func memberCookie(t *testing.T, db *sql.DB, acct *accounts.Service, orgID, role string) *http.Cookie {
	t.Helper()
	u := dbq.User{ID: uuid.Must(uuid.NewV7()).String()}
	u.Email = "user-" + u.ID[len(u.ID)-8:] + "@test.dev"
	u.PasswordHash = "x" // the cookie fingerprint must match the DB row
	if _, err := db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash) VALUES (?, ?, 'T', 'x')`,
		u.ID, u.Email); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO memberships (id, org_id, user_id, role) VALUES (?, ?, ?, ?)`,
		uuid.Must(uuid.NewV7()).String(), orgID, u.ID, role); err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	token, err := acct.EncodeSession(accounts.Session{User: u, Stage: accounts.StageFull})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: accounts.SessionCookie, Value: token}
}

func insertOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(`INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)`,
		id, "Org", "org-"+id[len(id)-12:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertLicence(t *testing.T, db *sql.DB, orgID string, revoked bool) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	var revokedAt any
	if revoked {
		revokedAt = time.Now().UTC()
	}
	if _, err := db.Exec(
		`INSERT INTO licences (id, org_id, licence_key, kind, plan, max_instances, expires_at, revoked_at)
		 VALUES (?, ?, ?, 'subscription', 'pro', 5, ?, ?)`,
		id, orgID, "SPL-"+id[len(id)-12:], time.Now().Add(365*24*time.Hour), revokedAt); err != nil {
		t.Fatal(err)
	}
	return id
}

func insertInstance(t *testing.T, db *sql.DB, orgID, licenceID string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO instances (id, org_id, licence_id, name, fingerprint, appliance_version, status)
		 VALUES (?, ?, ?, 'box', ?, '1.2.0', 'active')`,
		id, orgID, licenceID, "fp-"+id[len(id)-8:]); err != nil {
		t.Fatal(err)
	}
	return id
}

func doReq(t *testing.T, h http.Handler, method, path string,
	cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestListLicencesAndDetail(t *testing.T) {
	h, db, acct := testHandler(t)
	orgID, other := insertOrg(t, db), insertOrg(t, db)
	licID := insertLicence(t, db, orgID, false)
	insertLicence(t, db, orgID, true)
	insertLicence(t, db, other, false)
	insertInstance(t, db, orgID, licID)
	cookie := memberCookie(t, db, acct, orgID, "member")

	rec := doReq(t, h, "GET", "/licences?org_id="+orgID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list licences = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Licences []struct {
			ID           string `json:"id"`
			Status       string `json:"status"`
			SeatsUsed    int64  `json:"seats_used"`
			MaxInstances int32  `json:"max_instances"`
			LicenceKey   string `json:"licence_key"`
		} `json:"licences"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Licences) != 2 {
		t.Fatalf("want 2 licences, got %d", len(out.Licences))
	}
	// Only this org's licences; the bound instance counts as a seat.
	byID := map[string]int{}
	for _, l := range out.Licences {
		byID[l.ID]++
	}
	if byID[licID] != 1 {
		t.Fatalf("licence %s missing", licID)
	}
	rec = doReq(t, h, "GET", "/licences/"+licID, cookie)
	var det struct {
		Licence struct {
			SeatsUsed int64 `json:"seats_used"`
		} `json:"licence"`
		Instances []struct {
			Status string `json:"status"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &det); err != nil {
		t.Fatal(err)
	}
	if det.Licence.SeatsUsed != 1 || len(det.Instances) != 1 {
		t.Fatalf("detail = %+v", det)
	}
}

func TestLicenceCrossOrgForbidden(t *testing.T) {
	h, db, acct := testHandler(t)
	orgID, other := insertOrg(t, db), insertOrg(t, db)
	licID := insertLicence(t, db, other, false)
	cookie := memberCookie(t, db, acct, orgID, "member")
	if rec := doReq(t, h, "GET", "/licences/"+licID, cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org licence = %d, want 403", rec.Code)
	}
	if rec := doReq(t, h, "GET", "/licences?org_id="+other, cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org list = %d, want 403", rec.Code)
	}
}

func TestInstancesListReportsDeactivate(t *testing.T) {
	h, db, acct := testHandler(t)
	orgID := insertOrg(t, db)
	licID := insertLicence(t, db, orgID, false)
	instID := insertInstance(t, db, orgID, licID)
	if _, err := db.Exec(
		`INSERT INTO instance_reports (id, instance_id, reported_at, payload)
		 VALUES (?, ?, ?, ?)`,
		uuid.Must(uuid.NewV7()).String(), instID, time.Now().UTC(), `{"machines":4}`); err != nil {
		t.Fatal(err)
	}
	cookie := memberCookie(t, db, acct, orgID, "member")

	rec := doReq(t, h, "GET", "/instances?org_id="+orgID, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body)
	}
	var list struct {
		Instances []struct {
			ID         string `json:"id"`
			LicenceKey string `json:"licence_key"`
		} `json:"instances"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Instances) != 1 || list.Instances[0].LicenceKey == "" {
		t.Fatalf("list = %+v", list)
	}

	rec = doReq(t, h, "GET", "/instances/"+instID+"/reports", cookie)
	var reps struct {
		Reports []struct {
			Payload map[string]any `json:"payload"`
		} `json:"reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reps); err != nil {
		t.Fatal(err)
	}
	if len(reps.Reports) != 1 || reps.Reports[0].Payload["machines"] != float64(4) {
		t.Fatalf("reports = %+v", reps)
	}

	// Deactivate frees the seat and is idempotent.
	rec = doReq(t, h, "POST", "/instances/"+instID+"/deactivate", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("deactivate = %d: %s", rec.Code, rec.Body)
	}
	var status string
	if err := db.QueryRow(`SELECT status FROM instances WHERE id = ?`, instID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "decommissioned" {
		t.Fatalf("status = %q", status)
	}
	if rec := doReq(t, h, "POST", "/instances/"+instID+"/deactivate", cookie); rec.Code != http.StatusOK {
		t.Fatalf("second deactivate = %d", rec.Code)
	}
}

func TestViewerCannotDeactivate(t *testing.T) {
	h, db, acct := testHandler(t)
	orgID := insertOrg(t, db)
	instID := insertInstance(t, db, orgID, insertLicence(t, db, orgID, false))
	cookie := memberCookie(t, db, acct, orgID, "viewer")
	rec := doReq(t, h, "POST", "/instances/"+instID+"/deactivate", cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer deactivate = %d, want 403", rec.Code)
	}
	// Reads still work for viewers.
	if rec := doReq(t, h, "GET", "/instances?org_id="+orgID, cookie); rec.Code != http.StatusOK {
		t.Fatalf("viewer list = %d", rec.Code)
	}
}
