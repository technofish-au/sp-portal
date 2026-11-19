// Customer-facing catalogue + session download minting (R5-5) and the
// staff support-bundle access hooks.
package releases_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/storage"
)

// memberCookie mints a session cookie for a plain org member (no TOTP,
// no platform admin) joined to orgID.
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

func TestCustomerCatalogue(t *testing.T) {
	h, db, acct, _ := testHandler(t)
	orgID := insertOrg(t, db)
	live := time.Now().Add(365 * 24 * time.Hour)
	insertLicence(t, db, orgID, &live, nil)
	cookie := memberCookie(t, db, acct, orgID, "member")

	now := time.Now().UTC()
	pubID := insertRelease(t, db, "1.4.0", "platform/1.4.0/pkg.tgz", &now)
	insertRelease(t, db, "1.5.0-draft", "platform/1.5.0/pkg.tgz", nil)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/releases", nil)
	req.AddCookie(cookie)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalogue = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Releases []struct {
			ID        string `json:"id"`
			Version   string `json:"version"`
			Published bool   `json:"published"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Releases) != 1 || out.Releases[0].ID != pubID {
		t.Fatalf("catalogue = %+v, want only %s", out.Releases, pubID)
	}

	// Unauthenticated catalogue read is rejected.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/releases", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon catalogue = %d, want 401", rec.Code)
	}
}

func TestCustomerMintDownloadURL(t *testing.T) {
	h, db, acct, root := testHandler(t)
	orgID := insertOrg(t, db)
	live := time.Now().Add(365 * 24 * time.Hour)
	insertLicence(t, db, orgID, &live, nil)
	cookie := memberCookie(t, db, acct, orgID, "member")

	// Stage the artifact the download will serve.
	relDir := filepath.Join(root, string(storage.Releases), "platform/9.9.9")
	if err := os.MkdirAll(relDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(relDir, "pkg.tgz"),
		[]byte("artifact-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	relID := insertRelease(t, db, "9.9.9", "platform/9.9.9/pkg.tgz", &now)

	body := fmt.Sprintf(`{"org_id":%q}`, orgID)
	req := httptest.NewRequest("POST", "/releases/"+relID+"/download-url",
		strings.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body)
	}
	var minted struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &minted); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(minted.URL, "/download?t=") {
		t.Fatalf("url = %q", minted.URL)
	}

	// The minted URL serves the artifact (the token is the capability —
	// no cookie needed on the download leg). Routes() mounts the /v1
	// paths at the root here, so strip the /v1 prefix like the existing
	// download tests do.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", strings.TrimPrefix(minted.URL, "/v1"), nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "artifact-bytes" {
		t.Fatalf("download = %d %q", rec.Code, rec.Body.String())
	}
}

func TestCustomerMintDenied(t *testing.T) {
	h, db, acct, _ := testHandler(t)
	orgID := insertOrg(t, db)
	cookie := memberCookie(t, db, acct, orgID, "member")
	now := time.Now().UTC()
	relID := insertRelease(t, db, "1.0.0", "x", &now)
	draftID := insertRelease(t, db, "9.9-draft", "x", nil)

	mint := func(rel, body string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/releases/"+rel+"/download-url",
			strings.NewReader(body))
		if c != nil {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// No licence at all.
	if rec := mint(relID, fmt.Sprintf(`{"org_id":%q}`, orgID), cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("no-licence mint = %d, want 403", rec.Code)
	}
	// Expired licence entitles only releases published before it ended;
	// this release was published after.
	past := time.Now().Add(-24 * time.Hour).UTC()
	org2 := insertOrg(t, db)
	insertLicence(t, db, org2, &past, nil)
	cookie2 := memberCookie(t, db, acct, org2, "member")
	if rec := mint(relID, fmt.Sprintf(`{"org_id":%q}`, org2), cookie2); rec.Code != http.StatusForbidden {
		t.Fatalf("expired-licence mint = %d, want 403", rec.Code)
	}
	// Unpublished release.
	live := time.Now().Add(365 * 24 * time.Hour)
	insertLicence(t, db, orgID, &live, nil)
	if rec := mint(draftID, fmt.Sprintf(`{"org_id":%q}`, orgID), cookie); rec.Code != http.StatusConflict {
		t.Fatalf("draft mint = %d, want 409", rec.Code)
	}
	// Non-member org.
	other := insertOrg(t, db)
	if rec := mint(relID, fmt.Sprintf(`{"org_id":%q}`, other), cookie); rec.Code != http.StatusForbidden {
		t.Fatalf("non-member mint = %d, want 403", rec.Code)
	}
	// Anonymous.
	if rec := mint(relID, fmt.Sprintf(`{"org_id":%q}`, orgID), nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon mint = %d, want 401", rec.Code)
	}
}

func insertBundleRow(t *testing.T, db *sql.DB, orgID, path string) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	exp := time.Now().Add(24 * time.Hour).UTC()
	if _, err := db.Exec(
		`INSERT INTO support_bundles (id, org_id, path, size_bytes, expires_at)
		 VALUES (?, ?, ?, 4, ?)`, id, orgID, path, exp); err != nil {
		t.Fatalf("insert bundle: %v", err)
	}
	return id
}

func TestSupportBundleStaffHooks(t *testing.T) {
	h, db, acct, root := testHandler(t)
	orgID := insertOrg(t, db)
	staff := staffCookie(t, db, acct, true)
	nonStaff := staffCookie(t, db, acct, false)

	// File on disk under storage/support-bundles/<org>/.
	relPath := orgID + "/bundle-1.tar.gz"
	dest := filepath.Join(root, string(storage.SupportBundles), relPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("bundle-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	bundleID := insertBundleRow(t, db, orgID, relPath)

	get := func(path string, c *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if c != nil {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	// Staff list.
	rec := get("/admin/support-bundles", staff)
	if rec.Code != http.StatusOK {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body)
	}
	var out struct {
		Bundles []struct {
			ID    string `json:"id"`
			OrgID string `json:"org_id"`
			Path  string `json:"-"`
			Size  int64  `json:"size_bytes"`
		} `json:"bundles"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Bundles) != 1 || out.Bundles[0].ID != bundleID {
		t.Fatalf("bundles = %+v", out.Bundles)
	}

	// Staff download streams the archive and is audit-logged.
	rec = get("/admin/support-bundles/"+bundleID+"/download", staff)
	if rec.Code != http.StatusOK || rec.Body.String() != "bundle-bytes" {
		t.Fatalf("download = %d %q", rec.Code, rec.Body.String())
	}
	var action string
	err := db.QueryRow(
		`SELECT action FROM audit_log WHERE target_id = ? ORDER BY created_at DESC LIMIT 1`,
		bundleID).Scan(&action)
	if err != nil || action != "support_bundle.downloaded" {
		t.Fatalf("audit action = %q err=%v", action, err)
	}

	// Non-staff and anonymous access are denied.
	if rec := get("/admin/support-bundles", nonStaff); rec.Code != http.StatusForbidden {
		t.Fatalf("non-staff list = %d, want 403", rec.Code)
	}
	if rec := get("/admin/support-bundles", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon list = %d, want 401", rec.Code)
	}
}
