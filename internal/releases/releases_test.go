// Integration tests for the release-catalogue domain against a real
// MariaDB (internal/testutil): staff admin API (register/publish/
// withdraw/flags/prune), signed download URLs (mint, expiry, range
// resume), the basic-auth apt repository with licence gating, the
// support-bundle upload leg and offline-bundle generation.
package releases_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/bundles"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/releases"
	"github.com/technofish-au/sp-portal/internal/storage"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// --- fixtures -----------------------------------------------------------

const testDownloadSecret = "test-download-secret-0123456789ab"

func testHandler(t *testing.T) (http.Handler, *sql.DB, *accounts.Service, string) {
	t.Helper()
	db := testutil.MariaDB(t)
	root, err := storage.Ensure(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	acct := accounts.NewMust(db, accounts.Options{
		Secret: []byte("test-auth-secret-0123456789abcdef"), SessionTTL: time.Hour,
	})
	issuer, err := licensing.DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	h := releases.Routes(db, nil, acct, releases.Options{
		StorageRoot:    root,
		DownloadSecret: []byte(testDownloadSecret),
		BundleSigner:   issuer,
	})
	return h, db, acct, root
}

func insertOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)`,
		id, "Test Org", "org-"+id[len(id)-12:]); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	return id
}

func insertLicence(t *testing.T, db *sql.DB, orgID string, expiresAt, revokedAt *time.Time) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO licences (id, org_id, licence_key, kind, plan, max_instances,
		                       expires_at, revoked_at)
		 VALUES (?, ?, ?, 'subscription', 'pro', 5, ?, ?)`,
		id, orgID, "SPL-"+id[len(id)-12:], expiresAt, revokedAt); err != nil {
		t.Fatalf("insert licence: %v", err)
	}
	return id
}

// insertInstance seeds an activated appliance: instance row + bound key.
func insertInstance(t *testing.T, db *sql.DB, orgID, licenceID string) (instID string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	instID = uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO instances (id, org_id, licence_id, name, fingerprint, status, public_key)
		 VALUES (?, ?, ?, 'test-box', ?, 'active', ?)`,
		instID, orgID, licenceID, "machine-"+instID[len(instID)-8:], []byte(pub)); err != nil {
		t.Fatalf("insert instance: %v", err)
	}
	return instID, priv
}

func insertRelease(t *testing.T, db *sql.DB, version, artifactPath string, publishedAt *time.Time) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	if _, err := db.Exec(
		`INSERT INTO releases (id, version, component, channel, notes,
		                       artifact_path, sha256, size_bytes, published_at)
		 VALUES (?, ?, 'platform', 'stable', '', ?, '', 0, ?)`,
		id, version, artifactPath, publishedAt); err != nil {
		t.Fatalf("insert release: %v", err)
	}
	return id
}

func insertAptToken(t *testing.T, db *sql.DB, orgID, password string) {
	t.Helper()
	sum := sha256.Sum256([]byte(password))
	if _, err := db.Exec(
		`INSERT INTO download_tokens (id, token_hash, org_id, kind, path, expires_at)
		 VALUES (?, ?, ?, 'apt', 'apt/', ?)`,
		uuid.Must(uuid.NewV7()).String(), hex.EncodeToString(sum[:]), orgID,
		time.Now().Add(24*time.Hour).UTC()); err != nil {
		t.Fatalf("insert apt token: %v", err)
	}
}

// staffCookie mints a session cookie for an is_platform_admin user.
// RequireStaff demands TOTP, so the test user is created already
// enrolled (loginStage forces real staff through enrolment first).
func staffCookie(t *testing.T, db *sql.DB, acct *accounts.Service, admin bool) *http.Cookie {
	t.Helper()
	u := dbq.User{ID: uuid.Must(uuid.NewV7()).String()}
	u.Email = "user-" + u.ID[len(u.ID)-8:] + "@test.dev"
	u.IsPlatformAdmin = admin
	u.TotpEnabled = admin // staff must enrol before hitting /admin/*
	if _, err := db.Exec(
		`INSERT INTO users (id, email, display_name, password_hash, is_platform_admin, totp_enabled)
		 VALUES (?, ?, 'Test User', '', ?, ?)`, u.ID, u.Email, admin, admin); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	token, err := acct.EncodeSession(accounts.Session{User: u, Stage: accounts.StageFull})
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: accounts.SessionCookie, Value: token}
}

func doReq(t *testing.T, h http.Handler, method, path string, body io.Reader,
	ct string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, body)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func signedReq(t *testing.T, h http.Handler, priv ed25519.PrivateKey, instID,
	method, path string, body []byte, ct string) *httptest.ResponseRecorder {
	t.Helper()
	// uuidv7's head is the timestamp — prefixing a slice of it would
	// collide within the same millisecond, so use a random nonce.
	var nonceRaw [8]byte
	if _, err := rand.Read(nonceRaw[:]); err != nil {
		t.Fatal(err)
	}
	auth, err := instauth.SignRequest(priv, instID, method, path,
		time.Now().Unix(), "n-"+hex.EncodeToString(nonceRaw[:]), body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Authorization", auth)
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// writeArtifact drops a file under <root>/releases/<relPath>.
func writeArtifact(t *testing.T, root, relPath, content string) {
	t.Helper()
	dest := filepath.Join(root, storage.Releases, relPath)
	if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte(content), 0o640); err != nil {
		t.Fatal(err)
	}
}

// --- staff catalogue admin -------------------------------------------------

// multipartBody builds a fresh register-release upload each call.
func multipartBody(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("version", "1.4.2")
	_ = mw.WriteField("channel", "stable")
	_ = mw.WriteField("min_upgrade_from", "1.3.0")
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="artifact"; filename="sp-platform-1.4.2.tar.gz"`)
	hdr.Set("Content-Type", "application/octet-stream")
	pw, err := mw.CreatePart(hdr)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = pw.Write([]byte("fake-artifact-payload"))
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, mw.FormDataContentType()
}

func TestRegisterReleaseMultipartRoundTrip(t *testing.T) {
	h, db, acct, root := testHandler(t)
	cookie := staffCookie(t, db, acct, true)

	body, ct := multipartBody(t)
	rec := doReq(t, h, "POST", "/admin/releases", body, ct, cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", rec.Code, rec.Body.String())
	}
	var rel map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	if rel["version"] != "1.4.2" || rel["min_upgrade_from"] != "1.3.0" {
		t.Fatalf("release view: %v", rel)
	}
	sum := sha256.Sum256([]byte("fake-artifact-payload"))
	if rel["sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("sha256 = %v", rel["sha256"])
	}
	data, err := os.ReadFile(filepath.Join(root, storage.Releases, rel["artifact_path"].(string)))
	if err != nil || string(data) != "fake-artifact-payload" {
		t.Fatalf("artifact on disk: %v %q", err, data)
	}
	// Duplicate register conflicts.
	body, ct = multipartBody(t)
	rec = doReq(t, h, "POST", "/admin/releases", body, ct, cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate register = %d, want 409", rec.Code)
	}
	var audit int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='release.registered'`).Scan(&audit); err != nil || audit != 1 {
		t.Fatalf("registered audit rows = %d, err %v", audit, err)
	}
}

func TestRegisterReleaseJSONLeg(t *testing.T) {
	h, db, acct, root := testHandler(t)
	cookie := staffCookie(t, db, acct, true)
	writeArtifact(t, root, "platform/2.0.0/sp-platform-2.0.0.tar.gz", "staged-artifact")

	rec := doReq(t, h, "POST", "/admin/releases", strings.NewReader(`{
		"version":"2.0.0","artifact_path":"platform/2.0.0/sp-platform-2.0.0.tar.gz"}`),
		"application/json", cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register = %d: %s", rec.Code, rec.Body.String())
	}
	var rel map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	if rel["size_bytes"] != float64(len("staged-artifact")) {
		t.Fatalf("size_bytes = %v", rel["size_bytes"])
	}
}

func TestAdminRequiresStaff(t *testing.T) {
	h, db, acct, _ := testHandler(t)

	// No session: 401.
	rec := doReq(t, h, "GET", "/admin/releases", nil, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated = %d, want 401", rec.Code)
	}
	// Non-admin session: 403.
	rec = doReq(t, h, "GET", "/admin/releases", nil, "", staffCookie(t, db, acct, false))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin = %d, want 403", rec.Code)
	}
}

func TestPublishWithdrawFlagFlow(t *testing.T) {
	h, db, acct, _ := testHandler(t)
	cookie := staffCookie(t, db, acct, true)
	relID := insertRelease(t, db, "1.5.0", "", nil)

	patch := doReq(t, h, "PATCH", "/admin/releases/"+relID,
		strings.NewReader(`{"security":true,"min_upgrade_from":"1.2.0"}`),
		"application/json", cookie)
	if patch.Code != http.StatusOK {
		t.Fatalf("patch = %d: %s", patch.Code, patch.Body.String())
	}
	pub := doReq(t, h, "POST", "/admin/releases/"+relID+"/publish", nil, "", cookie)
	if pub.Code != http.StatusOK {
		t.Fatalf("publish = %d: %s", pub.Code, pub.Body.String())
	}
	var rel map[string]any
	if err := json.Unmarshal(pub.Body.Bytes(), &rel); err != nil {
		t.Fatal(err)
	}
	if rel["published"] != true || rel["security"] != true || rel["min_upgrade_from"] != "1.2.0" {
		t.Fatalf("published view: %v", rel)
	}
	wd := doReq(t, h, "POST", "/admin/releases/"+relID+"/withdraw", nil, "", cookie)
	if wd.Code != http.StatusOK {
		t.Fatalf("withdraw = %d: %s", wd.Code, wd.Body.String())
	}
	var wrel map[string]any
	if err := json.Unmarshal(wd.Body.Bytes(), &wrel); err != nil {
		t.Fatal(err)
	}
	if wrel["published"] != false || wrel["withdrawn_at"] == nil {
		t.Fatalf("withdrawn view: %v", wrel)
	}
	// A withdrawn release cannot be republished.
	rec := doReq(t, h, "POST", "/admin/releases/"+relID+"/publish", nil, "", cookie)
	if rec.Code != http.StatusConflict {
		t.Fatalf("republish withdrawn = %d, want 409", rec.Code)
	}
	// Missing release 404s.
	rec = doReq(t, h, "POST", "/admin/releases/"+uuid.Must(uuid.NewV7()).String()+"/publish",
		nil, "", cookie)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing release = %d, want 404", rec.Code)
	}
}

// --- signed download URLs -------------------------------------------------

// fixtureArtifact returns a release row plus its on-disk bytes.
func fixtureArtifact(t *testing.T, db *sql.DB, root, version, content string, published *time.Time) string {
	t.Helper()
	relPath := "platform/" + version + "/sp-platform-" + version + ".tar.gz"
	writeArtifact(t, root, relPath, content)
	return insertRelease(t, db, version, relPath, published)
}

func mintURL(t *testing.T, h http.Handler, priv ed25519.PrivateKey, instID, relID string) *httptest.ResponseRecorder {
	t.Helper()
	return signedReq(t, h, priv, instID, "POST", "/releases/download-urls",
		[]byte(fmt.Sprintf(`{"release_id":%q}`, relID)), "application/json")
}

func TestDownloadURLMintFetchRange(t *testing.T) {
	h, db, _, root := testHandler(t)
	orgID := insertOrg(t, db)
	licID := insertLicence(t, db, orgID, nil, nil)
	instID, priv := insertInstance(t, db, orgID, licID)
	now := time.Now().UTC()
	content := "0123456789abcdef-release-artifact"
	relID := fixtureArtifact(t, db, root, "1.4.2", content, &now)

	rec := mintURL(t, h, priv, instID, relID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	url := strings.TrimPrefix(resp["url"].(string), "/v1")

	// Full fetch.
	dl := doReq(t, h, "GET", url, nil, "", nil)
	if dl.Code != http.StatusOK || dl.Body.String() != content {
		t.Fatalf("download = %d %q", dl.Code, dl.Body.String())
	}
	// Range resume.
	req := httptest.NewRequest("GET", url, nil)
	req.Header.Set("Range", "bytes=4-9")
	rrec := httptest.NewRecorder()
	h.ServeHTTP(rrec, req)
	if rrec.Code != http.StatusPartialContent || rrec.Body.String() != content[4:10] {
		t.Fatalf("range = %d %q", rrec.Code, rrec.Body.String())
	}
	// The token row recorded issuance and first use.
	var used sql.NullTime
	var count int
	if err := db.QueryRow(
		`SELECT COUNT(*), MAX(used_at) FROM download_tokens WHERE kind='release' AND release_id=?`,
		relID).Scan(&count, &used); err != nil || count != 1 || !used.Valid {
		t.Fatalf("token row: count=%d used=%v err=%v", count, used, err)
	}
}

func TestDownloadURLAuthAndExpiry(t *testing.T) {
	h, db, _, root := testHandler(t)
	orgID := insertOrg(t, db)
	licID := insertLicence(t, db, orgID, nil, nil)
	insertInstance(t, db, orgID, licID)
	now := time.Now().UTC()
	relID := fixtureArtifact(t, db, root, "1.4.2", "artifact", &now)

	// Unauthenticated mint: 401.
	req := httptest.NewRequest("POST", "/releases/download-urls",
		strings.NewReader(fmt.Sprintf(`{"release_id":%q}`, relID)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed mint = %d, want 401", rec.Code)
	}
	// Unsigned download: 401.
	rec = doReq(t, h, "GET", "/releases/"+relID+"/download", nil, "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token = %d, want 401", rec.Code)
	}

	// An expired token row: forge the correctly-signed credential for an
	// already-expired token and record its hash as mintToken would.
	tokenID := uuid.Must(uuid.NewV7()).String()
	past := time.Now().Add(-time.Hour).Unix()
	mac := hmac.New(sha256.New, []byte(testDownloadSecret))
	fmt.Fprintf(mac, "SP-DL-V1\n%s\n%s\n%d\n%s\n", tokenID, relID, past, orgID)
	expired := fmt.Sprintf("%s.%d.%s", tokenID, past,
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))
	sum := sha256.Sum256([]byte(expired))
	if _, err := db.Exec(
		`INSERT INTO download_tokens (id, token_hash, org_id, kind, path,
		                             release_id, expires_at)
		 VALUES (?, ?, ?, 'release', 'x', ?, ?)`,
		tokenID, hex.EncodeToString(sum[:]), orgID, relID,
		time.Now().Add(-time.Minute).UTC()); err != nil {
		t.Fatalf("insert expired token: %v", err)
	}
	rec = doReq(t, h, "GET", "/releases/"+relID+"/download?t="+expired, nil, "", nil)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "token_expired") {
		t.Fatalf("expired token = %d: %s", rec.Code, rec.Body.String())
	}
	// A tampered signature: 401 bad_signature.
	bad := tokenID + "." + fmt.Sprint(time.Now().Add(time.Hour).Unix()) + ".AAAA"
	rec = doReq(t, h, "GET", "/releases/"+relID+"/download?t="+bad, nil, "", nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bad_signature") {
		t.Fatalf("bad sig = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDownloadEntitlementGating(t *testing.T) {
	h, db, _, root := testHandler(t)
	orgID := insertOrg(t, db)
	past := time.Now().Add(-time.Hour).UTC()
	older := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().Add(-time.Minute).UTC()
	licID := insertLicence(t, db, orgID, &past /* expired */, nil)
	instID, priv := insertInstance(t, db, orgID, licID)
	oldRel := fixtureArtifact(t, db, root, "1.0.0", "old", &older)
	newRel := fixtureArtifact(t, db, root, "9.9.9", "new", &recent)

	// Expired licence: an older release still mints.
	if rec := mintURL(t, h, priv, instID, oldRel); rec.Code != http.StatusCreated {
		t.Fatalf("older mint = %d: %s", rec.Code, rec.Body.String())
	}
	// A release published after the licence end is denied.
	rec := mintURL(t, h, priv, instID, newRel)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "entitlement_expired") {
		t.Fatalf("newer mint = %d: %s", rec.Code, rec.Body.String())
	}
	// Unpublished release: not_published.
	unpub := fixtureArtifact(t, db, root, "0.0.1", "unpub", nil)
	if rec := mintURL(t, h, priv, instID, unpub); rec.Code != http.StatusConflict {
		t.Fatalf("unpublished mint = %d, want 409", rec.Code)
	}
}

// --- apt repository ---------------------------------------------------------

func writeAptFixture(t *testing.T, root string) {
	t.Helper()
	for rel, content := range map[string]string{
		"dists/stable/Release":                    "release-index",
		"dists/stable/main/binary-amd64/Packages": "packages-index",
		"pool/main/sp-platform_1.0.0_amd64.deb":   "old-deb",
		"pool/main/sp-platform_9.9.9_amd64.deb":   "new-deb",
	} {
		dest := filepath.Join(root, storage.Apt, rel)
		if err := os.MkdirAll(filepath.Dir(dest), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dest, []byte(content), 0o640); err != nil {
			t.Fatal(err)
		}
	}
}

func aptGet(t *testing.T, h http.Handler, path, user, pass string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("GET", "/apt/"+path, nil)
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAptFetchBasicAuth(t *testing.T) {
	h, db, _, root := testHandler(t)
	writeAptFixture(t, root)
	orgID := insertOrg(t, db)
	licID := insertLicence(t, db, orgID, nil, nil)
	instID, _ := insertInstance(t, db, orgID, licID)
	insertAptToken(t, db, orgID, "spapt_secret")

	// Missing and wrong credentials: 401 with the challenge.
	if rec := aptGet(t, h, "dists/stable/Release", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no auth = %d, want 401", rec.Code)
	}
	if rec := aptGet(t, h, "dists/stable/Release", instID, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad pass = %d, want 401", rec.Code)
	}
	rec := aptGet(t, h, "dists/stable/Release", instID, "spapt_secret")
	if rec.Code != http.StatusOK || rec.Body.String() != "release-index" {
		t.Fatalf("dists fetch = %d %q", rec.Code, rec.Body.String())
	}
	rec = aptGet(t, h, "pool/main/sp-platform_1.0.0_amd64.deb", instID, "spapt_secret")
	if rec.Code != http.StatusOK || rec.Body.String() != "old-deb" {
		t.Fatalf("pool fetch = %d %q", rec.Code, rec.Body.String())
	}
	// Traversal is refused.
	if rec := aptGet(t, h, "../releases/x", instID, "spapt_secret"); rec.Code != http.StatusNotFound {
		t.Fatalf("traversal = %d, want 404", rec.Code)
	}
}

func TestAptLicenceGating(t *testing.T) {
	h, db, _, root := testHandler(t)
	writeAptFixture(t, root)
	orgID := insertOrg(t, db)
	past := time.Now().Add(-time.Hour).UTC()
	licID := insertLicence(t, db, orgID, &past /* expired */, nil)
	instID, _ := insertInstance(t, db, orgID, licID)
	insertAptToken(t, db, orgID, "spapt_secret")
	// Catalogue rows pin the pool versions' publish times either side of
	// the licence end.
	older := time.Now().Add(-48 * time.Hour).UTC()
	recent := time.Now().UTC()
	insertRelease(t, db, "1.0.0", "", &older)
	insertRelease(t, db, "9.9.9", "", &recent)

	// Metadata always served (the client still sees the index).
	if rec := aptGet(t, h, "dists/stable/Release", instID, "spapt_secret"); rec.Code != http.StatusOK {
		t.Fatalf("metadata = %d, want 200", rec.Code)
	}
	// Older payload version: still downloadable.
	if rec := aptGet(t, h, "pool/main/sp-platform_1.0.0_amd64.deb", instID, "spapt_secret"); rec.Code != http.StatusOK {
		t.Fatalf("older pool = %d, want 200", rec.Code)
	}
	// Newer payload version: 403 entitlement_expired.
	rec := aptGet(t, h, "pool/main/sp-platform_9.9.9_amd64.deb", instID, "spapt_secret")
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "entitlement_expired") {
		t.Fatalf("newer pool = %d: %s", rec.Code, rec.Body.String())
	}
}

// --- support bundles --------------------------------------------------------

func TestSupportBundleUpload(t *testing.T) {
	h, db, _, root := testHandler(t)
	orgID := insertOrg(t, db)
	licID := insertLicence(t, db, orgID, nil, nil)
	instID, priv := insertInstance(t, db, orgID, licID)

	body := []byte("fake-gzip-support-bundle")
	rec := signedReq(t, h, priv, instID, "POST", "/support-bundles", body, "application/gzip")
	if rec.Code != http.StatusCreated {
		t.Fatalf("upload = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	id, _ := resp["id"].(string)
	data, err := os.ReadFile(filepath.Join(root, storage.SupportBundles, orgID, id+".tar.gz"))
	if err != nil || !bytes.Equal(data, body) {
		t.Fatalf("bundle on disk: %v %q", err, data)
	}
	var path string
	if err := db.QueryRow(`SELECT path FROM support_bundles WHERE id=?`, id).Scan(&path); err != nil {
		t.Fatalf("bundle row: %v", err)
	}
	// Unsupported media type: 415.
	rec = signedReq(t, h, priv, instID, "POST", "/support-bundles", body, "text/plain")
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("text/plain = %d, want 415", rec.Code)
	}
	// Unauthenticated: 401.
	if rec := doReq(t, h, "POST", "/support-bundles", bytes.NewReader(body),
		"application/gzip", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthed = %d, want 401", rec.Code)
	}
}

// --- offline bundles + prune -------------------------------------------------

func TestOfflineBundleGenerateAndVerify(t *testing.T) {
	h, db, acct, root := testHandler(t)
	cookie := staffCookie(t, db, acct, true)
	now := time.Now().UTC()
	relID := fixtureArtifact(t, db, root, "1.4.2", "bundle-me", &now)

	rec := doReq(t, h, "POST", "/admin/releases/"+relID+"/offline-bundle", nil, "", cookie)
	if rec.Code != http.StatusCreated {
		t.Fatalf("generate = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	name := resp["bundle"].(string)
	data, err := os.ReadFile(filepath.Join(root, storage.OfflineBundles, name))
	if err != nil {
		t.Fatalf("bundle file: %v", err)
	}
	kid, pub, err := licensing.DevVerificationKey()
	if err != nil {
		t.Fatal(err)
	}
	v, err := bundles.Verify(bytes.NewReader(data),
		map[string]ed25519.PublicKey{kid: pub})
	if err != nil {
		t.Fatalf("bundle verify: %v", err)
	}
	if v.Manifest.Release.Version != "1.4.2" {
		t.Fatalf("manifest release: %+v", v.Manifest.Release)
	}
	if string(v.Payload["sp-platform-1.4.2.tar.gz"]) != "bundle-me" {
		t.Fatalf("payload: %v", v.Payload)
	}
	// The list endpoint sees it.
	rec = doReq(t, h, "GET", "/admin/offline-bundles", nil, "", cookie)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), name) {
		t.Fatalf("list = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStoragePrune(t *testing.T) {
	h, db, acct, root := testHandler(t)
	cookie := staffCookie(t, db, acct, true)
	now := time.Now().UTC()
	keep := fixtureArtifact(t, db, root, "1.0.0", "keep", &now)
	_ = keep
	writeArtifact(t, root, "platform/9.9.9/orphan.bin", "orphan")

	// Dry run reports, deletes nothing.
	rec := doReq(t, h, "POST", "/admin/storage/prune",
		strings.NewReader(`{"dry_run":true}`), "application/json", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("dry prune = %d: %s", rec.Code, rec.Body.String())
	}
	var dry map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &dry); err != nil {
		t.Fatal(err)
	}
	removed, _ := dry["removed"].([]any)
	if len(removed) != 1 || removed[0] != filepath.Join("platform", "9.9.9", "orphan.bin") {
		t.Fatalf("dry removed: %v", removed)
	}
	if _, err := os.Stat(filepath.Join(root, storage.Releases, "platform/9.9.9/orphan.bin")); err != nil {
		t.Fatal("dry run deleted the file")
	}
	// Real run deletes the orphan, keeps the referenced artifact.
	rec = doReq(t, h, "POST", "/admin/storage/prune", nil, "", cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("prune = %d: %s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(filepath.Join(root, storage.Releases, "platform/9.9.9/orphan.bin")); !os.IsNotExist(err) {
		t.Fatalf("orphan still present: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, storage.Releases, "platform/1.0.0/sp-platform-1.0.0.tar.gz")); err != nil {
		t.Fatalf("referenced artifact pruned: %v", err)
	}
}
