// Integration tests for the licensing endpoints against a real MariaDB
// (internal/testutil): activation, seat limits, clone detection, the
// SP-Ed25519 auth failures (forged signature, stale timestamp, replay,
// wrong key), document tampering and the offline activation round trip.
package licensing_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/instauth"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// --- fixtures -----------------------------------------------------------

func testHandler(t *testing.T, opts licensing.Options) (http.Handler, *sql.DB) {
	t.Helper()
	db := testutil.MariaDB(t)
	if opts.Issuer == nil {
		issuer, err := licensing.DevIssuer()
		if err != nil {
			t.Fatal(err)
		}
		opts.Issuer = issuer
	}
	return licensing.Routes(db, nil, opts), db
}

func insertOrg(t *testing.T, db *sql.DB) string {
	t.Helper()
	id := uuid.Must(uuid.NewV7()).String()
	// uuidv7's head is the timestamp; the tail is random — use it for
	// unique slugs/keys across fixtures created in the same millisecond.
	slug := "org-" + id[len(id)-12:]
	if _, err := db.Exec(
		`INSERT INTO organisations (id, name, slug) VALUES (?, ?, ?)`,
		id, "Test Org", slug); err != nil {
		t.Fatalf("insert org: %v", err)
	}
	return id
}

func insertLicence(t *testing.T, db *sql.DB, orgID string, maxInstances int,
	expiresAt, revokedAt *time.Time) (id, key string) {
	t.Helper()
	id = uuid.Must(uuid.NewV7()).String()
	key = "SPL-" + id[len(id)-12:]
	if _, err := db.Exec(
		`INSERT INTO licences (id, org_id, licence_key, kind, plan, max_instances,
		                       expires_at, revoked_at)
		 VALUES (?, ?, ?, 'subscription', 'pro', ?, ?, ?)`,
		id, orgID, key, maxInstances, expiresAt, revokedAt); err != nil {
		t.Fatalf("insert licence: %v", err)
	}
	return id, key
}

func insertRelease(t *testing.T, db *sql.DB, version string) {
	t.Helper()
	if _, err := db.Exec(
		`INSERT INTO releases (id, version, component, channel, notes, published_at)
		 VALUES (?, ?, 'platform', 'stable', '', UTC_TIMESTAMP(6))`,
		uuid.Must(uuid.NewV7()).String(), version); err != nil {
		t.Fatalf("insert release: %v", err)
	}
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv, base64.StdEncoding.EncodeToString(pub)
}

func doReq(t *testing.T, h http.Handler, method, path string, body any, auth string) *httptest.ResponseRecorder {
	t.Helper()
	var reader io.Reader
	switch b := body.(type) {
	case nil:
	case []byte:
		reader = strings.NewReader(string(b))
	case string:
		reader = strings.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, path, reader)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// signedReq issues an authed request with the given signing inputs.
func signedReq(t *testing.T, h http.Handler, priv ed25519.PrivateKey, instanceID,
	method, path string, ts int64, nonce string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	auth, err := instauth.SignRequest(priv, instanceID, method, path, ts, nonce, body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(string(body)))
	req.Header.Set("Authorization", auth)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// activate performs a full activation and returns the parsed response.
func activate(t *testing.T, h http.Handler, key, instanceID, pubB64 string) map[string]any {
	t.Helper()
	rec := doReq(t, h, "POST", "/activations", map[string]string{
		"licence_key": key, "instance_id": instanceID, "public_key": pubB64,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("activation = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func activatedInstance(t *testing.T, resp map[string]any) (instanceID, docRaw string) {
	t.Helper()
	inst, ok := resp["instance"].(map[string]any)
	if !ok {
		t.Fatalf("no instance in response: %v", resp)
	}
	doc, err := json.Marshal(resp["licence"])
	if err != nil {
		t.Fatal(err)
	}
	return inst["id"].(string), string(doc)
}

func devTrust(t *testing.T) map[string]ed25519.PublicKey {
	t.Helper()
	kid, pub, err := licensing.DevVerificationKey()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{kid: pub}
}

// --- activation ---------------------------------------------------------

func TestActivationFlow(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 3, nil, nil)
	_, _, pubB64 := newKey(t)

	resp := activate(t, h, licKey, "machine-1", pubB64)
	instID, docRaw := activatedInstance(t, resp)

	// The returned document verifies against the dev trust anchor.
	payload, err := licensing.VerifyDocument([]byte(docRaw), devTrust(t))
	if err != nil {
		t.Fatalf("verify issued doc: %v", err)
	}
	if payload.LicenceKey != licKey || payload.InstanceID != "machine-1" || payload.MaxInstances != 3 {
		t.Fatalf("payload mismatch: %+v", payload)
	}

	// Instance row, key binding and doc-hash audit event exist.
	var fp, status string
	if err := db.QueryRow(`SELECT fingerprint, status FROM instances WHERE id = ?`, instID).
		Scan(&fp, &status); err != nil {
		t.Fatalf("instance row: %v", err)
	}
	if fp != "machine-1" || status != "active" {
		t.Fatalf("instance = (%q,%q)", fp, status)
	}
	var bound int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='instance.key_bound' AND target_id=?`, instID).
		Scan(&bound); err != nil || bound != 1 {
		t.Fatalf("key_bound events = %d, err %v", bound, err)
	}
	var docEvents int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='licence.document_issued'`).Scan(&docEvents); err != nil || docEvents < 1 {
		t.Fatalf("document_issued events = %d, err %v", docEvents, err)
	}
	var apt int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM download_tokens WHERE kind='apt'`).Scan(&apt); err != nil || apt != 1 {
		t.Fatalf("apt tokens = %d, err %v", apt, err)
	}
	creds, ok := resp["apt_credentials"].(map[string]any)
	if !ok || creds["username"] != instID || !strings.HasPrefix(creds["password"].(string), "spapt_") {
		t.Fatalf("apt credentials: %v", resp["apt_credentials"])
	}
}

func TestActivationLicenceStates(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	past := time.Now().Add(-time.Hour).UTC()
	_, expiredKey := insertLicence(t, db, orgID, 3, &past, nil)
	_, revokedKey := insertLicence(t, db, orgID, 3, nil, &past)
	_, _, pubB64 := newKey(t)

	for _, tc := range []struct {
		key  string
		want int
	}{
		{"no-such-key", http.StatusNotFound},
		{expiredKey, http.StatusForbidden},
		{revokedKey, http.StatusForbidden},
	} {
		rec := doReq(t, h, "POST", "/activations", map[string]string{
			"licence_key": tc.key, "instance_id": "m", "public_key": pubB64,
		}, "")
		if rec.Code != tc.want {
			t.Fatalf("key %q: got %d want %d (%s)", tc.key, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestActivationSeatLimit(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 1, nil, nil)

	_, _, pub1 := newKey(t)
	activate(t, h, licKey, "machine-a", pub1)

	_, _, pub2 := newKey(t)
	rec := doReq(t, h, "POST", "/activations", map[string]string{
		"licence_key": licKey, "instance_id": "machine-b", "public_key": pub2,
	}, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("second seat activation = %d, want 409 (%s)", rec.Code, rec.Body.String())
	}
}

func TestReactivationIdempotent(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 1, nil, nil)
	_, _, pubB64 := newKey(t)

	r1 := activate(t, h, licKey, "machine-1", pubB64)
	r2 := activate(t, h, licKey, "machine-1", pubB64)
	id1, _ := activatedInstance(t, r1)
	id2, _ := activatedInstance(t, r2)
	if id1 != id2 {
		t.Fatalf("reactivation created a new instance: %s vs %s", id1, id2)
	}
	if r2["instance"].(map[string]any)["suspected_clone"] != false {
		t.Fatal("same-key reactivation flagged as clone")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM instances`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("instances = %d", n)
	}
}

// --- clone detection ----------------------------------------------------

func TestCloneDetection(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 2, nil, nil)
	_, priv1, pubB64a := newKey(t)
	_, priv2, pubB64b := newKey(t)

	resp1 := activate(t, h, licKey, "machine-clone-me", pubB64a)
	instID, _ := activatedInstance(t, resp1)

	// Same machine identity, different key: flagged, not blocked.
	resp2 := activate(t, h, licKey, "machine-clone-me", pubB64b)
	inst2, _ := activatedInstance(t, resp2)
	if inst2 != instID {
		t.Fatalf("clone activation made a new instance: %s vs %s", inst2, instID)
	}
	if resp2["instance"].(map[string]any)["suspected_clone"] != true {
		t.Fatal("clone activation not flagged")
	}
	var flags int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='instance.suspected_clone' AND target_id=?`, instID).
		Scan(&flags); err != nil || flags != 1 {
		t.Fatalf("clone flag events = %d, err %v", flags, err)
	}
	// Third activation with yet another key doesn't duplicate the flag.
	_, _, pubB64c := newKey(t)
	activate(t, h, licKey, "machine-clone-me", pubB64c)
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM audit_log WHERE action='instance.suspected_clone' AND target_id=?`, instID).
		Scan(&flags); err != nil || flags != 1 {
		t.Fatalf("clone flags = %d, want 1", flags)
	}

	// The original key still authenticates and sees suspected_clone.
	body := []byte(`{"appliance_version":"1.0.0"}`)
	rec := signedReq(t, h, priv1, instID, "POST", "/check-ins",
		time.Now().Unix(), "c1", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("original check-in = %d: %s", rec.Code, rec.Body.String())
	}
	var checkin map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &checkin); err != nil {
		t.Fatal(err)
	}
	if checkin["status"] != "suspected_clone" {
		t.Fatalf("status = %v, want suspected_clone", checkin["status"])
	}
	msgs, _ := checkin["messages"].([]any)
	found := false
	for _, m := range msgs {
		if m.(map[string]any)["code"] == "suspected_clone" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no suspected_clone message: %v", checkin["messages"])
	}

	// The clone's key cannot authenticate (wrong_key).
	rec = signedReq(t, h, priv2, instID, "POST", "/check-ins",
		time.Now().Unix(), "c2", body)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("clone check-in = %d, want 401", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "wrong_key") {
		t.Fatalf("clone rejection = %s, want wrong_key", rec.Body.String())
	}
}

// --- instance auth rejections -------------------------------------------

// authedInstance activates an appliance and returns what signedReq needs.
func authedInstance(t *testing.T, h http.Handler, db *sql.DB) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 2, nil, nil)
	pub, priv, pubB64 := newKey(t)
	machine := "machine-" + uuid.Must(uuid.NewV7()).String()
	resp := activate(t, h, licKey, machine[len(machine)-12:], pubB64)
	instID, _ := activatedInstance(t, resp)
	return instID, pub, priv
}

func checkIn(t *testing.T, h http.Handler, priv ed25519.PrivateKey, instID, nonce string) *httptest.ResponseRecorder {
	t.Helper()
	return signedReq(t, h, priv, instID, "POST", "/check-ins",
		time.Now().Unix(), nonce, []byte(`{"appliance_version":"1.0.0"}`))
}

func TestCheckInHappyPath(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, priv := authedInstance(t, h, db)
	insertRelease(t, db, "1.4.2")

	rec := checkIn(t, h, priv, instID, "n-happy")
	if rec.Code != http.StatusOK {
		t.Fatalf("check-in = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["status"] != "active" || resp["entitled_updates"] != true {
		t.Fatalf("check-in response: %v", resp)
	}
	doc, _ := json.Marshal(resp["licence"])
	if _, err := licensing.VerifyDocument(doc, devTrust(t)); err != nil {
		t.Fatalf("check-in doc does not verify: %v", err)
	}
	rel, _ := resp["latest_release"].(map[string]any)
	if rel["version"] != "1.4.2" {
		t.Fatalf("latest_release = %v", resp["latest_release"])
	}
	var reports int
	if err := db.QueryRow(`SELECT COUNT(*) FROM instance_reports WHERE instance_id=?`, instID).
		Scan(&reports); err != nil || reports != 1 {
		t.Fatalf("reports = %d, err %v", reports, err)
	}
	var seen sql.NullTime
	if err := db.QueryRow(`SELECT last_seen_at FROM instances WHERE id=?`, instID).
		Scan(&seen); err != nil || !seen.Valid {
		t.Fatalf("last_seen_at not set: %v", err)
	}
}

func TestGetLicenceAuthed(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, priv := authedInstance(t, h, db)
	rec := signedReq(t, h, priv, instID, "GET", "/licence",
		time.Now().Unix(), "g1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /licence = %d: %s", rec.Code, rec.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	doc, _ := json.Marshal(resp["licence"])
	if _, err := licensing.VerifyDocument(doc, devTrust(t)); err != nil {
		t.Fatalf("GET /licence doc does not verify: %v", err)
	}
	if resp["status"] != "active" {
		t.Fatalf("status = %v", resp["status"])
	}
}

func TestForgedSignatureRejected(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, pub, _ := authedInstance(t, h, db)

	// Sign with a different private key but present the bound pubkey —
	// the key check passes, the signature fails.
	_, priv2, _ := newKey(t)
	body := []byte(`{"appliance_version":"1.0.0"}`)
	ts := time.Now().Unix()
	sig := ed25519.Sign(priv2, instauth.StringToSign("POST", "/check-ins", ts, "f1", body))
	auth := instauth.Authorization(instID, pub, ts, "f1", sig)
	rec := doReq(t, h, "POST", "/check-ins", body, auth)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bad_signature") {
		t.Fatalf("forged sig = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestStaleTimestampRejected(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, priv := authedInstance(t, h, db)
	stale := time.Now().Add(-11 * time.Minute).Unix()
	rec := signedReq(t, h, priv, instID, "POST", "/check-ins", stale, "stale1",
		[]byte(`{"appliance_version":"1.0.0"}`))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "stale_timestamp") {
		t.Fatalf("stale ts = %d: %s", rec.Code, rec.Body.String())
	}
	future := time.Now().Add(11 * time.Minute).Unix()
	rec = signedReq(t, h, priv, instID, "POST", "/check-ins", future, "stale2",
		[]byte(`{"appliance_version":"1.0.0"}`))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "stale_timestamp") {
		t.Fatalf("future ts = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestReplayRejected(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, priv := authedInstance(t, h, db)
	body := []byte(`{"appliance_version":"1.0.0"}`)
	ts := time.Now().Unix()
	auth, err := instauth.SignRequest(priv, instID, "POST", "/check-ins", ts, "replay1", body)
	if err != nil {
		t.Fatal(err)
	}
	rec1 := doReq(t, h, "POST", "/check-ins", body, auth)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first request = %d: %s", rec1.Code, rec1.Body.String())
	}
	// Identical request — the same signature — is a replay.
	rec2 := doReq(t, h, "POST", "/check-ins", body, auth)
	if rec2.Code != http.StatusUnauthorized || !strings.Contains(rec2.Body.String(), "replay") {
		t.Fatalf("replay = %d: %s", rec2.Code, rec2.Body.String())
	}
	// A fresh nonce makes a distinct, accepted signature.
	rec3 := signedReq(t, h, priv, instID, "POST", "/check-ins", ts, "replay2", body)
	if rec3.Code != http.StatusOK {
		t.Fatalf("fresh nonce = %d: %s", rec3.Code, rec3.Body.String())
	}
}

func TestWrongKeyRejected(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, _ := authedInstance(t, h, db)
	_, priv2, _ := newKey(t)
	rec := signedReq(t, h, priv2, instID, "POST", "/check-ins",
		time.Now().Unix(), "wk1", []byte(`{"appliance_version":"1.0.0"}`))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "wrong_key") {
		t.Fatalf("wrong key = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAuthHeaderRejections(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	instID, _, priv := authedInstance(t, h, db)

	// No header at all.
	rec := doReq(t, h, "POST", "/check-ins", map[string]string{}, "")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bad_auth_header") {
		t.Fatalf("no header = %d: %s", rec.Code, rec.Body.String())
	}
	// Unknown instance id, validly signed.
	rec = signedReq(t, h, priv, uuid.Must(uuid.NewV7()).String(), "POST", "/check-ins",
		time.Now().Unix(), "u1", []byte(`{}`))
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "unknown_instance") {
		t.Fatalf("unknown instance = %d: %s", rec.Code, rec.Body.String())
	}
	// Tampered body under a valid signature (signed over different body).
	auth, err := instauth.SignRequest(priv, instID, "POST", "/check-ins",
		time.Now().Unix(), "tb1", []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	rec = doReq(t, h, "POST", "/check-ins", []byte(`{"a":2}`), auth)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Body.String(), "bad_signature") {
		t.Fatalf("tampered body = %d: %s", rec.Code, rec.Body.String())
	}
}

func TestInstanceRateLimit(t *testing.T) {
	h, db := testHandler(t, licensing.Options{RateLimitPerMin: 2})
	instID, _, priv := authedInstance(t, h, db)
	for i := range 2 {
		if rec := checkIn(t, h, priv, instID, fmt.Sprintf("rl%d", i)); rec.Code != http.StatusOK {
			t.Fatalf("request %d = %d", i, rec.Code)
		}
	}
	if rec := checkIn(t, h, priv, instID, "rl-x"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit = %d, want 429 (%s)", rec.Code, rec.Body.String())
	}
}

// --- offline activation --------------------------------------------------

func TestOfflineActivationRoundTrip(t *testing.T) {
	h, db := testHandler(t, licensing.Options{})
	orgID := insertOrg(t, db)
	_, licKey := insertLicence(t, db, orgID, 2, nil, nil)
	_, _, pubB64 := newKey(t)

	rec := doReq(t, h, "POST", "/offline/activations", map[string]string{
		"org_id": orgID, "licence_key": licKey,
		"instance_id": "airgap-1", "public_key": pubB64,
	}, "")
	if rec.Code != http.StatusCreated {
		t.Fatalf("offline activation = %d: %s", rec.Code, rec.Body.String())
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.HasPrefix(cd, "attachment") {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	var bundle map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle["bundle_version"] != float64(1) {
		t.Fatalf("bundle_version = %v", bundle["bundle_version"])
	}

	// Verify the document purely against the bundle's verification_keys —
	// the air-gapped round trip.
	keys := bundle["verification_keys"].([]any)
	trust := map[string]ed25519.PublicKey{}
	for _, k := range keys {
		km := k.(map[string]any)
		raw, err := base64.StdEncoding.DecodeString(km["public_key"].(string))
		if err != nil {
			t.Fatal(err)
		}
		trust[km["kid"].(string)] = ed25519.PublicKey(raw)
	}
	doc, _ := json.Marshal(bundle["licence"])
	payload, err := licensing.VerifyDocument(doc, trust)
	if err != nil {
		t.Fatalf("bundle doc verify: %v", err)
	}
	if payload.InstanceID != "airgap-1" {
		t.Fatalf("payload instance = %q", payload.InstanceID)
	}

	// The instance is registered and the presented key bound.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM instances WHERE fingerprint='airgap-1'`).
		Scan(&n); err != nil || n != 1 {
		t.Fatalf("airgap instance rows = %d", n)
	}

	// Licence belonging to another org is refused.
	org2 := insertOrg(t, db)
	_, licKey2 := insertLicence(t, db, org2, 2, nil, nil)
	rec = doReq(t, h, "POST", "/offline/activations", map[string]string{
		"org_id": orgID, "licence_key": licKey2, "instance_id": "x",
	}, "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org offline activation = %d, want 403", rec.Code)
	}
}
