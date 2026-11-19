package accounts

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// newService builds a Service over the test DB with captcha disabled and
// a real jobs queue (mail jobs land in the table for inspection).
func newService(t *testing.T, db *sql.DB) *Service {
	t.Helper()
	s, err := New(db, Options{
		Secret:           []byte("test-auth-secret-0123456789abcdef"),
		SessionTTL:       time.Hour,
		PublicBaseURL:    "http://portal.test",
		TrialDays:        30,
		TrialMaxMachines: 25,
		Queue:            jobs.NewQueue(db),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func signupInput(email string) SignupInput {
	return SignupInput{
		Email: email, Password: "a very good password",
		DisplayName: "Test User", OrgName: "Test Org " + email, IP: "127.0.0.1",
	}
}

func countAudit(t *testing.T, db *sql.DB, action string) int64 {
	t.Helper()
	var n int64
	if err := db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func TestSignupCreatesTrial(t *testing.T) {
	db := testutil.MariaDB(t)
	svc := newService(t, db)
	ctx := context.Background()

	res, err := svc.Signup(ctx, signupInput("alice@example.com"))
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if res.Session.Stage != StagePendingSetup {
		t.Fatalf("new owner session = %q, want pending setup", res.Session.Stage)
	}
	q := dbq.New(db)
	// membership: owner
	m, err := q.GetMembership(ctx, dbq.GetMembershipParams{OrgID: res.Org.ID, UserID: res.User.ID})
	if err != nil || m.Role != RoleOwner {
		t.Fatalf("membership: %+v %v", m, err)
	}
	// subscription: 30-day trial
	sub, err := q.GetLatestSubscriptionByOrg(ctx, res.Org.ID)
	if err != nil {
		t.Fatalf("subscription: %v", err)
	}
	if sub.Plan != "trial" || sub.Status != "trialing" {
		t.Fatalf("subscription = %s/%s, want trial/trialing", sub.Plan, sub.Status)
	}
	if sub.CurrentPeriodEnd == nil ||
		sub.CurrentPeriodEnd.Before(svc.now().Add(29*24*time.Hour)) {
		t.Fatalf("trial end not ~30d out: %v", sub.CurrentPeriodEnd)
	}
	// licence: 25-machine trial
	var kind string
	var maxInst int
	if err := db.QueryRowContext(ctx,
		`SELECT kind, max_instances FROM licences WHERE org_id = ?`, res.Org.ID).
		Scan(&kind, &maxInst); err != nil {
		t.Fatalf("licence: %v", err)
	}
	if kind != "trial" || maxInst != 25 {
		t.Fatalf("licence = %s/%d machines, want trial/25", kind, maxInst)
	}
	// audit rows for both state changes
	if countAudit(t, db, audit.ActionSignup) != 1 || countAudit(t, db, audit.ActionOrgCreated) != 1 {
		t.Fatal("missing signup/org.created audit rows")
	}
	// verification mail was enqueued
	var payload []byte
	if err := db.QueryRowContext(ctx,
		`SELECT payload FROM jobs WHERE kind = 'mail.send' LIMIT 1`).Scan(&payload); err != nil {
		t.Fatalf("verification mail job: %v", err)
	}
	if !strings.Contains(string(payload), "verify-email?token=") {
		t.Fatalf("mail payload lacks verification link: %s", payload)
	}
	// duplicate email rejected
	if _, err := svc.Signup(ctx, signupInput("alice@example.com")); err != ErrEmailTaken {
		t.Fatalf("duplicate signup err = %v, want ErrEmailTaken", err)
	}
}

func TestLoginStagesAndTOTP(t *testing.T) {
	db := testutil.MariaDB(t)
	svc := newService(t, db)
	ctx := context.Background()

	if _, err := svc.Signup(ctx, signupInput("bob@example.com")); err != nil {
		t.Fatalf("Signup: %v", err)
	}
	// bad password fails uniformly
	if _, err := svc.Login(ctx, LoginInput{Email: "bob@example.com", Password: "nope"}); err != ErrBadCredentials {
		t.Fatalf("bad login err = %v", err)
	}
	if countAudit(t, db, audit.ActionLoginFailed) != 1 {
		t.Fatal("login failure not audited")
	}
	// owner without TOTP -> pending setup
	lr, err := svc.Login(ctx, LoginInput{Email: "bob@example.com", Password: "a very good password"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if lr.Session.Stage != StagePendingSetup {
		t.Fatalf("stage = %q, want setup", lr.Session.Stage)
	}
	// enrol
	uri, secret, err := svc.TOTPSetup(ctx, lr.Session)
	if err != nil {
		t.Fatalf("TOTPSetup: %v", err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/") || secret == "" {
		t.Fatalf("bad setup output: %q %q", uri, secret)
	}
	code, err := TOTPCode(secret, svc.now())
	if err != nil {
		t.Fatalf("code: %v", err)
	}
	full, err := svc.TOTPEnable(ctx, lr.Session, code, "127.0.0.1")
	if err != nil {
		t.Fatalf("TOTPEnable: %v", err)
	}
	if !full.Full() {
		t.Fatal("session not full after enable")
	}
	if countAudit(t, db, audit.ActionTOTPEnabled) != 1 {
		t.Fatal("totp enable not audited")
	}
	// now login requires the TOTP step
	lr2, err := svc.Login(ctx, LoginInput{Email: "bob@example.com", Password: "a very good password"})
	if err != nil || lr2.Session.Stage != StagePendingTOTP {
		t.Fatalf("post-TOTP login stage = %v %q", err, lr2.Session.Stage)
	}
	if _, err := svc.CompleteTOTPLogin(ctx, lr2.Session, "000000", "127.0.0.1"); err != ErrBadTOTP {
		t.Fatalf("bad code err = %v", err)
	}
	code2, _ := TOTPCode(secret, svc.now())
	full2, err := svc.CompleteTOTPLogin(ctx, lr2.Session, code2, "127.0.0.1")
	if err != nil || !full2.Full() {
		t.Fatalf("complete login: %v full=%v", err, full2.Full())
	}
	// owners may not disable TOTP
	if err := svc.TOTPDisable(ctx, full2, code2, "127.0.0.1"); err != ErrTOTPRequiredOwner {
		t.Fatalf("owner disable err = %v", err)
	}
}

func TestEmailVerification(t *testing.T) {
	db := testutil.MariaDB(t)
	svc := newService(t, db)
	ctx := context.Background()

	res, err := svc.Signup(ctx, signupInput("carol@example.com"))
	if err != nil {
		t.Fatalf("Signup: %v", err)
	}
	if ok, _ := svc.EmailVerified(ctx, res.User.ID); ok {
		t.Fatal("verified before verification")
	}
	tok := svc.issueVerifyToken(res.User)
	if err := svc.VerifyEmail(ctx, tok, "127.0.0.1"); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if ok, _ := svc.EmailVerified(ctx, res.User.ID); !ok {
		t.Fatal("not verified after token")
	}
	// replay is idempotent, forged tokens fail
	if err := svc.VerifyEmail(ctx, tok, "127.0.0.1"); err != nil {
		t.Fatalf("replayed token: %v", err)
	}
	if err := svc.VerifyEmail(ctx, tok[:len(tok)-2]+"xx", "127.0.0.1"); err != ErrBadToken {
		t.Fatalf("forged token err = %v", err)
	}
	if countAudit(t, db, audit.ActionEmailVerified) != 1 {
		t.Fatal("expected exactly one email_verified audit row")
	}
}

// TestHTTPFlow exercises the routes end to end: signup -> cookie ->
// pending session -> TOTP enrolment -> full session.
func TestHTTPFlow(t *testing.T) {
	db := testutil.MariaDB(t)
	svc := newService(t, db)
	srv := httptest.NewServer(Routes(svc))
	defer srv.Close()

	post := func(path, body string, cookies []*http.Cookie) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		Routes(svc).ServeHTTP(rec, req)
		return rec
	}

	rec := post("/auth/signup", `{"email":"dave@example.com","password":"a very good password","org_name":"Dave Co"}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup = %d %s", rec.Code, rec.Body)
	}
	var cookies []*http.Cookie
	var session *http.Cookie
	for _, c := range rec.Result().Cookies() {
		cookies = append(cookies, c)
		if c.Name == SessionCookie {
			session = c
		}
	}
	if session == nil || !session.HttpOnly {
		t.Fatalf("missing/non-httpOnly session cookie: %+v", session)
	}
	// pending session: /me works, org routes don't.
	get := func(path string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		Routes(svc).ServeHTTP(rec, req)
		return rec
	}
	if rec := get("/auth/me"); rec.Code != http.StatusOK {
		t.Fatalf("me = %d", rec.Code)
	}
	if rec := get("/organisations"); rec.Code != http.StatusForbidden {
		t.Fatalf("pending org list = %d, want 403", rec.Code)
	}
	// enrol TOTP via the endpoints
	rec = post("/auth/totp/setup", `{}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp setup = %d %s", rec.Code, rec.Body)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &setup); err != nil || setup.Secret == "" {
		t.Fatalf("setup response: %v %s", err, rec.Body)
	}
	code, _ := TOTPCode(setup.Secret, svc.now())
	rec = post("/auth/totp/enable", `{"code":"`+code+`"}`, cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("totp enable = %d %s", rec.Code, rec.Body)
	}
	// new session cookie (stage=full) — replace cookie jar
	cookies = nil
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			cookies = append(cookies, c)
		}
	}
	rec = get("/organisations")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Dave Co") {
		t.Fatalf("org list = %d %s", rec.Code, rec.Body)
	}
	// no cookie -> 401
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/organisations", nil)
	rec = httptest.NewRecorder()
	Routes(svc).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated org list = %d", rec.Code)
	}
}
