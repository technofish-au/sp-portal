package billing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// --- stub Stripe client --------------------------------------------------

type stubCall struct {
	Method string
	Params any
}

// stubStripe is a recording Client for tests — no live API calls.
type stubStripe struct {
	mu    sync.Mutex
	calls []stubCall
	custN int
}

func (s *stubStripe) record(method string, params any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, stubCall{Method: method, Params: params})
}

func (s *stubStripe) CreateCheckoutSession(_ context.Context, p CheckoutSessionParams) (*CheckoutSession, error) {
	s.record("checkout", p)
	return &CheckoutSession{ID: "cs_test_1", URL: "https://checkout.stripe.test/cs_test_1"}, nil
}

func (s *stubStripe) CreatePortalSession(_ context.Context, p PortalSessionParams) (*PortalSession, error) {
	s.record("portal", p)
	return &PortalSession{ID: "bps_1", URL: "https://billing.stripe.test/bps_1"}, nil
}

func (s *stubStripe) EnsureCustomer(_ context.Context, p CustomerParams) (*Customer, error) {
	s.record("customer", p)
	s.mu.Lock()
	s.custN++
	id := fmt.Sprintf("cus_stub_%d", s.custN)
	s.mu.Unlock()
	return &Customer{ID: id}, nil
}

func (s *stubStripe) SendSubscriptionInvoice(_ context.Context, p InvoiceParams) (*InvoiceResult, error) {
	s.record("invoice", p)
	return &InvoiceResult{
		SubscriptionID:   "sub_stub_inv",
		InvoiceID:        "in_stub_1",
		HostedInvoiceURL: "https://invoice.stripe.test/in_stub_1",
	}, nil
}

// --- fixtures --------------------------------------------------------------

func testDeps(db *sql.DB, stub *stubStripe, secret string) Deps {
	return Deps{
		DB: db, Queue: jobs.NewQueue(db),
		Client:        stub,
		WebhookSecret: secret,
		PublicBaseURL: "http://portal.test",
		Prices:        map[string]string{"pro": "price_pro_123", "starter": "price_start_1", "enterprise": "price_ent_1"},
		AutomaticTax:  true,
		PastDueGrace:  14 * 24 * time.Hour,
		SweepInterval: time.Hour,
	}
}

// fixtureOrg seeds an org + trial subscription (as sign-up would).
func fixtureOrg(t *testing.T, db *sql.DB) (orgID, subID string) {
	t.Helper()
	q := dbq.New(db)
	ctx := context.Background()
	orgID = "org-" + strings.ReplaceAll(fmt.Sprint(time.Now().UnixNano()), "-", "")
	subID = "sub-local-" + fmt.Sprint(time.Now().UnixNano())
	if err := q.CreateOrganisation(ctx, dbq.CreateOrganisationParams{
		ID: orgID, Name: "Fixture Org", Slug: "fixture-" + orgID[len(orgID)-8:], BillingEmail: "billing@fixture.test",
	}); err != nil {
		t.Fatalf("org: %v", err)
	}
	now := time.Now().UTC()
	end := now.Add(30 * 24 * time.Hour)
	if err := q.CreateSubscription(ctx, dbq.CreateSubscriptionParams{
		ID: subID, OrgID: orgID, Plan: "trial", Status: "trialing",
		Seats: 1, CurrentPeriodStart: &now, CurrentPeriodEnd: &end,
	}); err != nil {
		t.Fatalf("subscription: %v", err)
	}
	return orgID, subID
}

// event builds a Stripe event payload.
func event(t *testing.T, id, typ string, obj any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"id": id, "type": typ, "livemode": false,
		"data": map[string]any{"object": obj},
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func subObject(id, customer, status, orgID string) map[string]any {
	return map[string]any{
		"id": id, "customer": customer, "status": status,
		"metadata": map[string]any{"org_id": orgID},
		"items": map[string]any{"data": []map[string]any{
			{"price": map[string]any{"id": "price_pro_123"}, "quantity": 2},
		}},
		"current_period_start": 1_700_000_000,
		"current_period_end":   1_700_300_000,
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

func subStatus(t *testing.T, db *sql.DB, subID string) string {
	t.Helper()
	var s string
	if err := db.QueryRowContext(context.Background(),
		`SELECT status FROM subscriptions WHERE id = ?`, subID).Scan(&s); err != nil {
		t.Fatalf("sub status: %v", err)
	}
	return s
}

// --- tests -----------------------------------------------------------------

// TestWebhookForgedRejected is acceptance: a forged signature is a 400 and
// nothing reaches stripe_events or jobs.
func TestWebhookForgedRejected(t *testing.T) {
	db := testutil.MariaDB(t)
	d := testDeps(db, &stubStripe{}, "whsec_forge")
	r := WebhookRoutes(d)

	body := event(t, "evt_forged", "customer.subscription.updated", subObject("sub_1", "cus_1", "active", "x"))
	req, _ := http.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
	req.Header.Set("Stripe-Signature", signBody(body, "whsec_wrong", time.Now().UTC()))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("forged webhook = %d, want 400", rec.Code)
	}
	var n int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("stripe_events has %d rows (err %v)", n, err)
	}
}

// TestWebhookReplayExactlyOnce is acceptance: the same signed event
// delivered twice is stored+processed exactly once.
func TestWebhookReplayExactlyOnce(t *testing.T) {
	db := testutil.MariaDB(t)
	stub := &stubStripe{}
	secret := "whsec_replay"
	d := testDeps(db, stub, secret)
	r := WebhookRoutes(d)
	ctx := context.Background()
	orgID, subID := fixtureOrg(t, db)

	body := event(t, "evt_replay", "customer.subscription.updated", subObject("sub_stripe_1", "cus_x", "active", orgID))
	post := func() *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodPost, "/webhook", strings.NewReader(string(body)))
		req.Header.Set("Stripe-Signature", signBody(body, secret, time.Now().UTC()))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}
	if rec := post(); rec.Code != http.StatusOK {
		t.Fatalf("first delivery = %d %s", rec.Code, rec.Body)
	}
	rec := post()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"duplicate":true`) {
		t.Fatalf("redelivery = %d %s", rec.Code, rec.Body)
	}
	// exactly one event row and one job row
	var evN, jobN int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM stripe_events WHERE event_id='evt_replay'`).Scan(&evN); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind='billing.stripe_event'`).Scan(&jobN); err != nil {
		t.Fatal(err)
	}
	if evN != 1 || jobN != 1 {
		t.Fatalf("rows: events=%d jobs=%d, want 1/1", evN, jobN)
	}
	// process once via the worker handler, then force a second run — no
	// double transition (exactly one audit row).
	h := d.StripeEventHandler()
	for i := 0; i < 2; i++ {
		if err := h(ctx, jobs.Job{Payload: json.RawMessage(`{"event_id":"evt_replay"}`)}); err != nil {
			t.Fatalf("handler run %d: %v", i, err)
		}
	}
	if got := subStatus(t, db, subID); got != "active" {
		t.Fatalf("status = %q, want active", got)
	}
	if n := countAudit(t, db, audit.ActionSubStatus); n != 1 {
		t.Fatalf("status transitions audited %d times, want exactly 1", n)
	}
	var processed bool
	if err := db.QueryRow(`SELECT processed_at IS NOT NULL FROM stripe_events WHERE event_id='evt_replay'`).Scan(&processed); err != nil || !processed {
		t.Fatal("event not marked processed")
	}
}

// TestSubscriptionStateMachine walks trial -> active -> past_due -> active
// -> cancelled with an audit row on every transition.
func TestSubscriptionStateMachine(t *testing.T) {
	db := testutil.MariaDB(t)
	d := testDeps(db, &stubStripe{}, "")
	ctx := context.Background()
	orgID, subID := fixtureOrg(t, db)
	q := dbq.New(db)

	feed := func(id, typ string, obj any) {
		t.Helper()
		body := event(t, id, typ, obj)
		if err := q.InsertStripeEvent(ctx, dbq.InsertStripeEventParams{
			ID: id, EventID: id, Type: typ, Payload: body,
		}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
		if err := d.ProcessEvent(ctx, id); err != nil {
			t.Fatalf("process %s: %v", id, err)
		}
	}

	// trial -> active via checkout completion + subscription update.
	feed("evt_co", "checkout.session.completed", map[string]any{
		"id": "cs_1", "mode": "subscription", "customer": "cus_sm1",
		"subscription": "sub_sm1", "client_reference_id": orgID,
		"customer_details": map[string]any{"email": "buyer@fixture.test",
			"tax_ids": []map[string]any{{"type": "au_abn", "value": "51824753556"}}},
	})
	org, _ := q.GetOrganisation(ctx, orgID)
	if !org.StripeCustomerID.Valid || org.StripeCustomerID.String != "cus_sm1" {
		t.Fatalf("customer not linked: %+v", org.StripeCustomerID)
	}
	sub, _ := q.GetSubscription(ctx, subID)
	if !sub.StripeSubscriptionID.Valid || sub.StripeSubscriptionID.String != "sub_sm1" {
		t.Fatalf("stripe sub not linked: %+v", sub.StripeSubscriptionID)
	}
	if countAudit(t, db, audit.ActionCheckoutDone) != 1 {
		t.Fatal("checkout completion not audited")
	}

	feed("evt_su1", "customer.subscription.updated", subObject("sub_sm1", "cus_sm1", "active", orgID))
	if got := subStatus(t, db, subID); got != "active" {
		t.Fatalf("status = %q, want active", got)
	}

	// active -> past_due on payment failure.
	feed("evt_if", "invoice.payment_failed", map[string]any{
		"id": "in_f1", "customer": "cus_sm1", "subscription": "sub_sm1",
		"amount_due": 9900, "currency": "aud", "customer_email": "billing@fixture.test",
		"hosted_invoice_url": "https://invoice.test/in_f1",
	})
	if got := subStatus(t, db, subID); got != "past_due" {
		t.Fatalf("status = %q, want past_due", got)
	}

	// past_due -> active on invoice paid.
	feed("evt_ip", "invoice.paid", map[string]any{
		"id": "in_p1", "customer": "cus_sm1", "subscription": "sub_sm1",
		"amount_paid": 9900, "currency": "aud", "customer_email": "billing@fixture.test",
		"hosted_invoice_url": "https://invoice.test/in_p1",
	})
	if got := subStatus(t, db, subID); got != "active" {
		t.Fatalf("status = %q, want active", got)
	}

	// active -> cancelled on subscription deleted.
	del := subObject("sub_sm1", "cus_sm1", "canceled", orgID)
	feed("evt_sd", "customer.subscription.deleted", del)
	if got := subStatus(t, db, subID); got != "cancelled" {
		t.Fatalf("status = %q, want cancelled", got)
	}

	// audit coverage: one transition row per status change + invoice events.
	// trialing->active, active->past_due, past_due->active, active->cancelled.
	if n := countAudit(t, db, audit.ActionSubStatus); n != 4 {
		t.Fatalf("status audit rows = %d, want 4", n)
	}
	if countAudit(t, db, audit.ActionInvoicePaid) != 1 || countAudit(t, db, audit.ActionInvoiceFailed) != 1 {
		t.Fatal("invoice audit rows missing")
	}
	// dunning + receipt mail were queued.
	var mailN int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind='mail.send'`).Scan(&mailN); err != nil || mailN < 2 {
		t.Fatalf("mail jobs = %d, want >= 2", mailN)
	}
}

// TestSuspendAfterGrace is acceptance: a subscription past_due beyond the
// 14-day grace is suspended (status -> suspended) with an audit row.
func TestSuspendAfterGrace(t *testing.T) {
	db := testutil.MariaDB(t)
	d := testDeps(db, &stubStripe{}, "")
	ctx := context.Background()
	_, subID := fixtureOrg(t, db)

	// Backdate the row past the 14-day grace.
	if _, err := db.ExecContext(ctx,
		`UPDATE subscriptions SET status='past_due', updated_at = UTC_TIMESTAMP(6) - INTERVAL 15 DAY WHERE id = ?`,
		subID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	if err := d.SuspendSweepHandler()(ctx, jobs.Job{}); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if got := subStatus(t, db, subID); got != "suspended" {
		t.Fatalf("status = %q, want suspended", got)
	}
	if n := countAudit(t, db, audit.ActionSubSuspended); n != 1 {
		t.Fatalf("suspension audits = %d, want 1", n)
	}
	// The sweep rescheduled itself and mailed the org.
	var sweepN, mailN int64
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind='billing.suspend_sweep'`).Scan(&sweepN); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM jobs WHERE kind='mail.send'`).Scan(&mailN); err != nil {
		t.Fatal(err)
	}
	if sweepN != 1 || mailN != 1 {
		t.Fatalf("jobs: sweep=%d mail=%d, want 1/1", sweepN, mailN)
	}
	// A subscription inside the grace window is left alone.
	_, subID2 := fixtureOrg(t, db)
	if _, err := db.ExecContext(ctx,
		`UPDATE subscriptions SET status='past_due', updated_at = UTC_TIMESTAMP(6) - INTERVAL 2 DAY WHERE id = ?`,
		subID2); err != nil {
		t.Fatal(err)
	}
	if err := d.SuspendSweepHandler()(ctx, jobs.Job{}); err != nil {
		t.Fatalf("sweep2: %v", err)
	}
	if got := subStatus(t, db, subID2); got != "past_due" {
		t.Fatalf("in-grace status = %q, want still past_due", got)
	}
}

// TestBillingRoutes exercises checkout/portal/send_invoice end to end with
// the stub client and a real owner session (TOTP enrolled).
func TestBillingRoutes(t *testing.T) {
	db := testutil.MariaDB(t)
	stub := &stubStripe{}
	d := testDeps(db, stub, "")
	acct, err := accounts.New(db, accounts.Options{
		Secret:           []byte("test-auth-secret-0123456789abcdef"),
		SessionTTL:       time.Hour,
		PublicBaseURL:    "http://portal.test",
		TrialDays:        30,
		TrialMaxMachines: 25,
		Queue:            jobs.NewQueue(db),
	})
	if err != nil {
		t.Fatalf("accounts: %v", err)
	}
	handler := Routes(acct, d)
	ctx := context.Background()

	// Real owner session: signup -> TOTP setup/enable -> full.
	res, err := acct.Signup(ctx, accounts.SignupInput{
		Email: "owner@fixture.test", Password: "a very good password", OrgName: "Billing Org", IP: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("signup: %v", err)
	}
	_, secret, err := acct.TOTPSetup(ctx, res.Session)
	if err != nil {
		t.Fatalf("totp setup: %v", err)
	}
	code, _ := accounts.TOTPCode(secret, time.Now().UTC())
	full, err := acct.TOTPEnable(ctx, res.Session, code, "127.0.0.1")
	if err != nil {
		t.Fatalf("totp enable: %v", err)
	}
	token, err := acct.EncodeSession(full)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	cookie := &http.Cookie{Name: accounts.SessionCookie, Value: token}

	call := func(method, path, body string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	orgJSON := fmt.Sprintf(`{"org_id":%q`, res.Org.ID)

	// checkout: creates the Stripe customer, audits, returns the URL.
	rec := call(http.MethodPost, "/checkout", orgJSON+`,"plan":"pro","seats":3}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "checkout.stripe.test") {
		t.Fatalf("checkout = %d %s", rec.Code, rec.Body)
	}
	q := dbq.New(db)
	org, _ := q.GetOrganisation(ctx, res.Org.ID)
	if !org.StripeCustomerID.Valid || org.StripeCustomerID.String != "cus_stub_1" {
		t.Fatalf("customer not linked: %+v", org.StripeCustomerID)
	}
	if countAudit(t, db, audit.ActionCheckoutStarted) != 1 || countAudit(t, db, audit.ActionCustomerCreated) != 1 {
		t.Fatal("checkout audits missing")
	}

	// portal session
	rec = call(http.MethodPost, "/portal", orgJSON+`}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "billing.stripe.test") {
		t.Fatalf("portal = %d %s", rec.Code, rec.Body)
	}

	// enterprise send-invoice with ABN
	rec = call(http.MethodPost, "/invoices", orgJSON+`,"plan":"enterprise","seats":10,"abn":"51 824 753 556"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "invoice.stripe.test") {
		t.Fatalf("invoice = %d %s", rec.Code, rec.Body)
	}
	if countAudit(t, db, audit.ActionInvoiceSent) != 1 {
		t.Fatal("invoice sent not audited")
	}
	inv, _ := lastCall(stub, "invoice")
	if inv.ABN != "51 824 753 556" || !inv.AutomaticTax {
		t.Fatalf("invoice params: %+v", inv)
	}

	// unauthenticated -> 401
	req, _ := http.NewRequest(http.MethodPost, "/checkout", strings.NewReader(orgJSON+`,"plan":"pro"}`))
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon checkout = %d", rec.Code)
	}
}

func lastCall(s *stubStripe, method string) (InvoiceParams, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.calls) - 1; i >= 0; i-- {
		if s.calls[i].Method == method {
			return s.calls[i].Params.(InvoiceParams), true
		}
	}
	return InvoiceParams{}, false
}
