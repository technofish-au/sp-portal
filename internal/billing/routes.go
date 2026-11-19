package billing

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/technofish-au/sp-portal/internal/accounts"
	"github.com/technofish-au/sp-portal/internal/audit"
	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/mailer"
)

// Routes returns the /v1/billing handler: Checkout Session creation,
// Customer Portal sessions, the enterprise send-invoice path and the
// org's subscription view. All endpoints need a full session; mutating
// ones need the owner or admin org role.
func Routes(acct *accounts.Service, d Deps) http.Handler {
	r := chi.NewRouter()
	r.Use(acct.SessionMiddleware())
	h := &handlers{acct: acct, d: d, q: d.queries()}

	r.Group(func(r chi.Router) {
		r.Use(accounts.RequireAuth)
		r.Get("/subscription", h.subscription)
		r.Post("/checkout", h.checkout)
		r.Post("/portal", h.portal)
		r.Post("/invoices", h.sendInvoice)
	})
	return r
}

type handlers struct {
	acct *accounts.Service
	d    Deps
	q    *dbq.Queries
}

// orgFrom resolves the org_id request field and enforces the role set.
func (h *handlers) orgFrom(w http.ResponseWriter, r *http.Request, orgID string, roles ...string) (dbq.Organisation, dbq.Membership, bool) {
	sess, _ := accounts.SessionFrom(r.Context())
	m, err := h.acct.RequireOrgRole(r.Context(), sess.User.ID, orgID, roles...)
	if err != nil {
		writeError(w, http.StatusForbidden, "forbidden", "org membership with billing role required")
		return dbq.Organisation{}, dbq.Membership{}, false
	}
	org, err := h.q.GetOrganisation(r.Context(), orgID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "organisation not found")
		return dbq.Organisation{}, dbq.Membership{}, false
	}
	return org, m, true
}

// ensureCustomer returns the org's Stripe customer id, creating the
// customer (and linking it on the org) on first use.
func (h *handlers) ensureCustomer(r *http.Request, org dbq.Organisation, abn string) (string, error) {
	if org.StripeCustomerID.Valid && org.StripeCustomerID.String != "" {
		return org.StripeCustomerID.String, nil
	}
	cust, err := h.d.Client.EnsureCustomer(r.Context(), CustomerParams{
		OrgID: org.ID, Name: org.Name, Email: org.BillingEmail, ABN: abn,
	})
	if err != nil {
		return "", err
	}
	if err := h.q.SetOrganisationStripeCustomer(r.Context(), dbq.SetOrganisationStripeCustomerParams{
		ID: org.ID, StripeCustomerID: sqlString(cust.ID),
	}); err != nil {
		return "", err
	}
	sess, _ := accounts.SessionFrom(r.Context())
	_ = audit.Write(r.Context(), h.q, audit.Entry{
		OrgID: org.ID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: audit.ActionCustomerCreated, TargetType: "organisation", TargetID: org.ID,
		Detail: map[string]any{"stripe_customer_id": cust.ID, "abn": abn != ""},
	})
	return cust.ID, nil
}

// audit writes a billing audit row attributed to the session user.
func (h *handlers) audit(r *http.Request, orgID, action, targetType, targetID string, detail any) {
	sess, _ := accounts.SessionFrom(r.Context())
	_ = audit.Write(r.Context(), h.q, audit.Entry{
		OrgID: orgID, ActorUserID: sess.User.ID, ActorEmail: sess.User.Email,
		Action: action, TargetType: targetType, TargetID: targetID, Detail: detail,
	})
}

// disabled responds 503 when no Stripe client is configured.
func (h *handlers) disabled(w http.ResponseWriter) bool {
	if !h.d.Enabled() {
		writeError(w, http.StatusServiceUnavailable, "billing_disabled", "Stripe is not configured")
		return true
	}
	return false
}

// subscription returns the org's latest subscription (any member role).
func (h *handlers) subscription(w http.ResponseWriter, r *http.Request) {
	org, _, ok := h.orgFrom(w, r, r.URL.Query().Get("org_id"),
		accounts.RoleOwner, accounts.RoleAdmin, accounts.RoleMember, accounts.RoleViewer)
	if !ok {
		return
	}
	sub, err := h.q.GetLatestSubscriptionByOrg(r.Context(), org.ID)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no subscription")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscription": sub})
}

// checkoutReq is POST /checkout.
type checkoutReq struct {
	OrgID string `json:"org_id"`
	Plan  string `json:"plan"`
	Seats int    `json:"seats"`
}

// checkout creates a Stripe Checkout Session for a plan purchase.
func (h *handlers) checkout(w http.ResponseWriter, r *http.Request) {
	if h.disabled(w) {
		return
	}
	var in checkoutReq
	if !decodeBody(w, r, &in) {
		return
	}
	price := h.d.Prices[strings.ToLower(in.Plan)]
	if price == "" {
		writeError(w, http.StatusBadRequest, "unknown_plan", "plan must be one of: "+strings.Join(h.planNames(), ", "))
		return
	}
	org, _, ok := h.orgFrom(w, r, in.OrgID, accounts.RoleOwner, accounts.RoleAdmin)
	if !ok {
		return
	}
	customerID, err := h.ensureCustomer(r, org, "")
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe_error", err.Error())
		return
	}
	base := strings.TrimRight(h.d.PublicBaseURL, "/")
	cs, err := h.d.Client.CreateCheckoutSession(r.Context(), CheckoutSessionParams{
		OrgID: org.ID, CustomerID: customerID, PriceID: price,
		Quantity:     max(in.Seats, 1),
		SuccessURL:   base + "/billing/success?session_id={CHECKOUT_SESSION_ID}",
		CancelURL:    base + "/billing/cancelled",
		AutomaticTax: h.d.AutomaticTax,
		CollectTaxID: true, // lets checkout capture the ABN (au_abn)
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe_error", err.Error())
		return
	}
	h.audit(r, org.ID, audit.ActionCheckoutStarted, "checkout_session", cs.ID,
		map[string]any{"plan": in.Plan, "price_id": price, "seats": max(in.Seats, 1)})
	writeJSON(w, http.StatusOK, map[string]string{"url": cs.URL, "session_id": cs.ID})
}

// portalReq is POST /portal.
type portalReq struct {
	OrgID string `json:"org_id"`
}

// portal opens a Stripe Customer Portal session for the org.
func (h *handlers) portal(w http.ResponseWriter, r *http.Request) {
	if h.disabled(w) {
		return
	}
	var in portalReq
	if !decodeBody(w, r, &in) {
		return
	}
	org, _, ok := h.orgFrom(w, r, in.OrgID, accounts.RoleOwner, accounts.RoleAdmin)
	if !ok {
		return
	}
	if !org.StripeCustomerID.Valid || org.StripeCustomerID.String == "" {
		writeError(w, http.StatusConflict, "no_customer", "no billing account yet — start a checkout first")
		return
	}
	ps, err := h.d.Client.CreatePortalSession(r.Context(), PortalSessionParams{
		CustomerID: org.StripeCustomerID.String,
		ReturnURL:  strings.TrimRight(h.d.PublicBaseURL, "/") + "/",
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe_error", err.Error())
		return
	}
	h.audit(r, org.ID, audit.ActionPortalSession, "portal_session", ps.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"url": ps.URL})
}

// invoiceReq is POST /invoices (enterprise send-invoice purchase).
type invoiceReq struct {
	OrgID        string `json:"org_id"`
	Plan         string `json:"plan"` // must map to a configured price
	Seats        int    `json:"seats"`
	ABN          string `json:"abn"` // recorded on the customer as au_abn
	DaysUntilDue int    `json:"days_until_due"`
}

// sendInvoice is the enterprise purchase path: a send_invoice Stripe
// subscription that emails the customer an invoice instead of Checkout.
func (h *handlers) sendInvoice(w http.ResponseWriter, r *http.Request) {
	if h.disabled(w) {
		return
	}
	var in invoiceReq
	if !decodeBody(w, r, &in) {
		return
	}
	price := h.d.Prices[strings.ToLower(in.Plan)]
	if price == "" {
		writeError(w, http.StatusBadRequest, "unknown_plan", "plan must be one of: "+strings.Join(h.planNames(), ", "))
		return
	}
	org, _, ok := h.orgFrom(w, r, in.OrgID, accounts.RoleOwner, accounts.RoleAdmin)
	if !ok {
		return
	}
	customerID, err := h.ensureCustomer(r, org, in.ABN)
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe_error", err.Error())
		return
	}
	res, err := h.d.Client.SendSubscriptionInvoice(r.Context(), InvoiceParams{
		CustomerID: customerID, OrgID: org.ID, PriceID: price,
		Quantity:     max(in.Seats, 1),
		DaysUntilDue: max(in.DaysUntilDue, 14),
		AutomaticTax: h.d.AutomaticTax,
		ABN:          in.ABN,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, "stripe_error", err.Error())
		return
	}
	h.audit(r, org.ID, audit.ActionInvoiceSent, "invoice", res.InvoiceID,
		map[string]any{
			"plan": in.Plan, "seats": max(in.Seats, 1), "abn": in.ABN != "",
			"stripe_subscription_id": res.SubscriptionID, "days_until_due": max(in.DaysUntilDue, 14),
		})
	if h.d.Queue != nil && org.BillingEmail != "" {
		_, _ = h.d.Queue.Enqueue(r.Context(), mailer.KindSend, mailer.Message{
			To:      org.BillingEmail,
			Subject: "Your ServerPerch invoice",
			Text: "Your ServerPerch subscription invoice is ready.\n\n" +
				"View and pay it online: " + res.HostedInvoiceURL + "\n\n" +
				"The subscription activates once the invoice is paid.\n",
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"subscription_id":    res.SubscriptionID,
		"invoice_id":         res.InvoiceID,
		"hosted_invoice_url": res.HostedInvoiceURL,
	})
}

// planNames lists the configured plan names for error messages.
func (h *handlers) planNames() []string {
	out := make([]string, 0, len(h.d.Prices))
	for plan, id := range h.d.Prices {
		if id != "" {
			out = append(out, plan)
		}
	}
	return out
}

// decodeBody reads a small JSON request body.
func decodeBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "malformed JSON body")
		return false
	}
	return true
}
