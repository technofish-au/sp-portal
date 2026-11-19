// Package billing implements the Stripe domain: Checkout Session creation
// and the Customer Portal for self-serve purchases, the enterprise
// send-invoice path, webhook ingestion (verify → stripe_events row → jobs
// row → 200) and the worker handlers that drive the subscription state
// machine idempotently off event payloads.
//
// The Stripe API is bound behind the Client interface so tests run
// entirely against a stub — no live API calls anywhere in the test suite.
package billing

import "context"

// Client is the outbound Stripe API surface the portal uses. The real
// implementation is StripeClient (a thin net/http client — no SDK);
// tests substitute a recording stub.
type Client interface {
	// CreateCheckoutSession starts a hosted subscription checkout.
	CreateCheckoutSession(ctx context.Context, p CheckoutSessionParams) (*CheckoutSession, error)
	// CreatePortalSession opens the Stripe Customer Portal.
	CreatePortalSession(ctx context.Context, p PortalSessionParams) (*PortalSession, error)
	// EnsureCustomer returns the Stripe customer id for an org, creating
	// the customer (with ABN when supplied) if absent.
	EnsureCustomer(ctx context.Context, p CustomerParams) (*Customer, error)
	// SendSubscriptionInvoice creates a send_invoice subscription (the
	// enterprise path — no Checkout), finalises the first invoice and
	// returns its hosted URL for delivery.
	SendSubscriptionInvoice(ctx context.Context, p InvoiceParams) (*InvoiceResult, error)
}

// CheckoutSessionParams are the inputs to POST /v1/checkout/sessions.
type CheckoutSessionParams struct {
	OrgID         string
	CustomerID    string // existing cus_...; empty uses CustomerEmail
	CustomerEmail string
	PriceID       string
	Quantity      int
	SuccessURL    string
	CancelURL     string
	AutomaticTax  bool
	CollectTaxID  bool // tax_id_collection — captures ABN etc. at checkout
}

// CheckoutSession is the session id + hosted URL.
type CheckoutSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// PortalSessionParams are the inputs to POST /v1/billing_portal/sessions.
type PortalSessionParams struct {
	CustomerID string
	ReturnURL  string
}

// PortalSession is the hosted portal URL.
type PortalSession struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

// CustomerParams are the inputs to POST /v1/customers (+ tax_ids).
type CustomerParams struct {
	OrgID string
	Name  string
	Email string
	ABN   string // Australian Business Number (au_abn tax id); optional
}

// Customer is the created/loaded Stripe customer.
type Customer struct {
	ID string `json:"id"`
}

// InvoiceParams drives the enterprise send-invoice path.
type InvoiceParams struct {
	CustomerID   string
	OrgID        string
	PriceID      string
	Quantity     int
	DaysUntilDue int
	AutomaticTax bool
	ABN          string // attached to the customer as an au_abn tax id
}

// InvoiceResult is the send_invoice subscription + first invoice.
type InvoiceResult struct {
	SubscriptionID   string `json:"subscription_id"`
	InvoiceID        string `json:"invoice_id"`
	HostedInvoiceURL string `json:"hosted_invoice_url"`
}
