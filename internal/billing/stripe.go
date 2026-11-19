package billing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the Stripe API endpoint; a field on StripeClient so
// tests can point it at a local server.
const DefaultBaseURL = "https://api.stripe.com"

// maxResponseBody bounds Stripe API responses read into memory.
const maxResponseBody = 4 << 20

// StripeClient is the production Client: a thin form-encoded net/http
// wrapper over the Stripe REST API (the SDK is deliberately not a
// dependency — the portal uses five endpoints).
type StripeClient struct {
	key  string
	base string
	http *http.Client
}

// NewStripeClient returns a Client for the secret key (sk_live_/sk_test_).
func NewStripeClient(secretKey string) *StripeClient {
	return &StripeClient{
		key:  secretKey,
		base: DefaultBaseURL,
		http: &http.Client{Timeout: 30 * time.Second},
	}
}

var _ Client = (*StripeClient)(nil)

// APIError is a non-2xx Stripe response.
type APIError struct {
	Status  int
	Type    string
	Code    string
	Message string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("stripe: %s (%d %s)", e.Message, e.Status, e.Type)
}

// do executes one form-encoded request and decodes the JSON body into out.
func (c *StripeClient) do(ctx context.Context, method, path string, form url.Values, out any) error {
	var body io.Reader
	if len(form) > 0 {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.key, "")
	if len(form) > 0 {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("stripe: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("stripe: read %s: %w", path, err)
	}
	if resp.StatusCode/100 != 2 {
		apiErr := &APIError{Status: resp.StatusCode}
		var e struct {
			Error struct {
				Type    string `json:"type"`
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &e) == nil {
			apiErr.Type, apiErr.Code, apiErr.Message = e.Error.Type, e.Error.Code, e.Error.Message
		}
		if apiErr.Message == "" {
			apiErr.Message = http.StatusText(resp.StatusCode)
		}
		return apiErr
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("stripe: decode %s: %w", path, err)
		}
	}
	return nil
}

// CreateCheckoutSession implements Client (POST /v1/checkout/sessions).
func (c *StripeClient) CreateCheckoutSession(ctx context.Context, p CheckoutSessionParams) (*CheckoutSession, error) {
	f := url.Values{}
	f.Set("mode", "subscription")
	f.Set("line_items[0][price]", p.PriceID)
	f.Set("line_items[0][quantity]", strconv.Itoa(max(p.Quantity, 1)))
	f.Set("success_url", p.SuccessURL)
	f.Set("cancel_url", p.CancelURL)
	f.Set("client_reference_id", p.OrgID)
	f.Set("metadata[org_id]", p.OrgID)
	f.Set("subscription_data[metadata][org_id]", p.OrgID)
	if p.CustomerID != "" {
		f.Set("customer", p.CustomerID)
	} else if p.CustomerEmail != "" {
		f.Set("customer_email", p.CustomerEmail)
	}
	if p.AutomaticTax {
		f.Set("automatic_tax[enabled]", "true")
	}
	if p.CollectTaxID {
		f.Set("tax_id_collection[enabled]", "true")
	}
	var out CheckoutSession
	if err := c.do(ctx, http.MethodPost, "/v1/checkout/sessions", f, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreatePortalSession implements Client (POST /v1/billing_portal/sessions).
func (c *StripeClient) CreatePortalSession(ctx context.Context, p PortalSessionParams) (*PortalSession, error) {
	f := url.Values{"customer": {p.CustomerID}, "return_url": {p.ReturnURL}}
	var out PortalSession
	if err := c.do(ctx, http.MethodPost, "/v1/billing_portal/sessions", f, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// EnsureCustomer implements Client: POST /v1/customers, then attach the
// ABN as an au_abn tax id when supplied.
func (c *StripeClient) EnsureCustomer(ctx context.Context, p CustomerParams) (*Customer, error) {
	f := url.Values{
		"name":             {p.Name},
		"email":            {p.Email},
		"metadata[org_id]": {p.OrgID},
	}
	var out Customer
	if err := c.do(ctx, http.MethodPost, "/v1/customers", f, &out); err != nil {
		return nil, err
	}
	if p.ABN != "" {
		tf := url.Values{"type": {"au_abn"}, "value": {digitsOnly(p.ABN)}}
		if err := c.do(ctx, http.MethodPost, "/v1/customers/"+out.ID+"/tax_ids", tf, nil); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

// SendSubscriptionInvoice implements Client: a send_invoice subscription
// (enterprise purchase — the customer is invoiced, no Checkout). The first
// invoice is finalised by Stripe's auto-advance; its hosted URL is
// returned for the notification email.
func (c *StripeClient) SendSubscriptionInvoice(ctx context.Context, p InvoiceParams) (*InvoiceResult, error) {
	if p.ABN != "" {
		tf := url.Values{"type": {"au_abn"}, "value": {digitsOnly(p.ABN)}}
		if err := c.do(ctx, http.MethodPost, "/v1/customers/"+p.CustomerID+"/tax_ids", tf, nil); err != nil {
			return nil, err
		}
	}
	f := url.Values{
		"customer":               {p.CustomerID},
		"collection_method":      {"send_invoice"},
		"days_until_due":         {strconv.Itoa(max(p.DaysUntilDue, 1))},
		"items[0][price]":        {p.PriceID},
		"items[0][quantity]":     {strconv.Itoa(max(p.Quantity, 1))},
		"metadata[org_id]":       {p.OrgID},
		"automatic_tax[enabled]": {strconv.FormatBool(p.AutomaticTax)},
		"expand[]":               {"latest_invoice"},
	}
	var sub struct {
		ID            string `json:"id"`
		LatestInvoice struct {
			ID               string `json:"id"`
			HostedInvoiceURL string `json:"hosted_invoice_url"`
		} `json:"latest_invoice"`
	}
	if err := c.do(ctx, http.MethodPost, "/v1/subscriptions", f, &sub); err != nil {
		return nil, err
	}
	return &InvoiceResult{
		SubscriptionID:   sub.ID,
		InvoiceID:        sub.LatestInvoice.ID,
		HostedInvoiceURL: sub.LatestInvoice.HostedInvoiceURL,
	}, nil
}

// digitsOnly strips non-digits (ABN inputs often carry spaces).
func digitsOnly(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// --- webhook signature verification ------------------------------------

// signatureTolerance rejects webhook timestamps older than this (Stripe
// sends fresh events; tolerance covers clock skew + retries).
const signatureTolerance = 5 * time.Minute

// ErrBadSignature rejects forged/malformed Stripe-Signature headers.
var ErrBadSignature = errors.New("invalid stripe signature")

// VerifySignature validates the Stripe-Signature header for payload:
// v1 must equal HMAC-SHA256(secret, "<t>.<payload>") and the timestamp
// must be within tolerance of now.
func VerifySignature(payload []byte, header, secret string, now time.Time) error {
	var ts int64
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch k {
		case "t":
			if t, err := strconv.ParseInt(v, 10, 64); err == nil {
				ts = t
			}
		case "v1":
			sigs = append(sigs, v)
		}
	}
	if ts == 0 || len(sigs) == 0 {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(strconv.FormatInt(ts, 10)))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(payload)
	want := fmt.Sprintf("%x", mac.Sum(nil))
	matched := false
	for _, sig := range sigs {
		if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) == 1 {
			matched = true
		}
	}
	if !matched {
		return ErrBadSignature
	}
	if skew := now.Sub(time.Unix(ts, 0)); skew > signatureTolerance || skew < -signatureTolerance {
		return ErrBadSignature
	}
	return nil
}
