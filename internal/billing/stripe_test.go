package billing

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// signBody builds a Stripe-Signature header for payload as Stripe would.
func signBody(payload []byte, secret string, t time.Time) string {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "%d.%s", t.Unix(), payload)
	return fmt.Sprintf("t=%d,v1=%x", t.Unix(), mac.Sum(nil))
}

func TestVerifySignature(t *testing.T) {
	secret := "whsec_testsecret"
	body := []byte(`{"id":"evt_1","type":"ping"}`)
	now := time.Now().UTC()

	if err := VerifySignature(body, signBody(body, secret, now), secret, now); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	// Forged: wrong secret.
	forged := signBody(body, "whsec_wrong", now)
	if err := VerifySignature(body, forged, secret, now); err == nil {
		t.Fatal("forged signature accepted")
	}
	// Tampered body.
	if err := VerifySignature([]byte(`{"id":"evt_2"}`), signBody(body, secret, now), secret, now); err == nil {
		t.Fatal("tampered body accepted")
	}
	// Stale timestamp (replay outside tolerance).
	if err := VerifySignature(body, signBody(body, secret, now.Add(-time.Hour)), secret, now); err == nil {
		t.Fatal("stale timestamp accepted")
	}
	// Malformed headers.
	for _, h := range []string{"", "t=abc,v1=x", "v1=only", "t=123"} {
		if err := VerifySignature(body, h, secret, now); err == nil {
			t.Fatalf("malformed header %q accepted", h)
		}
	}
}

// TestStripeClientForm exercises the real client against a stub HTTP
// server (the public API surface — no live Stripe).
func TestStripeClientCheckout(t *testing.T) {
	var gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"cs_test_1","url":"https://checkout.stripe.test/pay/cs_test_1"}`)
	}))
	defer srv.Close()

	c := NewStripeClient("sk_test_123")
	c.base = srv.URL
	out, err := c.CreateCheckoutSession(t.Context(), CheckoutSessionParams{
		OrgID: "org-1", CustomerID: "cus_1", PriceID: "price_pro",
		Quantity: 3, SuccessURL: "https://x/ok", CancelURL: "https://x/no",
		AutomaticTax: true, CollectTaxID: true,
	})
	if err != nil {
		t.Fatalf("checkout: %v", err)
	}
	if out.URL == "" || out.ID != "cs_test_1" {
		t.Fatalf("bad session: %+v", out)
	}
	if gotAuth != "Basic "+base64.StdEncoding.EncodeToString([]byte("sk_test_123:")) {
		t.Fatalf("unexpected auth header: %q", gotAuth)
	}
	for _, want := range []string{
		"mode=subscription", "line_items%5B0%5D%5Bprice%5D=price_pro",
		"automatic_tax%5Benabled%5D=true", "tax_id_collection%5Benabled%5D=true",
		"client_reference_id=org-1",
	} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("form missing %q in %q", want, gotBody)
		}
	}
}

func TestStripeClientError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusPaymentRequired)
		fmt.Fprint(w, `{"error":{"type":"card_error","code":"card_declined","message":"Your card was declined."}}`)
	}))
	defer srv.Close()
	c := NewStripeClient("sk_test_123")
	c.base = srv.URL
	_, err := c.CreatePortalSession(t.Context(), PortalSessionParams{CustomerID: "cus_1", ReturnURL: "https://x"})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "card_declined" {
		t.Fatalf("expected APIError card_declined, got %v", err)
	}
}
