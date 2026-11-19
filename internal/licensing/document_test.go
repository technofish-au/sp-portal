package licensing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestCanonicalJSONOrdering(t *testing.T) {
	got, err := CanonicalJSON(map[string]any{
		"b": float64(2), "a": "x", "c": []any{"y", nil, true},
	})
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	want := `{"a":"x","b":2,"c":["y",null,true]}`
	if string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestCanonicalJSONEscapes(t *testing.T) {
	// JCS escapes only ", \ and C0 controls — '<', '>', '&' pass through
	// (unlike encoding/json).
	got, err := CanonicalJSON("a<b>&\"\\\x01")
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	if want := `"a<b>&\"\\\u0001"`; string(got) != want {
		t.Fatalf("canonical = %s, want %s", got, want)
	}
}

func TestCanonicalJSONRejects(t *testing.T) {
	for _, v := range []any{
		float64(1.5),                      // fractional
		float64(1 << 60),                  // above the integer range
		map[string]any{"k": float64(0.5)}, // nested fractional
		map[string]any{"café": 1.0},       // non-ASCII key
	} {
		if _, err := CanonicalJSON(v); err == nil {
			t.Fatalf("CanonicalJSON(%v) succeeded, want error", v)
		}
	}
}

func testPayload() Payload {
	exp := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	return Payload{
		Version:      1,
		LicenceID:    "018f0000-0000-7000-8000-000000000001",
		LicenceKey:   "SPL-TEST-1",
		OrgID:        "018f0000-0000-7000-8000-000000000002",
		InstanceID:   "machine-abc",
		Kind:         "subscription",
		Plan:         "pro",
		MaxInstances: 5,
		Features:     []string{"monitoring", "apt-updates", "fleet"},
		IssuedAt:     time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		ExpiresAt:    &exp,
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	issuer, err := DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	doc, hash, err := issuer.Sign(testPayload())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(hash) != 64 {
		t.Fatalf("doc hash %q is not sha256 hex", hash)
	}
	got, err := VerifyDocument(doc, issuer.TrustedKeys())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.LicenceKey != "SPL-TEST-1" || got.MaxInstances != 5 || got.InstanceID != "machine-abc" {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestVerifyRejectsNonCanonicalWriter(t *testing.T) {
	// A document produced by a non-canonical writer (different key order,
	// whitespace) must still verify: verification canonicalises.
	issuer, err := DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	canon, err := CanonicalJSON(testPayload().wire())
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(issuer.priv, canon))
	// Same content, different member order and whitespace.
	messy := []byte(`{ "signatures": [ {"sig":"` + sig + `","alg":"Ed25519","kid":"` + issuer.KID() + `"} ],
"licence":  ` + string(canon) + ` }`)
	if _, err := VerifyDocument(messy, issuer.TrustedKeys()); err != nil {
		t.Fatalf("verify messy doc: %v", err)
	}
}

func TestTamperedDocumentRejected(t *testing.T) {
	issuer, err := DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := issuer.Sign(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	lic := env["licence"].(map[string]any)
	lic["max_instances"] = float64(500) // tamper
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(tampered, issuer.TrustedKeys()); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("tampered doc verified: %v", err)
	}
}

func TestRotationSlots(t *testing.T) {
	// A second signature slot from an unknown kid is skipped; the trusted
	// one still verifies. A doc signed by an untrusted key fails.
	issuer, err := DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	doc, _, err := issuer.Sign(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(doc, &env); err != nil {
		t.Fatal(err)
	}
	env["signatures"] = append([]any{map[string]any{
		"kid": "future-issuer", "alg": "Ed25519",
		"sig": base64.StdEncoding.EncodeToString(make([]byte, 64)),
	}}, env["signatures"].([]any)...)
	multi, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(multi, issuer.TrustedKeys()); err != nil {
		t.Fatalf("verify with extra unknown slot: %v", err)
	}

	// An entirely foreign signer is not accepted.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	foreign, err := NewIssuer("mallory-1", priv)
	if err != nil {
		t.Fatal(err)
	}
	fdoc, _, err := foreign.Sign(testPayload())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDocument(fdoc, issuer.TrustedKeys()); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("foreign doc verified: %v", err)
	}
	if _, err := VerifyDocument(fdoc, map[string]ed25519.PublicKey{"mallory-1": pub}); err != nil {
		t.Fatalf("foreign doc rejected by its own trust set: %v", err)
	}
}

func TestLoadIssuerSeedAndKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	full, err := LoadIssuer("k1", base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("load full key: %v", err)
	}
	seed, err := LoadIssuer("k1", base64.StdEncoding.EncodeToString(priv.Seed()))
	if err != nil {
		t.Fatalf("load seed: %v", err)
	}
	if !full.PublicKey().Equal(pub) || !seed.PublicKey().Equal(pub) {
		t.Fatal("loaded keys do not match generated key")
	}
	if _, err := LoadIssuer("k1", "not base64!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
}

func TestDevIssuerMatchesPublishedKey(t *testing.T) {
	// The committed dev pair must be self-consistent and stable (the
	// contract in docs/fakeportal.md pins the public key).
	issuer, err := DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	kid, pub, err := DevVerificationKey()
	if err != nil {
		t.Fatal(err)
	}
	if kid != issuer.KID() || !pub.Equal(issuer.PublicKey()) {
		t.Fatal("dev issuer / verification key mismatch")
	}
	if got := base64.StdEncoding.EncodeToString(pub); got != devIssuerPubB64 {
		t.Fatalf("dev pubkey changed: %s", got)
	}
}
