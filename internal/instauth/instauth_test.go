package instauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"
)

func TestStringToSignFormat(t *testing.T) {
	body := []byte(`{"a":1}`)
	got := StringToSign("post", "/v1/check-ins", 1730000000, "nonce1", body)
	sum := sha256.Sum256(body)
	want := fmt.Sprintf("SP-ED25519-V1\nPOST\n/v1/check-ins\n1730000000\nnonce1\n%x\n", sum)
	if string(got) != want {
		t.Fatalf("StringToSign = %q, want %q", got, want)
	}
}

func TestParseAuthorizationRoundTrip(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	body := []byte("hello")
	header, err := SignRequest(priv, "inst-1", "POST", "/v1/check-ins", 1730000000, "abc123", body)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := parseAuthorization(header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cred.instanceID != "inst-1" || cred.ts != 1730000000 || cred.nonce != "abc123" {
		t.Fatalf("credentials mismatch: %+v", cred)
	}
	if !cred.pub.Equal(pub) {
		t.Fatal("pubkey mismatch")
	}
	msg := StringToSign("POST", "/v1/check-ins", cred.ts, cred.nonce, body)
	if !ed25519.Verify(pub, msg, cred.sig) {
		t.Fatal("signature does not verify")
	}
}

func TestParseAuthorizationRejects(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	good := Authorization("i", pub, 1730000000, "n", make([]byte, ed25519.SignatureSize))
	for _, h := range []string{
		"",
		"Bearer abc",
		"SP-Ed25519",              // no params
		`SP-Ed25519 instance="i"`, // missing fields
		`SP-Ed25519 instance="i", key="AAA", ts="1", nonce="n", sig="` +
			base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)) + `"`, // bad key
		`SP-Ed25519 instance="i", key="` + base64.StdEncoding.EncodeToString(pub) +
			`", ts="soon", nonce="n", sig="` + base64.StdEncoding.EncodeToString(make([]byte, 64)) + `"`, // bad ts
		good + `, bogus="x"`, // unknown field
	} {
		if _, err := parseAuthorization(h); err == nil {
			t.Fatalf("parseAuthorization(%q) succeeded, want error", h)
		}
	}
}

func TestReplayCache(t *testing.T) {
	c := newReplayCache(10*time.Minute, 8)
	now := time.Now()
	var d [32]byte
	copy(d[:], "a digest")
	if c.checkAndMark(d, now) {
		t.Fatal("first presentation marked replay")
	}
	if !c.checkAndMark(d, now.Add(time.Minute)) {
		t.Fatal("second presentation not detected as replay")
	}
	// Beyond the TTL an evicted entry may repeat — but the timestamp
	// check rejects those requests anyway.
	var other [32]byte
	copy(other[:], "different")
	if c.checkAndMark(other, now.Add(11*time.Minute)) {
		t.Fatal("fresh digest marked replay")
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Now()
	clock := func() time.Time { return now }
	l := newRateLimiter(2, clock) // 2/min sustained, burst 2
	if !l.Allow("i1") {
		t.Fatal("first burst request denied")
	}
	if !l.Allow("i1") {
		t.Fatal("second burst request denied")
	}
	if l.Allow("i1") {
		t.Fatal("over-limit request allowed")
	}
	if !l.Allow("i2") {
		t.Fatal("per-instance limit leaked across instances")
	}
	now = now.Add(31 * time.Second) // ~1 token refilled
	if !l.Allow("i1") {
		t.Fatal("refilled request denied")
	}
}
