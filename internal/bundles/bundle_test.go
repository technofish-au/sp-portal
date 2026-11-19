// Unit tests for the .spb signed-bundle format: build/verify round
// trip, signature trust slots and tamper detection. No DB needed.
package bundles_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/technofish-au/sp-portal/internal/bundles"
	"github.com/technofish-au/sp-portal/internal/licensing"
)

func testSigner(t *testing.T) *licensing.Issuer {
	t.Helper()
	issuer, err := licensing.DevIssuer()
	if err != nil {
		t.Fatal(err)
	}
	return issuer
}

func trustFor(t *testing.T, issuer *licensing.Issuer) map[string]ed25519.PublicKey {
	t.Helper()
	return map[string]ed25519.PublicKey{issuer.KID(): issuer.PublicKey()}
}

func build(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	err := bundles.Build(&buf, bundles.Manifest{
		CreatedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Release: bundles.ReleaseInfo{
			Component: "platform", Version: "1.4.2", Channel: "stable",
			MinUpgradeFrom: "1.3.0", Security: true,
		},
	}, []bundles.File{
		{Path: "sp-platform-1.4.2.tar.gz", Data: strings.NewReader("artifact-bytes")},
		{Path: "notes/readme.txt", Data: strings.NewReader("release notes")},
	}, testSigner(t))
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return buf.Bytes()
}

func TestBuildVerifyRoundTrip(t *testing.T) {
	issuer := testSigner(t)
	data := build(t)
	v, err := bundles.Verify(bytes.NewReader(data), trustFor(t, issuer))
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	m := v.Manifest
	if m.V != 1 || m.Kind != bundles.Kind {
		t.Fatalf("manifest header: %+v", m)
	}
	if m.Release.Version != "1.4.2" || !m.Release.Security || m.Release.MinUpgradeFrom != "1.3.0" {
		t.Fatalf("release info: %+v", m.Release)
	}
	if len(m.Files) != 2 {
		t.Fatalf("files: %+v", m.Files)
	}
	if got := string(v.Payload["sp-platform-1.4.2.tar.gz"]); got != "artifact-bytes" {
		t.Fatalf("payload[artifact] = %q", got)
	}
	if got := string(v.Payload["notes/readme.txt"]); got != "release notes" {
		t.Fatalf("payload[notes] = %q", got)
	}
}

func TestVerifyTamperedBundleRejected(t *testing.T) {
	issuer := testSigner(t)
	data := build(t)
	// Flip bytes inside the archive: whichever member is hit, something
	// (signature over MANIFEST, or a payload hash) must fail.
	data[len(data)/2] ^= 0xFF
	if _, err := bundles.Verify(bytes.NewReader(data), trustFor(t, issuer)); err == nil {
		t.Fatal("tampered bundle verified")
	}
}

func TestVerifyUntrustedKidRejected(t *testing.T) {
	data := build(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, err = bundles.Verify(bytes.NewReader(data),
		map[string]ed25519.PublicKey{"other-kid": pub})
	if !errors.Is(err, bundles.ErrNoSignature) {
		t.Fatalf("untrusted kid: %v, want ErrNoSignature", err)
	}
}

func TestVerifyGarbageRejected(t *testing.T) {
	_, err := bundles.Verify(strings.NewReader("not a bundle"),
		trustFor(t, testSigner(t)))
	if !errors.Is(err, bundles.ErrBadBundle) {
		t.Fatalf("garbage: %v, want ErrBadBundle", err)
	}
}
