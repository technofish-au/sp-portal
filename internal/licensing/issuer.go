// The licence issuer: the Ed25519 key that signs licence documents and
// the trust anchors exposed for verification (offline bundles).
package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// Issuer signs licence documents under a key id (kid). Documents carry the
// kid in each signature slot so verifiers can pick the right public key.
type Issuer struct {
	kid  string
	priv ed25519.PrivateKey
}

// NewIssuer validates kid/priv consistency and returns the issuer. priv
// must be a 64-byte Ed25519 private key (seed||public).
func NewIssuer(kid string, priv ed25519.PrivateKey) (*Issuer, error) {
	if kid == "" {
		return nil, fmt.Errorf("licensing: issuer kid must not be empty")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("licensing: issuer key is %d bytes, want %d", len(priv), ed25519.PrivateKeySize)
	}
	return &Issuer{kid: kid, priv: priv}, nil
}

// LoadIssuer parses a file-mounted signing key: base64 of either the
// 64-byte private key or the 32-byte seed (expanded in place). The file's
// contents are handled by internal/secrets — never logged.
func LoadIssuer(kid string, keyFileContents string) (*Issuer, error) {
	raw, err := base64.StdEncoding.DecodeString(keyFileContents)
	if err != nil {
		return nil, fmt.Errorf("licensing: signing key is not base64")
	}
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return NewIssuer(kid, ed25519.PrivateKey(raw))
	case ed25519.SeedSize:
		return NewIssuer(kid, ed25519.NewKeyFromSeed(raw))
	default:
		return nil, fmt.Errorf("licensing: signing key is %d bytes, want %d (private key) or %d (seed)",
			len(raw), ed25519.PrivateKeySize, ed25519.SeedSize)
	}
}

// KID returns the issuer's key id.
func (i *Issuer) KID() string { return i.kid }

// SignRaw signs arbitrary bytes with the issuer key — for signature
// schemes that are not licence documents (offline bundle manifests,
// docs/offline-bundles.md).
func (i *Issuer) SignRaw(msg []byte) []byte { return ed25519.Sign(i.priv, msg) }

// PublicKey returns the issuer's Ed25519 public key.
func (i *Issuer) PublicKey() ed25519.PublicKey {
	return i.priv.Public().(ed25519.PublicKey) //nolint:forcetypeassert -- Ed25519 keys only
}

// VerificationKey is a public trust anchor named by kid.
type VerificationKey struct {
	KID       string `json:"kid"`
	Alg       string `json:"alg"`
	PublicKey string `json:"public_key"` // base64, 32 bytes
}

// VerificationKeys returns the trust anchors a verifier needs for this
// issuer's documents — currently just the issuer's own key. When a second
// issuer key is introduced it is added here (rotation slot).
func (i *Issuer) VerificationKeys() []VerificationKey {
	return []VerificationKey{{
		KID:       i.kid,
		Alg:       AlgEd25519,
		PublicKey: base64.StdEncoding.EncodeToString(i.PublicKey()),
	}}
}

// TrustedKeys returns the kid->pubkey map for VerifyDocument.
func (i *Issuer) TrustedKeys() map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{i.kid: i.PublicKey()}
}
