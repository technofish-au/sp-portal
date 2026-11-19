// DEV-ONLY licence issuer keypair.
//
// The key material below is committed to the repository on purpose: it is
// the well-known development/test issuer so that local runs, the dev
// compose stack and integration tests can issue verifiable licence
// documents out of the box. It provides NO production security — anyone
// with repo access can forge documents signed by it. Production
// deployments MUST configure licence_signing_key_file with a real,
// file-mounted key and a distinct licence_issuer_kid; serve logs a warning
// whenever this embedded key is in use.
package licensing

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

// DevIssuerKID is the key id of the embedded development issuer.
const DevIssuerKID = "dev-issuer-1"

// Dev-issuer-1 key material (base64): 64-byte Ed25519 private key and its
// 32-byte public key. NEVER FOR PRODUCTION — see the package comment above.
const (
	devIssuerPrivB64 = "1OFt92c7P0qvHIxW+8phZRg6gRz0QUX5ODdZJmykYW6/lV+A3k1uigrIEjMphMd1Ai+HnC+M2Jp4l7cEBpFzRg=="
	devIssuerPubB64  = "v5VfgN5NbooKyBIzKYTHdQIvh5wvjNiaeJe3BAaRc0Y="
)

// DevIssuer returns the well-known development issuer (see warning above).
func DevIssuer() (*Issuer, error) {
	priv, err := base64.StdEncoding.DecodeString(devIssuerPrivB64)
	if err != nil {
		return nil, fmt.Errorf("licensing: decode dev issuer key: %w", err)
	}
	return NewIssuer(DevIssuerKID, ed25519.PrivateKey(priv))
}

// DevVerificationKey returns the dev issuer's public trust anchor, for
// including in offline bundles and the fakeportal contract tests.
func DevVerificationKey() (kid string, pub ed25519.PublicKey, err error) {
	raw, err := base64.StdEncoding.DecodeString(devIssuerPubB64)
	if err != nil {
		return "", nil, fmt.Errorf("licensing: decode dev issuer pubkey: %w", err)
	}
	return DevIssuerKID, ed25519.PublicKey(raw), nil
}
