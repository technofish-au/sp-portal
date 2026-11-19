// The signed licence document issued to appliances.
//
// Wire format (the "licence document", see docs/fakeportal.md):
//
//	{"licence": { ...payload... },
//	 "signatures": [{"kid": "...", "alg": "Ed25519", "sig": "<base64>"}]}
//
// The signed message is the canonical (JCS-subset, see canonical.go)
// serialisation of the "licence" member. Keeping signatures in an array —
// rather than a single sig field — is the key-rotation slot: an appliance
// accepts the document when ANY listed signature verifies against a key id
// it trusts, so a second issuer key can be introduced without invalidating
// documents or verifiers that only know the first.
package licensing

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// AlgEd25519 is the only signature algorithm the licence format uses.
const AlgEd25519 = "Ed25519"

// Payload is the signed content of a licence document. All fields are
// serialised by encoding/json under their snake_case names; the canonical
// form sorts them, so declaration order here is irrelevant to the
// signature.
type Payload struct {
	Version      int        `json:"v"`
	LicenceID    string     `json:"licence_id"`
	LicenceKey   string     `json:"licence_key"`
	OrgID        string     `json:"org_id"`
	InstanceID   string     `json:"instance_id"`
	Kind         string     `json:"kind"`
	Plan         string     `json:"plan"`
	MaxInstances int64      `json:"max_instances"`
	Features     []string   `json:"features"`
	IssuedAt     time.Time  `json:"-"`
	ExpiresAt    *time.Time `json:"-"`
	// IssuedAt/ExpiresAt travel on the wire as RFC3339 strings via the
	// marshal helpers below so the canonical form stays stringly-typed.
}

// signatureEntry is one slot in the envelope's signatures array.
type signatureEntry struct {
	KID string `json:"kid"`
	Alg string `json:"alg"`
	Sig string `json:"sig"`
}

// envelope is the wire shape of a signed licence document.
type envelope struct {
	Licence    json.RawMessage  `json:"licence"`
	Signatures []signatureEntry `json:"signatures"`
}

// payloadWire adapts Payload for wire serialisation (RFC3339 timestamps).
type payloadWire struct {
	Version      int      `json:"v"`
	LicenceID    string   `json:"licence_id"`
	LicenceKey   string   `json:"licence_key"`
	OrgID        string   `json:"org_id"`
	InstanceID   string   `json:"instance_id"`
	Kind         string   `json:"kind"`
	Plan         string   `json:"plan"`
	MaxInstances int64    `json:"max_instances"`
	Features     []string `json:"features"`
	IssuedAt     string   `json:"issued_at"`
	ExpiresAt    *string  `json:"expires_at"`
}

func (p Payload) wire() payloadWire {
	w := payloadWire{
		Version:      p.Version,
		LicenceID:    p.LicenceID,
		LicenceKey:   p.LicenceKey,
		OrgID:        p.OrgID,
		InstanceID:   p.InstanceID,
		Kind:         p.Kind,
		Plan:         p.Plan,
		MaxInstances: p.MaxInstances,
		Features:     p.Features,
		IssuedAt:     p.IssuedAt.UTC().Format(time.RFC3339),
	}
	if p.ExpiresAt != nil {
		s := p.ExpiresAt.UTC().Format(time.RFC3339)
		w.ExpiresAt = &s
	}
	return w
}

// Sign builds the signed licence document for payload: the canonical
// "licence" bytes signed with the issuer key, wrapped in the envelope.
// The returned document is itself canonical JSON.
func (i *Issuer) Sign(payload Payload) (doc []byte, docHash string, err error) {
	canon, err := CanonicalJSON(payload.wire())
	if err != nil {
		return nil, "", err
	}
	sig := ed25519.Sign(i.priv, canon)
	env, err := CanonicalJSON(envelope{
		Licence: canon,
		Signatures: []signatureEntry{{
			KID: i.kid,
			Alg: AlgEd25519,
			Sig: base64.StdEncoding.EncodeToString(sig),
		}},
	})
	if err != nil {
		return nil, "", err
	}
	return env, fmt.Sprintf("%x", sha256.Sum256(env)), nil
}

// ErrNoValidSignature means the document parsed but no listed signature
// verified against the trusted key set (covers tampered payloads).
var ErrNoValidSignature = errors.New("licensing: no valid signature")

// VerifyDocument parses a licence document and returns the signed payload
// when at least one listed signature verifies against a trusted key (the
// rotation slot). The "licence" member is re-canonicalised before
// verification, so documents produced by non-canonical writers still
// verify and any tampering invalidates the signature.
func VerifyDocument(doc []byte, trusted map[string]ed25519.PublicKey) (Payload, error) {
	var env envelope
	if err := json.Unmarshal(doc, &env); err != nil {
		return Payload{}, fmt.Errorf("licensing: document parse: %w", err)
	}
	canon, err := CanonicalJSON(env.Licence)
	if err != nil {
		return Payload{}, err
	}
	for _, entry := range env.Signatures {
		if entry.Alg != AlgEd25519 {
			continue
		}
		pub, ok := trusted[entry.KID]
		if !ok {
			continue // unknown key id: try the next rotation slot
		}
		sig, err := base64.StdEncoding.DecodeString(entry.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, canon, sig) {
			return decodePayload(env.Licence)
		}
	}
	return Payload{}, ErrNoValidSignature
}

// decodePayload converts the raw licence member back into a Payload.
func decodePayload(raw json.RawMessage) (Payload, error) {
	var w payloadWire
	if err := json.Unmarshal(raw, &w); err != nil {
		return Payload{}, fmt.Errorf("licensing: payload parse: %w", err)
	}
	issued, err := time.Parse(time.RFC3339, w.IssuedAt)
	if err != nil {
		return Payload{}, fmt.Errorf("licensing: payload issued_at: %w", err)
	}
	p := Payload{
		Version:      w.Version,
		LicenceID:    w.LicenceID,
		LicenceKey:   w.LicenceKey,
		OrgID:        w.OrgID,
		InstanceID:   w.InstanceID,
		Kind:         w.Kind,
		Plan:         w.Plan,
		MaxInstances: w.MaxInstances,
		Features:     w.Features,
		IssuedAt:     issued,
	}
	if w.ExpiresAt != nil {
		exp, err := time.Parse(time.RFC3339, *w.ExpiresAt)
		if err != nil {
			return Payload{}, fmt.Errorf("licensing: payload expires_at: %w", err)
		}
		p.ExpiresAt = &exp
	}
	return p, nil
}
