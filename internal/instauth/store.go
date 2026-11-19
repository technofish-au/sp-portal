package instauth

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// Auth state has no dedicated columns in the frozen R5-1 schema (no
// instances.public_key, no clone flag), so bindings ride on the
// append-only audit_log — the one JSON-detail event table. Actions:
//
//	instance.key_bound        detail {"public_key": "<base64>"}
//	instance.suspected_clone  detail {"bound_key_id","presented_key_id"}
//
// target_type is always "instance", target_id the instances.id. The most
// recent key_bound event is the active binding.
const (
	ActionKeyBound       = "instance.key_bound"
	ActionSuspectedClone = "instance.suspected_clone"
	TargetTypeInstance   = "instance"
)

// Store is the database side of instance authentication. licensing calls
// BindKey/FlagClone at activation; the middleware calls BoundKey and
// CloneFlagged per request.
type Store struct {
	q *dbq.Queries
}

// NewStore returns the audit_log-backed instance-auth store.
func NewStore(db *sql.DB) *Store { return &Store{q: dbq.New(db)} }

// KeyID is the short, log-safe identifier of a public key (first 16 bytes
// of its SHA-256, base64url). It appears in audit detail rows; the full
// key never does beyond its bound record.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

type keyBoundDetail struct {
	PublicKey string `json:"public_key"`
}

// BoundKey returns the public key currently bound to the instance
// (the latest key_bound audit event). found is false when no key has ever
// been bound — activation is what binds keys.
func (s *Store) BoundKey(ctx context.Context, instanceID string) (pub ed25519.PublicKey, found bool, err error) {
	raw, err := s.q.LatestAuditDetail(ctx, dbq.LatestAuditDetailParams{
		Action:     ActionKeyBound,
		TargetType: TargetTypeInstance,
		TargetID:   instanceID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("instauth: bound key: %w", err)
	}
	var d keyBoundDetail
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, false, fmt.Errorf("instauth: bound key detail: %w", err)
	}
	key, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("instauth: bound key detail malformed")
	}
	return ed25519.PublicKey(key), true, nil
}

// BindKey records public key pub as the instance's request-signing key.
func (s *Store) BindKey(ctx context.Context, orgID, instanceID string, pub ed25519.PublicKey) error {
	detail, err := json.Marshal(keyBoundDetail{
		PublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		return err
	}
	return s.q.InsertAuditEvent(ctx, dbq.InsertAuditEventParams{
		ID:         uuid.Must(uuid.NewV7()).String(),
		OrgID:      sql.NullString{String: orgID, Valid: orgID != ""},
		Action:     ActionKeyBound,
		TargetType: TargetTypeInstance,
		TargetID:   instanceID,
		Detail:     detail,
	})
}

// FlagClone records that a different key presented the instance's stable
// identity — the durable half of clone detection (see CheckIn status).
// It is idempotent: a second flag for the same instance is a no-op.
func (s *Store) FlagClone(ctx context.Context, orgID, instanceID string, bound, presented ed25519.PublicKey) error {
	flagged, err := s.CloneFlagged(ctx, instanceID)
	if err != nil || flagged {
		return err
	}
	detail, err := json.Marshal(map[string]string{
		"bound_key_id":     KeyID(bound),
		"presented_key_id": KeyID(presented),
	})
	if err != nil {
		return err
	}
	return s.q.InsertAuditEvent(ctx, dbq.InsertAuditEventParams{
		ID:         uuid.Must(uuid.NewV7()).String(),
		OrgID:      sql.NullString{String: orgID, Valid: orgID != ""},
		Action:     ActionSuspectedClone,
		TargetType: TargetTypeInstance,
		TargetID:   instanceID,
		Detail:     detail,
	})
}

// CloneFlagged reports whether the instance carries the suspected_clone
// flag — surfaced as the check-in status rather than a block.
func (s *Store) CloneFlagged(ctx context.Context, instanceID string) (bool, error) {
	return s.q.HasAuditEvent(ctx, dbq.HasAuditEventParams{
		Action:     ActionSuspectedClone,
		TargetType: TargetTypeInstance,
		TargetID:   instanceID,
	})
}
