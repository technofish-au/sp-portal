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

// Auth state lives on the instance row itself (migration 00006):
// instances.public_key is the bound request-signing key and
// instances.suspected_clone_at is the clone flag. Audit events are still
// written for the forensic trail (which keys clashed) but the columns
// are the state of record. Actions:
//
//	instance.key_bound        detail {"public_key": "<base64>"}
//	instance.suspected_clone  detail {"bound_key_id","presented_key_id"}
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

// NewStore returns the instance-auth store.
func NewStore(db *sql.DB) *Store { return &Store{q: dbq.New(db)} }

// KeyID is the short, log-safe identifier of a public key (first 16 bytes
// of its SHA-256, base64url). It appears in audit detail rows; the full
// key never does beyond its bound record.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:16])
}

// BoundKey returns the public key bound to the instance
// (instances.public_key). found is false when no key has ever been
// bound — activation is what binds keys.
func (s *Store) BoundKey(ctx context.Context, instanceID string) (pub ed25519.PublicKey, found bool, err error) {
	inst, err := s.q.GetInstance(ctx, instanceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("instauth: bound key: %w", err)
	}
	if !inst.PublicKey.Valid {
		return nil, false, nil
	}
	key := []byte(inst.PublicKey.String)
	if len(key) != ed25519.PublicKeySize {
		return nil, false, fmt.Errorf("instauth: bound key malformed")
	}
	return ed25519.PublicKey(key), true, nil
}

// BindKey records public key pub as the instance's request-signing key.
// The column write is guarded by public_key IS NULL so an existing
// binding is never overwritten; the audit row keeps the event trail.
func (s *Store) BindKey(ctx context.Context, orgID, instanceID string, pub ed25519.PublicKey) error {
	if err := s.q.BindInstancePublicKey(ctx, dbq.BindInstancePublicKeyParams{
		PublicKey: sql.NullString{String: string(pub), Valid: true},
		ID:        instanceID,
	}); err != nil {
		return fmt.Errorf("instauth: bind key: %w", err)
	}
	detail, err := json.Marshal(map[string]string{
		"public_key": base64.StdEncoding.EncodeToString(pub),
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
	if err := s.q.FlagInstanceClone(ctx, instanceID); err != nil {
		return fmt.Errorf("instauth: flag clone: %w", err)
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
	inst, err := s.q.GetInstance(ctx, instanceID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return inst.SuspectedCloneAt != nil, nil
}
