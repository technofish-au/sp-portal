// Database side of the licensing domain: licence validity, seat counting,
// instance registration and the audit_log records that stand in for
// columns the frozen schema lacks (issued document hashes live on
// licence.document_issued events; key bindings and clone flags live in
// internal/instauth's store on the same table).
package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
	"github.com/technofish-au/sp-portal/internal/instauth"
)

// ActionDocIssued is the audit_log action recording an issued licence
// document hash (there is no licences.doc_hash column; the event trail
// carries it). Detail: {"doc_hash","instance_id","kid"}.
const ActionDocIssued = "licence.document_issued"

// aptTokenKind is the download_tokens kind for apt repository credentials.
const aptTokenKind = "apt"

// aptTokenTTL bounds issued apt credentials when the licence itself has
// no expiry; licence expiry wins when sooner.
const aptTokenTTL = 365 * 24 * time.Hour

// ErrSeatLimit means activation would exceed licences.max_instances.
var ErrSeatLimit = errors.New("licensing: max_instances reached")

// licenceProblem classifies a licence row: "" usable, else the status the
// API reports ("revoked"/"expired").
func licenceProblem(lic dbq.Licence, now time.Time) string {
	switch {
	case lic.RevokedAt != nil:
		return "revoked"
	case lic.ExpiresAt != nil && !lic.ExpiresAt.After(now):
		return "expired"
	default:
		return ""
	}
}

// issueDocument signs a licence document binding lic to inst and records
// its hash on a licence.document_issued audit event.
func issueDocument(ctx context.Context, q *dbq.Queries, issuer *Issuer, lic dbq.Licence, inst dbq.Instance) (json.RawMessage, error) {
	doc, hash, err := issuer.Sign(Payload{
		Version:      1,
		LicenceID:    lic.ID,
		LicenceKey:   lic.LicenceKey,
		OrgID:        lic.OrgID,
		InstanceID:   inst.Fingerprint, // appliance-supplied stable identity
		Kind:         lic.Kind,
		Plan:         lic.Plan,
		MaxInstances: int64(lic.MaxInstances),
		Features:     planFeatures(lic.Plan),
		IssuedAt:     lic.IssuedAt,
		ExpiresAt:    lic.ExpiresAt,
	})
	if err != nil {
		return nil, err
	}
	detail, err := json.Marshal(map[string]string{
		"doc_hash":    hash,
		"instance_id": inst.ID,
		"kid":         issuer.KID(),
	})
	if err != nil {
		return nil, err
	}
	if err := q.InsertAuditEvent(ctx, dbq.InsertAuditEventParams{
		ID:         uuid.Must(uuid.NewV7()).String(),
		OrgID:      sql.NullString{String: lic.OrgID, Valid: true},
		Action:     ActionDocIssued,
		TargetType: "licence",
		TargetID:   lic.ID,
		Detail:     detail,
	}); err != nil {
		return nil, fmt.Errorf("licensing: record doc hash: %w", err)
	}
	return doc, nil
}

// planFeatures maps a plan to the feature list embedded in licence
// documents — informational entitlements for the appliance.
func planFeatures(plan string) []string {
	switch plan {
	case "pro":
		return []string{"monitoring", "apt-updates", "fleet"}
	case "enterprise":
		return []string{"monitoring", "apt-updates", "fleet", "sso"}
	default: // trial, starter
		return []string{"monitoring", "apt-updates"}
	}
}

// registerInstance finds or creates the instance for (lic.OrgID,
// instanceID) — the appliance-supplied stable identity stored in
// instances.fingerprint. When the instance already exists with a different
// bound public key the instance is flagged suspected_clone (recorded, not
// blocked). On a new instance the licence seat count is enforced first.
func registerInstance(ctx context.Context, q *dbq.Queries, keys *instauth.Store,
	lic dbq.Licence, instanceID, name, applianceVersion string, pub ed25519.PublicKey) (inst dbq.Instance, clone bool, err error) {

	inst, err = q.GetInstanceByFingerprint(ctx, dbq.GetInstanceByFingerprintParams{
		OrgID: lic.OrgID, Fingerprint: instanceID,
	})
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return inst, false, fmt.Errorf("licensing: instance lookup: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		seats, cerr := q.CountLicenceInstances(ctx, sql.NullString{String: lic.ID, Valid: true})
		if cerr != nil {
			return inst, false, fmt.Errorf("licensing: seat count: %w", cerr)
		}
		if seats >= int64(lic.MaxInstances) {
			return inst, false, ErrSeatLimit
		}
		inst = dbq.Instance{
			ID:               uuid.Must(uuid.NewV7()).String(),
			OrgID:            lic.OrgID,
			LicenceID:        sql.NullString{String: lic.ID, Valid: true},
			Name:             name,
			Fingerprint:      instanceID,
			ApplianceVersion: applianceVersion,
			Status:           "active",
		}
		if err := q.CreateInstance(ctx, dbq.CreateInstanceParams{
			ID:               inst.ID,
			OrgID:            inst.OrgID,
			LicenceID:        inst.LicenceID,
			Name:             inst.Name,
			Fingerprint:      inst.Fingerprint,
			ApplianceVersion: inst.ApplianceVersion,
		}); err != nil {
			return inst, false, fmt.Errorf("licensing: create instance: %w", err)
		}
	} else {
		// Re-activation of a known appliance: refresh licence/name/version.
		if err := q.UpdateInstanceLicence(ctx, dbq.UpdateInstanceLicenceParams{
			LicenceID:        sql.NullString{String: lic.ID, Valid: true},
			Name:             name,
			ApplianceVersion: applianceVersion,
			ID:               inst.ID,
		}); err != nil {
			return inst, false, fmt.Errorf("licensing: update instance: %w", err)
		}
		inst.LicenceID = sql.NullString{String: lic.ID, Valid: true}
		inst.Name = name
		inst.ApplianceVersion = applianceVersion
	}

	if pub == nil {
		return inst, false, nil // offline activation without a key: no binding
	}
	bound, found, err := keys.BoundKey(ctx, inst.ID)
	if err != nil {
		return inst, false, err
	}
	switch {
	case !found:
		if err := keys.BindKey(ctx, inst.OrgID, inst.ID, pub); err != nil {
			return inst, false, fmt.Errorf("licensing: bind key: %w", err)
		}
	case !bound.Equal(pub):
		// Same machine identity, different signing key: suspected clone.
		// Flag it — the original binding is kept so the real appliance's
		// check-ins keep working and see the flag.
		if err := keys.FlagClone(ctx, inst.OrgID, inst.ID, bound, pub); err != nil {
			return inst, false, fmt.Errorf("licensing: flag clone: %w", err)
		}
		clone = true
	}
	return inst, clone, nil
}

// aptCredentials mints a bearer token for the hosted apt repository; only
// its SHA-256 is stored (download_tokens, kind "apt"). The raw token is
// returned exactly once.
func aptCredentials(ctx context.Context, q *dbq.Queries, lic dbq.Licence, inst dbq.Instance, now time.Time) (username, password string, err error) {
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	password = "spapt_" + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(password))
	expires := now.Add(aptTokenTTL)
	if lic.ExpiresAt != nil && lic.ExpiresAt.Before(expires) {
		expires = *lic.ExpiresAt
	}
	if err := q.InsertDownloadToken(ctx, dbq.InsertDownloadTokenParams{
		ID:        uuid.Must(uuid.NewV7()).String(),
		TokenHash: hex.EncodeToString(sum[:]),
		OrgID:     sql.NullString{String: lic.OrgID, Valid: true},
		Kind:      aptTokenKind,
		Path:      "apt/",
		ExpiresAt: expires,
	}); err != nil {
		return "", "", fmt.Errorf("licensing: apt credentials: %w", err)
	}
	return inst.ID, password, nil
}
