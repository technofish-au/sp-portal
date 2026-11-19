// Shared helpers for the releases domain: entitlement gating, storage
// path resolution, download-token minting and the audit action names.
package releases

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/technofish-au/sp-portal/internal/db/dbq"
)

// Audit action names written by this domain (target_type identifies what
// changed).
const (
	ActionRegistered      = "release.registered"
	ActionPublished       = "release.published"
	ActionWithdrawn       = "release.withdrawn"
	ActionMetaUpdated     = "release.updated"
	ActionBundleGenerated = "release.bundle_generated"
	ActionStoragePruned   = "release.storage_pruned"
	ActionSupportUploaded = "support_bundle.uploaded"

	// R5-5 additions.
	ActionDownloadMinted    = "release.download_url_minted"
	ActionSupportDownloaded = "support_bundle.downloaded"
)

// ephemeralSecret generates a dev fallback HMAC key (minted URLs die
// with the process).
func ephemeralSecret() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// storageJoin resolves rel below root/sub, refusing traversal that would
// escape the sub directory. Returned bool is false on escape.
func storageJoin(root, sub, rel string) (string, bool) {
	base := filepath.Join(root, sub)
	clean := filepath.Clean(filepath.Join(base, rel))
	if clean != base && !strings.HasPrefix(clean, base+string(filepath.Separator)) {
		return "", false
	}
	return clean, true
}

// entitlement returns the instance's download entitlement: a nil cutoff
// means fully entitled; a non-nil cutoff is the licence end time —
// releases published on/before it stay downloadable (the older-versions
// rule for expired/revoked licences) and newer ones are denied.
// noLicence reports the instance has no bound licence at all.
func (s *service) entitlement(ctx context.Context, inst dbq.Instance) (cutoff *time.Time, noLicence bool, err error) {
	if !inst.LicenceID.Valid {
		return nil, true, nil
	}
	lic, err := s.q.GetLicence(ctx, inst.LicenceID.String)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, true, nil
		}
		return nil, false, fmt.Errorf("releases: licence lookup: %w", err)
	}
	return licenceEnd(lic, s.now()), false, nil
}

// releaseAllowed applies the older-versions rule: fully entitled
// licences (nil cutoff) get everything; expired/revoked ones only
// releases published on/before the cutoff.
func releaseAllowed(rel dbq.Release, cutoff *time.Time) bool {
	if cutoff == nil {
		return true
	}
	return rel.PublishedAt != nil && !rel.PublishedAt.After(*cutoff)
}

// downloadSig is the HMAC-SHA256 over the signed-token fields; base64url.
// The covered string is documented in docs/fakeportal.md:
//
//	SP-DL-V1\n<token_id>\n<release_id>\n<exp_unix>\n<org_id>\n
func (s *service) downloadSig(tokenID, releaseID string, exp int64, orgID string) string {
	mac := hmac.New(sha256.New, s.opts.DownloadSecret)
	fmt.Fprintf(mac, "%s\n%s\n%s\n%d\n%s\n",
		downloadTokenHashPurpose, tokenID, releaseID, exp, orgID)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// mintToken records a download_tokens row (only the credential's SHA-256
// is stored) and returns the presented credential
// "<token_id>.<exp>.<sig>" the download URL carries as t=.
func (s *service) mintToken(ctx context.Context, rel dbq.Release, orgID, actorID string, now time.Time) (token string, expires time.Time, err error) {
	expires = now.Add(s.opts.DownloadURLTTL)
	tokenID := newID()
	sig := s.downloadSig(tokenID, rel.ID, expires.Unix(), orgID)
	token = fmt.Sprintf("%s.%d.%s", tokenID, expires.Unix(), sig)
	sum := sha256.Sum256([]byte(token))
	err = s.q.InsertReleaseDownloadToken(ctx, dbq.InsertReleaseDownloadTokenParams{
		ID:        tokenID,
		TokenHash: hex.EncodeToString(sum[:]),
		OrgID:     sql.NullString{String: orgID, Valid: orgID != ""},
		Kind:      tokenKindRelease,
		Path:      rel.ArtifactPath,
		ReleaseID: sql.NullString{String: rel.ID, Valid: true},
		ExpiresAt: expires,
		CreatedBy: sql.NullString{String: actorID, Valid: actorID != ""},
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("releases: mint token: %w", err)
	}
	return token, expires, nil
}

// validateToken parses the t= credential "<id>.<exp>.<sig>", checks the
// HMAC, expiry and the recorded download_tokens row. It returns the row
// on success; the error string is a stable machine code for the
// {error,message} envelope.
func (s *service) validateToken(ctx context.Context, releaseID, token string) (dbq.DownloadToken, string) {
	var tok dbq.DownloadToken
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return tok, "bad_token"
	}
	id, expStr, sig := parts[0], parts[1], parts[2]
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return tok, "bad_token"
	}
	tok, err = s.q.GetDownloadToken(ctx, id)
	if err != nil {
		return tok, "bad_token" // unknown ids and DB errors both deny
	}
	if !tok.ReleaseID.Valid || tok.ReleaseID.String != releaseID || tok.Kind != tokenKindRelease {
		return tok, "bad_token"
	}
	orgID := ""
	if tok.OrgID.Valid {
		orgID = tok.OrgID.String
	}
	if subtle.ConstantTimeCompare([]byte(sig), []byte(s.downloadSig(id, releaseID, exp, orgID))) != 1 {
		return tok, "bad_signature"
	}
	sum := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(tok.TokenHash)) != 1 {
		return tok, "bad_token"
	}
	if time.Unix(exp, 0).Before(s.now()) || tok.ExpiresAt.Before(s.now()) {
		return tok, "token_expired"
	}
	return tok, ""
}
