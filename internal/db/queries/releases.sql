-- Release-catalogue queries (R5-4): the staff admin API (register,
-- publish, withdraw, security flag), HMAC download tokens, the apt
-- repository credential lookup and support-bundle uploads.
--
-- Column lists put columns added after the table's creation (migration
-- 00007's min_upgrade_from/security/withdrawn_at, 00006's doc_hash) at
-- the END of the SELECT so sqlc keeps emitting the dbq.<Model> types.

-- name: GetRelease :one
SELECT id, version, component, channel, notes, artifact_path, sha256,
       size_bytes, published_at, created_at, updated_at,
       min_upgrade_from, security, withdrawn_at
  FROM releases WHERE id = ?;

-- name: GetReleaseByVersion :one
SELECT id, version, component, channel, notes, artifact_path, sha256,
       size_bytes, published_at, created_at, updated_at,
       min_upgrade_from, security, withdrawn_at
  FROM releases WHERE component = ? AND version = ?;

-- name: ListReleases :many
SELECT id, version, component, channel, notes, artifact_path, sha256,
       size_bytes, published_at, created_at, updated_at,
       min_upgrade_from, security, withdrawn_at
  FROM releases ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?;

-- name: InsertRelease :exec
INSERT INTO releases (id, version, component, channel, notes,
                      min_upgrade_from, artifact_path, sha256, size_bytes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: PublishRelease :exec
-- NULL guard keeps publish idempotent — the first publish time stands.
UPDATE releases SET published_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND published_at IS NULL;

-- name: WithdrawRelease :exec
-- Withdrawal does not touch published_at (history); "published" means
-- published_at set AND withdrawn_at NULL.
UPDATE releases SET withdrawn_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND withdrawn_at IS NULL;

-- name: UpdateReleaseMeta :exec
-- Staff metadata edit: security flag and the upgrade floor.
UPDATE releases SET security = ?, min_upgrade_from = ? WHERE id = ?;

-- name: ListReleaseArtifactPaths :many
-- Referenced artifacts for the storage prune sweep.
SELECT artifact_path FROM releases WHERE artifact_path <> '';

-- name: ListWithdrawnArtifactPaths :many
-- Artifacts of withdrawn releases — eligible for pruning when the staff
-- action passes include_withdrawn.
SELECT artifact_path FROM releases
 WHERE artifact_path <> '' AND withdrawn_at IS NOT NULL;

-- name: GetDownloadToken :one
SELECT id, token_hash, org_id, kind, path, release_id, expires_at,
       used_at, created_by, created_at
  FROM download_tokens WHERE id = ?;

-- name: GetDownloadTokenByHash :one
-- The apt repo's basic-auth lookup (kind 'apt') and any other
-- bearer-token path that presents the raw credential.
SELECT id, token_hash, org_id, kind, path, release_id, expires_at,
       used_at, created_by, created_at
  FROM download_tokens WHERE token_hash = ? AND kind = ?;

-- name: InsertReleaseDownloadToken :exec
-- Unlike licensing's apt-token insert this records the release id and
-- the actor (created_by) that minted it.
INSERT INTO download_tokens (id, token_hash, org_id, kind, path,
                             release_id, expires_at, created_by)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: MarkDownloadTokenUsed :exec
-- First-use marker for the audit trail; range resumes keep working
-- because expiry, not used_at, is the gate.
UPDATE download_tokens SET used_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND used_at IS NULL;

-- name: GetLicenceForInstance :one
-- The licence an instance is bound to — the apt repo's entitlement gate.
SELECT l.id, l.org_id, l.subscription_id, l.licence_key, l.kind, l.plan,
       l.max_instances, l.issued_at, l.expires_at, l.revoked_at,
       l.created_at, l.updated_at, l.doc_hash
  FROM licences l JOIN instances i ON i.licence_id = l.id
 WHERE i.id = ?;

-- name: InsertSupportBundle :exec
INSERT INTO support_bundles (id, org_id, instance_id, path, size_bytes,
                             uploaded_by, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?);
