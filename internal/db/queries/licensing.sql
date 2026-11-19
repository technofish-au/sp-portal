-- Licence-domain queries (R5-2): licence lookup, instance registration,
-- check-in reports and the audit_log events that stand in for dedicated
-- columns (key bindings, clone flags, issued document hashes) while the
-- schema is frozen.

-- name: GetLicenceByKey :one
SELECT id, org_id, subscription_id, licence_key, kind, plan, max_instances,
       issued_at, expires_at, revoked_at, created_at, updated_at
  FROM licences WHERE licence_key = ?;

-- name: GetLicence :one
SELECT id, org_id, subscription_id, licence_key, kind, plan, max_instances,
       issued_at, expires_at, revoked_at, created_at, updated_at
  FROM licences WHERE id = ?;

-- name: CountLicenceInstances :one
-- Seats in use: registered instances not decommissioned.
SELECT COUNT(*) FROM instances
 WHERE licence_id = ? AND status <> 'decommissioned';

-- name: GetInstance :one
SELECT id, org_id, licence_id, name, fingerprint, appliance_version, status,
       last_seen_at, created_at, updated_at
  FROM instances WHERE id = ?;

-- name: GetInstanceByFingerprint :one
-- fingerprint carries the appliance-supplied instance_id (stable machine
-- identity); the unique (org_id, fingerprint) key makes re-activation an
-- update rather than a duplicate.
SELECT id, org_id, licence_id, name, fingerprint, appliance_version, status,
       last_seen_at, created_at, updated_at
  FROM instances WHERE org_id = ? AND fingerprint = ?;

-- name: CreateInstance :exec
INSERT INTO instances (id, org_id, licence_id, name, fingerprint,
                       appliance_version, status)
VALUES (?, ?, ?, ?, ?, ?, 'active');

-- name: UpdateInstanceLicence :exec
UPDATE instances SET licence_id = ?, name = ?, appliance_version = ?
 WHERE id = ?;

-- name: TouchInstance :exec
-- Empty appliance_version keeps the stored value (heartbeat check-ins may
-- not know it).
UPDATE instances SET last_seen_at = CURRENT_TIMESTAMP(6),
                     appliance_version = COALESCE(NULLIF(sqlc.arg(appliance_version), ''), appliance_version)
 WHERE id = sqlc.arg(id);

-- name: InsertInstanceReport :exec
INSERT INTO instance_reports (id, instance_id, reported_at, payload)
VALUES (?, ?, ?, ?);

-- name: LatestPublishedRelease :one
SELECT id, version, component, channel, notes, artifact_path, sha256,
       size_bytes, published_at, created_at, updated_at
  FROM releases
 WHERE component = ? AND channel = ? AND published_at IS NOT NULL
 ORDER BY published_at DESC, id DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_log (id, org_id, actor_user_id, actor_email, action,
                       target_type, target_id, detail, ip)
VALUES (?, ?, NULL, '', ?, ?, ?, ?, '');

-- name: LatestAuditDetail :one
-- Most recent audit event detail for a (target_type, target_id, action)
-- triple; used for instance key bindings (action 'instance.key_bound').
SELECT detail FROM audit_log
 WHERE action = ? AND target_type = ? AND target_id = ?
 ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: HasAuditEvent :one
SELECT EXISTS(
    SELECT 1 FROM audit_log
     WHERE action = ? AND target_type = ? AND target_id = ?
);

-- name: InsertDownloadToken :exec
INSERT INTO download_tokens (id, token_hash, org_id, kind, path, expires_at)
VALUES (?, ?, ?, ?, ?, ?);
