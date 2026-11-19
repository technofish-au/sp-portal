-- Licence-domain queries (R5-2): licence lookup, instance registration,
-- check-in reports and the real auth-state columns added by migration
-- 00006 (public_key, suspected_clone_at, doc_hash). audit_log events are
-- still written for the forensic trail (which keys clashed, which kid
-- signed an issuance) but are no longer the state of record.

-- name: GetLicenceByKey :one
SELECT id, org_id, subscription_id, licence_key, kind, plan,
       max_instances, issued_at, expires_at, revoked_at, created_at, updated_at,
       doc_hash
  FROM licences WHERE licence_key = ?;

-- name: GetLicence :one
SELECT id, org_id, subscription_id, licence_key, kind, plan,
       max_instances, issued_at, expires_at, revoked_at, created_at, updated_at,
       doc_hash
  FROM licences WHERE id = ?;

-- name: SetLicenceDocHash :exec
-- Hash of the most recently issued signed licence document.
UPDATE licences SET doc_hash = ? WHERE id = ?;

-- name: CountLicenceInstances :one
-- Seats in use: registered instances not decommissioned.
SELECT COUNT(*) FROM instances
 WHERE licence_id = ? AND status <> 'decommissioned';

-- name: GetInstance :one
SELECT id, org_id, licence_id, name, fingerprint,
       appliance_version, status, last_seen_at,
       created_at, updated_at, public_key, suspected_clone_at
  FROM instances WHERE id = ?;

-- name: GetInstanceByFingerprint :one
-- fingerprint carries the appliance-supplied instance_id (stable machine
-- identity); the unique (org_id, fingerprint) key makes re-activation an
-- update rather than a duplicate.
SELECT id, org_id, licence_id, name, fingerprint,
       appliance_version, status, last_seen_at,
       created_at, updated_at, public_key, suspected_clone_at
  FROM instances WHERE org_id = ? AND fingerprint = ?;

-- name: CreateInstance :exec
INSERT INTO instances (id, org_id, licence_id, name, fingerprint,
                       appliance_version, status)
VALUES (?, ?, ?, ?, ?, ?, 'active');

-- name: UpdateInstanceLicence :exec
UPDATE instances SET licence_id = ?, name = ?, appliance_version = ?
 WHERE id = ?;

-- name: BindInstancePublicKey :exec
-- Binds the request-signing key once; the NULL guard makes it a no-op if
-- a key was already bound (re-binding is not a thing — a clashing key is
-- a clone flag instead).
UPDATE instances SET public_key = ? WHERE id = ? AND public_key IS NULL;

-- name: FlagInstanceClone :exec
-- Sets suspected_clone_at once; NULL guard keeps it idempotent.
UPDATE instances SET suspected_clone_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND suspected_clone_at IS NULL;

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
-- "Published" excludes withdrawn releases (00007): published_at keeps
-- the history, withdrawn_at is the off switch.
SELECT id, version, component, channel, notes, artifact_path, sha256,
       size_bytes, published_at, created_at, updated_at,
       min_upgrade_from, security, withdrawn_at
  FROM releases
 WHERE component = ? AND channel = ? AND published_at IS NOT NULL
   AND withdrawn_at IS NULL
 ORDER BY published_at DESC, id DESC LIMIT 1;

-- name: InsertAuditEvent :exec
INSERT INTO audit_log (id, org_id, actor_user_id, actor_email, action,
                       target_type, target_id, detail, ip)
VALUES (?, ?, NULL, '', ?, ?, ?, ?, '');

-- name: InsertDownloadToken :exec
INSERT INTO download_tokens (id, token_hash, org_id, kind, path, expires_at)
VALUES (?, ?, ?, ?, ?, ?);
