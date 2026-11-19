-- name: CreateLicence :exec
INSERT INTO licences (id, org_id, subscription_id, licence_key, kind, plan,
                      max_instances, issued_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- Customer + staff views (R5-5).

-- name: ListLicencesByOrg :many
SELECT id, org_id, subscription_id, licence_key, kind, plan,
       max_instances, issued_at, expires_at, revoked_at, created_at, updated_at,
       doc_hash
  FROM licences WHERE org_id = ? ORDER BY created_at DESC, id DESC;

-- name: RevokeLicence :exec
-- NULL guard keeps revocation idempotent; the first revoke time stands.
UPDATE licences SET revoked_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND revoked_at IS NULL;

-- name: SearchLicences :many
-- Staff search: licence key substring, or an exact licence/org id.
SELECT id, org_id, subscription_id, licence_key, kind, plan,
       max_instances, issued_at, expires_at, revoked_at, created_at, updated_at,
       doc_hash
  FROM licences
 WHERE licence_key LIKE ? OR id = ? OR org_id = ?
 ORDER BY created_at DESC LIMIT ?;
