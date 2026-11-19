-- name: InsertAuditLog :exec
INSERT INTO audit_log (id, org_id, actor_user_id, actor_email, action,
                       target_type, target_id, detail, ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CountAuditActions :one
SELECT COUNT(*) FROM audit_log WHERE actor_user_id = ? AND action = ?;

-- name: ListAuditByOrg :many
SELECT id, org_id, actor_user_id, actor_email, action, target_type,
       target_id, detail, ip, created_at
  FROM audit_log WHERE org_id = ? ORDER BY created_at DESC, id DESC
 LIMIT ? OFFSET ?;
