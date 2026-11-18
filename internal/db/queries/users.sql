-- name: GetUser :one
SELECT id, email, display_name, password_hash, is_platform_admin,
       totp_secret_enc, totp_enabled, disabled_at, created_at, updated_at
  FROM users WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, email, display_name, password_hash, is_platform_admin,
       totp_secret_enc, totp_enabled, disabled_at, created_at, updated_at
  FROM users WHERE email = ?;

-- name: CreateUser :exec
INSERT INTO users (id, email, display_name, password_hash, is_platform_admin)
VALUES (?, ?, ?, ?, ?);

-- name: ListOrgMembers :many
SELECT u.id, u.email, u.display_name, m.role
  FROM memberships m JOIN users u ON u.id = m.user_id
 WHERE m.org_id = ? ORDER BY u.email;
