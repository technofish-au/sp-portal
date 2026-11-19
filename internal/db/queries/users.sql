-- name: GetUser :one
SELECT id, email, display_name, password_hash, is_platform_admin,
       totp_secret_enc, totp_enabled, disabled_at,
       created_at, updated_at, email_verified_at
  FROM users WHERE id = ?;

-- name: GetUserByEmail :one
SELECT id, email, display_name, password_hash, is_platform_admin,
       totp_secret_enc, totp_enabled, disabled_at,
       created_at, updated_at, email_verified_at
  FROM users WHERE email = ?;

-- name: CreateUser :exec
INSERT INTO users (id, email, display_name, password_hash, is_platform_admin)
VALUES (?, ?, ?, ?, ?);

-- name: ListOrgMembers :many
SELECT u.id, u.email, u.display_name, m.role
  FROM memberships m JOIN users u ON u.id = m.user_id
 WHERE m.org_id = ? ORDER BY u.email;

-- name: UpdateUserPassword :exec
UPDATE users SET password_hash = ? WHERE id = ?;

-- name: SetUserTOTPSecret :exec
UPDATE users SET totp_secret_enc = ? WHERE id = ?;

-- name: SetUserTOTPEnabled :exec
UPDATE users SET totp_enabled = ? WHERE id = ?;

-- name: SetUserEmailVerified :exec
UPDATE users SET email_verified_at = CURRENT_TIMESTAMP(6)
 WHERE id = ? AND email_verified_at IS NULL;
