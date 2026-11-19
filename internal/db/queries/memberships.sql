-- name: CreateMembership :exec
INSERT INTO memberships (id, org_id, user_id, role)
VALUES (?, ?, ?, ?);

-- name: GetMembership :one
SELECT id, org_id, user_id, role, created_at
  FROM memberships WHERE org_id = ? AND user_id = ?;

-- name: ListUserMemberships :many
SELECT m.id, m.org_id, m.user_id, m.role, m.created_at, o.name AS org_name, o.slug AS org_slug
  FROM memberships m JOIN organisations o ON o.id = m.org_id
 WHERE m.user_id = ? ORDER BY o.name, o.id;

-- name: CountUserOwnerOrgs :one
SELECT COUNT(*) FROM memberships WHERE user_id = ? AND role = 'owner';

-- name: DeleteMembership :exec
DELETE FROM memberships WHERE org_id = ? AND user_id = ?;

-- name: UpdateMembershipRole :exec
UPDATE memberships SET role = ? WHERE org_id = ? AND user_id = ?;

-- name: CountOrgOwners :one
-- Guards the "can't demote/remove the last owner" rule.
SELECT COUNT(*) FROM memberships WHERE org_id = ? AND role = 'owner';
