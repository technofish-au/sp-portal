-- name: GetOrganisation :one
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at
  FROM organisations WHERE id = ?;

-- name: GetOrganisationBySlug :one
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at
  FROM organisations WHERE slug = ?;

-- name: ListOrganisations :many
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at
  FROM organisations ORDER BY name, id LIMIT ? OFFSET ?;

-- name: CreateOrganisation :exec
INSERT INTO organisations (id, name, slug, billing_email)
VALUES (?, ?, ?, ?);

-- name: SetOrganisationStripeCustomer :exec
UPDATE organisations SET stripe_customer_id = ? WHERE id = ?;

-- name: CountOrganisations :one
SELECT COUNT(*) FROM organisations;
