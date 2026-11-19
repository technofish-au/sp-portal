-- name: GetOrganisation :one
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at, tax_id
  FROM organisations WHERE id = ?;

-- name: GetOrganisationBySlug :one
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at, tax_id
  FROM organisations WHERE slug = ?;

-- name: ListOrganisations :many
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at, tax_id
  FROM organisations ORDER BY name, id LIMIT ? OFFSET ?;

-- name: CreateOrganisation :exec
INSERT INTO organisations (id, name, slug, billing_email)
VALUES (?, ?, ?, ?);

-- name: SetOrganisationStripeCustomer :exec
UPDATE organisations SET stripe_customer_id = ? WHERE id = ?;

-- name: CountOrganisations :one
SELECT COUNT(*) FROM organisations;

-- name: GetOrganisationByStripeCustomer :one
SELECT id, name, slug, billing_email, stripe_customer_id, created_at, updated_at, tax_id
  FROM organisations WHERE stripe_customer_id = ?;

-- name: UpdateOrganisationBilling :exec
UPDATE organisations SET name = ?, billing_email = ? WHERE id = ?;

-- name: SetOrganisationTaxID :exec
UPDATE organisations SET tax_id = ? WHERE id = ?;
