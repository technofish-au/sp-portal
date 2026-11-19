-- name: CreateSubscription :exec
INSERT INTO subscriptions (id, org_id, stripe_subscription_id, stripe_price_id,
                           plan, status, seats, current_period_start,
                           current_period_end, cancel_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetSubscription :one
SELECT id, org_id, stripe_subscription_id, stripe_price_id, plan, status,
       seats, current_period_start, current_period_end, cancel_at,
       created_at, updated_at
  FROM subscriptions WHERE id = ?;

-- name: GetLatestSubscriptionByOrg :one
SELECT id, org_id, stripe_subscription_id, stripe_price_id, plan, status,
       seats, current_period_start, current_period_end, cancel_at,
       created_at, updated_at
  FROM subscriptions WHERE org_id = ? ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: GetSubscriptionByStripeID :one
SELECT id, org_id, stripe_subscription_id, stripe_price_id, plan, status,
       seats, current_period_start, current_period_end, cancel_at,
       created_at, updated_at
  FROM subscriptions WHERE stripe_subscription_id = ?;

-- name: UpdateSubscriptionState :exec
UPDATE subscriptions
   SET stripe_subscription_id = ?, stripe_price_id = ?, plan = ?, status = ?,
       seats = ?, current_period_start = ?, current_period_end = ?, cancel_at = ?
 WHERE id = ?;

-- name: ListPastDueSubscriptions :many
SELECT s.id, s.org_id, s.stripe_subscription_id, s.stripe_price_id, s.plan,
       s.status, s.seats, s.current_period_start, s.current_period_end,
       s.cancel_at, s.created_at, s.updated_at
  FROM subscriptions s
 WHERE s.status = 'past_due' AND s.updated_at < ?
 ORDER BY s.updated_at, s.id;
