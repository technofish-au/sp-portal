-- name: InsertStripeEvent :exec
INSERT INTO stripe_events (id, event_id, type, livemode, payload)
VALUES (?, ?, ?, ?, ?);

-- name: GetStripeEvent :one
SELECT id, event_id, type, livemode, payload, processed_at, process_error, created_at
  FROM stripe_events WHERE event_id = ?;

-- name: MarkStripeEventProcessed :exec
UPDATE stripe_events
   SET processed_at = CURRENT_TIMESTAMP(6), process_error = NULL
 WHERE event_id = ?;

-- name: MarkStripeEventError :exec
UPDATE stripe_events SET process_error = ? WHERE event_id = ?;
