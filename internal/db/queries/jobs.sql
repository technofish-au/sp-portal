-- Job-queue admin queries. Claiming lives in internal/jobs (plain
-- database/sql: it needs FOR UPDATE SKIP LOCKED and per-statement control
-- inside the claim transaction).

-- name: CountJobsByStatus :many
SELECT status, COUNT(*) AS count FROM jobs GROUP BY status;

-- name: ListDeadJobs :many
SELECT id, kind, attempts, last_error, created_at
  FROM jobs WHERE status = 'dead' ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: RequeueDeadJob :exec
UPDATE jobs SET status = 'pending', run_at = CURRENT_TIMESTAMP(6),
                attempts = 0, last_error = NULL
 WHERE id = ? AND status = 'dead';

-- name: GetJob :one
SELECT id, kind, payload, dedupe_key, status, attempts, max_attempts,
       run_at, claimed_by, claimed_at, last_error, created_at, updated_at,
       finished_at
  FROM jobs WHERE id = ?;

-- name: CountRunnableJobsByKind :one
SELECT COUNT(*) FROM jobs WHERE kind = ? AND status IN ('pending', 'running');
