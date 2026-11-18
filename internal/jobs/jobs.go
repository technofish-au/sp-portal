// Package jobs implements the durable job queue on the jobs table: enqueue
// with an optional dedupe key, claim with SELECT ... FOR UPDATE SKIP
// LOCKED, retry with exponential backoff and a terminal dead state.
//
// Job lifecycle:
//
//	pending --claim--> running --handler ok--> done
//	                       |---handler err, attempts < max--> pending (backoff)
//	                       |---handler err, attempts >= max--> dead
//	                       |---worker death, claim stale-----> pending (reaper)
//
// Timestamps are UTC (the pool's session time_zone is fixed to +00:00).
package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// Job is one claimed unit of work.
type Job struct {
	ID        string
	Kind      string
	Payload   json.RawMessage
	Attempts  int // already incremented for the current try
	DedupeKey string
}

// Handler processes one claimed job. A nil return marks the job done; an
// error reschedules it with backoff (or kills it once attempts reaches
// max_attempts). ctx is the worker's: on graceful shutdown handlers should
// finish promptly.
type Handler func(ctx context.Context, job Job) error

// Queue is the enqueue side of the jobs table.
type Queue struct {
	db  *sql.DB
	now func() time.Time
}

// NewQueue returns the enqueue side over db.
func NewQueue(db *sql.DB) *Queue {
	return &Queue{db: db, now: func() time.Time { return time.Now().UTC() }}
}

// EnqueueOption tweaks one enqueue.
type EnqueueOption func(*enqueueOpts)

type enqueueOpts struct {
	dedupeKey   string
	runAt       time.Time
	maxAttempts int
}

// WithDedupeKey makes the enqueue idempotent: a second enqueue with the
// same key returns the existing job's id and a nil error.
func WithDedupeKey(key string) EnqueueOption {
	return func(o *enqueueOpts) { o.dedupeKey = key }
}

// WithRunAt schedules the job for later; the zero value means now.
func WithRunAt(t time.Time) EnqueueOption {
	return func(o *enqueueOpts) { o.runAt = t.UTC() }
}

// WithMaxAttempts overrides the default max_attempts (8).
func WithMaxAttempts(n int) EnqueueOption {
	return func(o *enqueueOpts) { o.maxAttempts = n }
}

// Enqueue inserts a pending job of kind with a JSON payload and returns
// its id. When a dedupe key collides the insert is a no-op and the id of
// the existing job is returned.
func (q *Queue) Enqueue(ctx context.Context, kind string, payload any, opts ...EnqueueOption) (string, error) {
	var o enqueueOpts
	for _, opt := range opts {
		opt(&o)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("jobs: marshal payload: %w", err)
	}
	id := uuid.Must(uuid.NewV7()).String()
	runAt := o.runAt
	if runAt.IsZero() {
		runAt = q.now()
	}
	maxAttempts := o.maxAttempts
	if maxAttempts == 0 {
		maxAttempts = 8
	}
	var dedupe any
	if o.dedupeKey != "" {
		dedupe = o.dedupeKey
	}
	_, err = q.db.ExecContext(ctx,
		`INSERT INTO jobs (id, kind, payload, dedupe_key, run_at, max_attempts)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, kind, raw, dedupe, runAt, maxAttempts)
	if err == nil {
		return id, nil
	}
	if !isDuplicate(err) || o.dedupeKey == "" {
		return "", fmt.Errorf("jobs: enqueue %s: %w", kind, err)
	}
	var existing string
	switch qerr := q.db.QueryRowContext(ctx,
		`SELECT id FROM jobs WHERE dedupe_key = ?`, o.dedupeKey).Scan(&existing); {
	case qerr != nil:
		return "", fmt.Errorf("jobs: enqueue %s: %w (dedupe lookup: %v)", kind, err, qerr)
	default:
		return existing, nil
	}
}

// backoff returns the retry delay after the given (1-based) attempt:
// base * 2^(attempt-1) capped at max, with ±25% jitter.
func backoff(base, maxDelay time.Duration, attempt int) time.Duration {
	d := base
	for i := 1; i < attempt && d < maxDelay; i++ {
		d *= 2
	}
	d = min(d, maxDelay)
	// ±25% jitter: multiply by a factor in [0.75, 1.25).
	jitter := 0.75 + rand.Float64()*0.5 //nolint:gosec -- jitter need not be crypto
	return time.Duration(float64(d) * jitter)
}

// isDuplicate reports whether err is MySQL error 1062 (duplicate entry
// for a unique key) — the dedupe-key collision.
func isDuplicate(err error) bool {
	var merr *gomysql.MySQLError
	return errors.As(err, &merr) && merr.Number == 1062
}
