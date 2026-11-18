package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

// Defaults; override via the With* options.
const (
	DefaultInterval    = 1 * time.Second
	DefaultBatchSize   = 32
	DefaultStaleAfter  = 5 * time.Minute
	defaultBaseBackoff = 1 * time.Second
	defaultMaxBackoff  = 5 * time.Minute
	// DefaultConcurrency bounds concurrently running handlers (also the
	// worker's peak DB connection usage).
	DefaultConcurrency  = 8
	shutdownGracePeriod = 30 * time.Second
	// deadlockRetries is how many times a statement that lost an InnoDB
	// deadlock (error 1213) or lock wait (1205) is retried — losing side is
	// rolled back by InnoDB and the statement is safe to replay.
	deadlockRetries = 4
)

// Worker claims pending jobs off the jobs table and runs the Handler
// registered for each job's kind. Multiple workers (replicas or processes)
// share the table safely: claims hold row locks taken with FOR UPDATE
// SKIP LOCKED inside a transaction.
type Worker struct {
	db  *sql.DB
	id  string // claimed_by value; unique per Worker instance
	log *slog.Logger
	now func() time.Time

	handlers map[string]Handler

	interval    time.Duration
	batch       int
	staleAfter  time.Duration
	baseDelay   time.Duration
	maxDelay    time.Duration
	concurrency int

	wg sync.WaitGroup // in-flight job handlers
}

// Option configures a Worker.
type Option func(*Worker)

// WithLogger sets the worker's logger (default: discard).
func WithLogger(l *slog.Logger) Option {
	return func(w *Worker) { w.log = l }
}

// WithInterval sets the idle poll interval (default DefaultInterval).
func WithInterval(d time.Duration) Option {
	return func(w *Worker) { w.interval = d }
}

// WithBatchSize sets the maximum jobs claimed per poll (default
// DefaultBatchSize).
func WithBatchSize(n int) Option {
	return func(w *Worker) { w.batch = n }
}

// WithStaleAfter sets how old a 'running' claim must be before the reaper
// returns it to pending (default DefaultStaleAfter).
func WithStaleAfter(d time.Duration) Option {
	return func(w *Worker) { w.staleAfter = d }
}

// WithBackoff overrides the retry backoff base and cap.
func WithBackoff(base, maxDelay time.Duration) Option {
	return func(w *Worker) { w.baseDelay, w.maxDelay = base, maxDelay }
}

// WithConcurrency bounds how many handlers run at once (default
// DefaultConcurrency). It also bounds the worker's database footprint:
// handlers typically hold a connection each.
func WithConcurrency(n int) Option {
	return func(w *Worker) { w.concurrency = n }
}

// NewWorker returns a Worker over db. Register handlers before Run.
func NewWorker(db *sql.DB, opts ...Option) *Worker {
	w := &Worker{
		db:          db,
		id:          uuid.Must(uuid.NewV7()).String(),
		log:         slog.New(slog.DiscardHandler),
		now:         func() time.Time { return time.Now().UTC() },
		handlers:    map[string]Handler{},
		interval:    DefaultInterval,
		batch:       DefaultBatchSize,
		staleAfter:  DefaultStaleAfter,
		baseDelay:   defaultBaseBackoff,
		maxDelay:    defaultMaxBackoff,
		concurrency: DefaultConcurrency,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// Register installs h for job kind. Register before Run. The claim query
// only selects registered kinds, so a job whose kind no running worker
// handles stays pending (a claimed job that still loses its handler —
// e.g. a stale Worker — is sent to dead).
func (w *Worker) Register(kind string, h Handler) {
	w.handlers[kind] = h
}

// Run claims and processes jobs until ctx is cancelled, then drains
// in-flight handlers and releases still-unhandled claims back to pending
// (graceful shutdown). It returns nil on clean shutdown.
func (w *Worker) Run(ctx context.Context) error {
	log := w.log.With(slog.String("worker_id", w.id))
	log.Info("job worker started",
		slog.Duration("interval", w.interval), slog.Int("batch", w.batch))

	// The reaper runs on a slower cadence than the claim loop; every pass
	// through it is an index-scanning UPDATE that otherwise just adds lock
	// contention against claim/finish.
	reapEvery := max(w.staleAfter/4, 5*time.Second)
	lastReap := time.Time{}

	// slots bounds concurrently executing handlers.
	slots := make(chan struct{}, w.concurrency)

	for {
		if err := ctx.Err(); err != nil {
			break
		}
		if time.Since(lastReap) >= reapEvery {
			w.reapStale(ctx, log)
			lastReap = w.now()
		}
		claimed, err := w.claim(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Error("job claim failed", slog.String("error", err.Error()))
			if !sleepCtx(ctx, w.interval) {
				break
			}
			continue
		}
		if len(claimed) == 0 {
			if !sleepCtx(ctx, w.interval) {
				break
			}
			continue
		}
		for _, job := range claimed {
			// Wait for a handler slot; on shutdown the unstarted claims
			// stay 'running' until releaseMine returns them to pending.
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
			}
			if ctx.Err() != nil {
				break
			}
			w.wg.Add(1)
			go func() {
				defer func() { <-slots }()
				w.execute(ctx, log, job)
			}()
		}
	}

	log.Info("job worker draining", slog.Duration("grace", shutdownGracePeriod))
	done := make(chan struct{})
	go func() { w.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(shutdownGracePeriod):
		log.Warn("job worker drain timed out")
	}
	requeued, err := w.releaseMine(context.WithoutCancel(ctx))
	if err != nil {
		log.Error("releasing claimed jobs failed", slog.String("error", err.Error()))
	} else if requeued > 0 {
		log.Info("released claimed jobs", slog.Int64("jobs", requeued))
	}
	log.Info("job worker stopped")
	return nil
}

// isDeadlock reports whether err is a transient InnoDB lock failure:
// 1213 (deadlock — InnoDB rolled the loser back) or 1205 (lock wait
// timeout). Both are safe to retry.
func isDeadlock(err error) bool {
	var merr *gomysql.MySQLError
	return errors.As(err, &merr) && (merr.Number == 1213 || merr.Number == 1205)
}

// claim takes row locks on up to batch due pending jobs — of the kinds
// this worker has handlers for — and marks them running under this
// worker's id, in one transaction. Deadlock losers are retried a few
// times before the error reaches the caller.
func (w *Worker) claim(ctx context.Context) ([]Job, error) {
	var lastErr error
	for i := 0; i < deadlockRetries; i++ {
		claimed, err := w.claimOnce(ctx)
		if err == nil {
			return claimed, nil
		}
		if !isDeadlock(err) || ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
		if !sleepCtx(ctx, 20*time.Millisecond) {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// claimOnce is one claim transaction. The kind filter keeps heterogenous
// workers (different deployments, different registered handlers) out of
// each other's queues: an unhandled kind is left pending rather than
// killed.
func (w *Worker) claimOnce(ctx context.Context) ([]Job, error) {
	kinds := make([]string, 0, len(w.handlers))
	args := make([]any, 0, len(w.handlers)+1)
	for kind := range w.handlers {
		kinds = append(kinds, kind)
		args = append(args, kind)
	}
	if len(kinds) == 0 {
		return nil, nil // no handlers registered: nothing we can process
	}
	placeholders := strings.Repeat("?,", len(kinds))
	tx, err := w.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("jobs: claim begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	args = append(args, w.batch)
	rows, err := tx.QueryContext(ctx,
		fmt.Sprintf(`SELECT id, kind, payload, attempts, IFNULL(dedupe_key, '')
		   FROM jobs
		  WHERE status = 'pending' AND run_at <= UTC_TIMESTAMP(6)
		    AND kind IN (%s)
		  ORDER BY run_at, id
		  LIMIT ?
		  FOR UPDATE SKIP LOCKED`, placeholders[:len(placeholders)-1]), args...)
	if err != nil {
		return nil, fmt.Errorf("jobs: claim select: %w", err)
	}
	var claimed []Job
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Kind, &j.Payload, &j.Attempts, &j.DedupeKey); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("jobs: claim scan: %w", err)
		}
		claimed = append(claimed, j)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("jobs: claim rows: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("jobs: claim close: %w", err)
	}
	for i := range claimed {
		res, err := tx.ExecContext(ctx,
			`UPDATE jobs
			    SET status = 'running', claimed_by = ?, claimed_at = UTC_TIMESTAMP(6),
			        attempts = attempts + 1
			  WHERE id = ? AND status = 'pending'`, w.id, claimed[i].ID)
		if err != nil {
			return nil, fmt.Errorf("jobs: claim update: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 1 {
			claimed[i].Attempts++
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("jobs: claim commit: %w", err)
	}
	return claimed, nil
}

// execute runs the handler for job and finishes it.
func (w *Worker) execute(ctx context.Context, log *slog.Logger, job Job) {
	defer w.wg.Done()
	l := log.With(slog.String("job_id", job.ID), slog.String("kind", job.Kind),
		slog.Int("attempt", job.Attempts))
	h, ok := w.handlers[job.Kind]
	if !ok {
		if err := w.kill(context.WithoutCancel(ctx), job.ID,
			"no handler registered for kind "+job.Kind); err != nil {
			l.Error("marking job dead failed", slog.String("error", err.Error()))
		}
		return
	}
	// The handler sees the cancellable ctx; the bookkeeping below uses a
	// detached ctx so the outcome is recorded even during shutdown drain
	// (otherwise the job would sit 'running' until the stale reaper).
	if err := h(ctx, job); err != nil {
		l.Warn("job failed", slog.String("error", err.Error()))
		if ferr := w.fail(context.WithoutCancel(ctx), job, err); ferr != nil {
			l.Error("rescheduling job failed", slog.String("error", ferr.Error()))
		}
		return
	}
	if err := w.finish(context.WithoutCancel(ctx), job.ID); err != nil {
		l.Error("finishing job failed", slog.String("error", err.Error()))
	}
}

// execRetry runs a single autocommit statement, retrying transient InnoDB
// deadlocks (the loser is rolled back, so replaying is safe).
func (w *Worker) execRetry(ctx context.Context, query string, args ...any) (sql.Result, error) {
	var lastErr error
	for i := 0; i < deadlockRetries; i++ {
		res, err := w.db.ExecContext(ctx, query, args...)
		if err == nil {
			return res, nil
		}
		if !isDeadlock(err) || ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
		if !sleepCtx(ctx, 20*time.Millisecond) {
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

// finish marks a successfully processed job done.
func (w *Worker) finish(ctx context.Context, id string) error {
	_, err := w.execRetry(ctx,
		`UPDATE jobs SET status = 'done', finished_at = UTC_TIMESTAMP(6),
		                    claimed_by = NULL, claimed_at = NULL, last_error = NULL
		  WHERE id = ?`, id)
	return err
}

// fail reschedules the job with exponential backoff, or kills it once it
// exhausts max_attempts (terminal dead state).
func (w *Worker) fail(ctx context.Context, job Job, cause error) error {
	msg := cause.Error()
	res, err := w.execRetry(ctx,
		`UPDATE jobs
		    SET status = 'dead', last_error = ?, claimed_by = NULL, claimed_at = NULL,
		        finished_at = UTC_TIMESTAMP(6)
		  WHERE id = ? AND attempts >= max_attempts`, msg, job.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		return nil // dead
	}
	next := w.now().Add(backoff(w.baseDelay, w.maxDelay, job.Attempts))
	_, err = w.execRetry(ctx,
		`UPDATE jobs
		    SET status = 'pending', run_at = ?, last_error = ?,
		        claimed_by = NULL, claimed_at = NULL
		  WHERE id = ? AND status = 'running'`, next, msg, job.ID)
	return err
}

// kill moves a job straight to dead (unhandled kind, poison payload).
func (w *Worker) kill(ctx context.Context, id, reason string) error {
	_, err := w.execRetry(ctx,
		`UPDATE jobs SET status = 'dead', last_error = ?, claimed_by = NULL,
		                    claimed_at = NULL, finished_at = UTC_TIMESTAMP(6)
		  WHERE id = ?`, reason, id)
	return err
}

// reapStale returns 'running' claims older than staleAfter to pending so a
// dead worker's jobs are retried instead of lost.
func (w *Worker) reapStale(ctx context.Context, log *slog.Logger) {
	cutoff := w.now().Add(-w.staleAfter)
	res, err := w.execRetry(ctx,
		`UPDATE jobs SET status = 'pending', claimed_by = NULL, claimed_at = NULL
		  WHERE status = 'running' AND claimed_at < ?`, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			log.Warn("stale-claim reaper failed", slog.String("error", err.Error()))
		}
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Info("requeued stale claims", slog.Int64("jobs", n))
	}
}

// releaseMine returns this worker's unfinished claims to pending on
// shutdown.
func (w *Worker) releaseMine(ctx context.Context) (int64, error) {
	res, err := w.execRetry(ctx,
		`UPDATE jobs SET status = 'pending', claimed_by = NULL, claimed_at = NULL
		  WHERE status = 'running' AND claimed_by = ?`, w.id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Counts reports job rows grouped by status — a convenience for operators
// and tests.
func (w *Worker) Counts(ctx context.Context) (map[string]int64, error) {
	rows, err := w.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM jobs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var status string
		var n int64
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		out[status] = n
	}
	return out, rows.Err()
}

// sleepCtx waits d or until ctx is done; false means ctx ended first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
