package jobs_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/testutil"
)

// TestWorkerConcurrentExactlyOnce is the R5-1 acceptance test: 1000 jobs
// processed by two concurrent worker replicas against one MariaDB. Every
// job must be processed exactly once (SKIP LOCKED claim) and none may land
// in dead.
func TestWorkerConcurrentExactlyOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("acceptance test needs a real MariaDB")
	}
	sqlDB := testutil.MariaDB(t)
	ctx := context.Background()

	// Results sink: the PK on job_id makes any double-processing a hard
	// error (which would surface as a dead job, also asserted).
	if _, err := sqlDB.ExecContext(ctx, `
		CREATE TABLE job_results (
			job_id      CHAR(36)    NOT NULL PRIMARY KEY,
			worker_id   VARCHAR(64) NOT NULL,
			processed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
		)`); err != nil {
		t.Fatalf("create results table: %v", err)
	}

	const total = 1000
	queue := jobs.NewQueue(sqlDB)
	for i := 0; i < total; i++ {
		if _, err := queue.Enqueue(ctx, "test.record", map[string]int{"i": i}); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}

	logger := slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	newWorker := func(name string) *jobs.Worker {
		w := jobs.NewWorker(sqlDB,
			jobs.WithLogger(logger.With(slog.String("worker", name))),
			jobs.WithInterval(10*time.Millisecond),
			jobs.WithBatchSize(64),
			jobs.WithStaleAfter(5*time.Minute),
		)
		w.Register("test.record", func(ctx context.Context, job jobs.Job) error {
			_, err := sqlDB.ExecContext(ctx,
				`INSERT INTO job_results (job_id, worker_id) VALUES (?, ?)`, job.ID, name)
			return err
		})
		return w
	}

	wctx, stopWorkers := context.WithCancel(ctx)
	done := make(chan error, 2)
	go func() { done <- newWorker("replica-1").Run(wctx) }()
	go func() { done <- newWorker("replica-2").Run(wctx) }()
	// Stop the workers before testutil's cleanup closes the pool even when
	// an assertion below calls t.Fatalf (cleanups run LIFO).
	var workerErrs []error
	stopAll := sync.OnceFunc(func() {
		stopWorkers()
		for i := 0; i < 2; i++ {
			workerErrs = append(workerErrs, <-done)
		}
	})
	t.Cleanup(stopAll)

	// Wait for all jobs to reach a terminal state.
	deadline := time.Now().Add(120 * time.Second)
	for {
		var finished int
		if err := sqlDB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM jobs WHERE status IN ('done','dead')`).Scan(&finished); err != nil {
			t.Fatalf("count finished: %v", err)
		}
		if finished == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %d/%d jobs finished", finished, total)
		}
		time.Sleep(100 * time.Millisecond)
	}
	stopAll()
	if err := errors.Join(workerErrs...); err != nil {
		t.Fatalf("worker returned error: %v", err)
	}

	var processed, distinct, dead int
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*), COUNT(DISTINCT job_id) FROM job_results`).Scan(&processed, &distinct); err != nil {
		t.Fatalf("count results: %v", err)
	}
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM jobs WHERE status = 'dead'`).Scan(&dead); err != nil {
		t.Fatalf("count dead: %v", err)
	}
	if processed != total || distinct != total {
		t.Fatalf("processed=%d distinct=%d, want exactly %d each", processed, distinct, total)
	}
	if dead != 0 {
		t.Fatalf("%d jobs landed in dead", dead)
	}
}

// TestWorkerRetryAndDead covers the failure path on a real database: a
// flaky handler retries with backoff, an always-failing handler exhausts
// max_attempts into dead.
func TestWorkerRetryAndDead(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a real MariaDB")
	}
	sqlDB := testutil.MariaDB(t)
	ctx := context.Background()
	queue := jobs.NewQueue(sqlDB)

	flakyID, err := queue.Enqueue(ctx, "test.flaky", nil)
	if err != nil {
		t.Fatal(err)
	}
	badID, err := queue.Enqueue(ctx, "test.bad", nil, jobs.WithMaxAttempts(2))
	if err != nil {
		t.Fatal(err)
	}
	// Dedupe: re-enqueueing the key returns the same id, no second row.
	a, err := queue.Enqueue(ctx, "test.once", nil, jobs.WithDedupeKey("k1"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := queue.Enqueue(ctx, "test.once", nil, jobs.WithDedupeKey("k1"))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("dedupe returned different ids %q vs %q", a, b)
	}

	attempts := 0
	w := jobs.NewWorker(sqlDB,
		jobs.WithLogger(slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))),
		jobs.WithInterval(10*time.Millisecond), jobs.WithBatchSize(8),
		jobs.WithBackoff(10*time.Millisecond, 50*time.Millisecond))
	w.Register("test.flaky", func(ctx context.Context, job jobs.Job) error {
		attempts++
		if attempts < 3 {
			return fmt.Errorf("transient %d", attempts)
		}
		return nil
	})
	w.Register("test.bad", func(ctx context.Context, job jobs.Job) error {
		return fmt.Errorf("always fails")
	})
	w.Register("test.once", func(ctx context.Context, job jobs.Job) error { return nil })

	wctx, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- w.Run(wctx) }()
	var runErr error
	stopAll := sync.OnceFunc(func() { stop(); runErr = <-done })
	t.Cleanup(stopAll)

	deadline := time.Now().Add(60 * time.Second)
	for {
		var doneCount, deadCount int
		_ = sqlDB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM jobs WHERE status = 'done'`).Scan(&doneCount)
		_ = sqlDB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM jobs WHERE status = 'dead'`).Scan(&deadCount)
		if doneCount == 2 && deadCount == 1 {
			break
		}
		if time.Now().After(deadline) {
			rows, _ := sqlDB.QueryContext(ctx,
				`SELECT id, kind, status, attempts, run_at, claimed_by, UTC_TIMESTAMP(6) FROM jobs`)
			if rows != nil {
				for rows.Next() {
					var id, kind, status, claimedBy, runAt, now string
					var att int
					_ = rows.Scan(&id, &kind, &status, &att, &runAt, &claimedBy, &now)
					t.Logf("job %s kind=%s status=%s attempts=%d run_at=%s claimed_by=%s db_now=%s",
						id, kind, status, att, runAt, claimedBy, now)
				}
				_ = rows.Close()
			}
			t.Fatalf("timed out: done=%d dead=%d (want 2/1)", doneCount, deadCount)
		}
		time.Sleep(50 * time.Millisecond)
	}
	stopAll()
	if runErr != nil {
		t.Fatalf("worker: %v", runErr)
	}
	if attempts < 3 {
		t.Fatalf("flaky handler attempts = %d, want >= 3", attempts)
	}
	var id string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT id FROM jobs WHERE status = 'dead'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id != badID {
		t.Fatalf("dead job = %q, want %q", id, badID)
	}
	var flakyStatus string
	if err := sqlDB.QueryRowContext(ctx,
		`SELECT status FROM jobs WHERE id = ?`, flakyID).Scan(&flakyStatus); err != nil {
		t.Fatal(err)
	}
	if flakyStatus != "done" {
		t.Fatalf("flaky job status = %q", flakyStatus)
	}
}

type testWriter struct{ t *testing.T }

func (tw testWriter) Write(p []byte) (int, error) {
	tw.t.Log(string(p))
	return len(p), nil
}
