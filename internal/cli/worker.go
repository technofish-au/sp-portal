package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/logging"
)

// registerHandlers installs every built-in job kind. Waves adding domains
// register their handlers here (and keep kind names stable — pending rows
// outlive the binary).
func registerHandlers(w *jobs.Worker) {
	// portal.ping is a trivial smoke-test job: it completes immediately so
	// operators can verify the queue end to end.
	w.Register("portal.ping", func(ctx context.Context, job jobs.Job) error { return nil })
}

// runWorker: config → DB pool + schema check → worker loop until ctx
// cancellation (graceful drain).
func runWorker(ctx context.Context, stderr io.Writer) int {
	cfg, err := loadPortalConfig()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal worker: %v\n", err)
		return ExitUsage
	}
	level, _ := logging.ParseLevel(cfg.LogLevel)
	logger := logging.New(stderr, level)

	sqlDB, err := openSchemaPool(ctx, cfg)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return ExitError
	}
	defer func() { _ = sqlDB.Close() }()

	w := jobs.NewWorker(sqlDB,
		jobs.WithLogger(logger),
		jobs.WithInterval(cfg.WorkerInterval),
		jobs.WithBatchSize(cfg.WorkerBatchSize),
		jobs.WithStaleAfter(cfg.WorkerStaleTimeout),
	)
	registerHandlers(w)
	if err := w.Run(ctx); err != nil {
		logger.Error("worker failed", "error", err.Error())
		return ExitError
	}
	return ExitOK
}
