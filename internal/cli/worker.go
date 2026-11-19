package cli

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"

	"github.com/technofish-au/sp-portal/internal/billing"
	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/jobs"
	"github.com/technofish-au/sp-portal/internal/logging"
	"github.com/technofish-au/sp-portal/internal/mailer"
)

// registerHandlers installs every built-in job kind. Waves adding domains
// register their handlers here (and keep kind names stable — pending rows
// outlive the binary).
func registerHandlers(w *jobs.Worker, cfg config.Config, sqlDB *sql.DB, ml mailer.Mailer, logger *slog.Logger) {
	// portal.ping is a trivial smoke-test job: it completes immediately so
	// operators can verify the queue end to end.
	w.Register("portal.ping", func(ctx context.Context, job jobs.Job) error { return nil })

	w.Register(mailer.KindSend, mailer.SendJobHandler(ml))

	bill := billingDeps(cfg, sqlDB, logger)
	w.Register(billing.KindStripeEvent, bill.StripeEventHandler())
	w.Register(billing.KindSuspendSweep, bill.SuspendSweepHandler())
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

	ml, err := mailer.New(cfg, logger)
	if err != nil {
		logger.Error("startup failed", "error", err.Error())
		return ExitError
	}

	w := jobs.NewWorker(sqlDB,
		jobs.WithLogger(logger),
		jobs.WithInterval(cfg.WorkerInterval),
		jobs.WithBatchSize(cfg.WorkerBatchSize),
		jobs.WithStaleAfter(cfg.WorkerStaleTimeout),
	)
	registerHandlers(w, cfg, sqlDB, ml, logger)
	if err := billingDeps(cfg, sqlDB, logger).SeedSweep(ctx); err != nil {
		logger.Warn("suspend-sweep seed failed", "error", err.Error())
	}
	if err := w.Run(ctx); err != nil {
		logger.Error("worker failed", "error", err.Error())
		return ExitError
	}
	return ExitOK
}
