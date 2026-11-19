package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/db"
	"github.com/technofish-au/sp-portal/internal/httpapi"
	"github.com/technofish-au/sp-portal/internal/licensing"
	"github.com/technofish-au/sp-portal/internal/logging"
	"github.com/technofish-au/sp-portal/internal/secrets"
	"github.com/technofish-au/sp-portal/internal/storage"
	"github.com/technofish-au/sp-portal/internal/version"
)

// shutdownTimeout bounds graceful shutdown of in-flight requests.
const shutdownTimeout = 15 * time.Second

// loadConfig is swapped in tests.
var loadConfig = config.LoadFromOS

// loadPortalConfig resolves config and reports errors with the command
// prefix; used by serve, worker and migrate.
func loadPortalConfig() (config.Config, error) {
	return loadConfig()
}

// openSchemaPool opens the pool and enforces the schema version: serve and
// worker refuse to start on an unmigrated (or newer) database.
func openSchemaPool(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	sqlDB, err := db.Open(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := db.CheckVersion(ctx, sqlDB); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return sqlDB, nil
}

// runServe: config → storage layout → DB pool + schema check → chi router
// → listen, with graceful shutdown on ctx cancel.
func runServe(ctx context.Context, stderr io.Writer) int {
	cfg, err := loadPortalConfig()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal serve: %v\n", err)
		return ExitUsage
	}
	level, _ := logging.ParseLevel(cfg.LogLevel) // validated by config.Load
	logger := logging.New(stderr, level)

	if _, err := storage.Ensure(cfg.StorageDir); err != nil {
		logger.Error("startup failed", slog.String("error", err.Error()))
		return ExitError
	}
	sqlDB, err := openSchemaPool(ctx, cfg)
	if err != nil {
		logger.Error("startup failed", slog.String("error", err.Error()))
		return ExitError
	}
	defer func() { _ = sqlDB.Close() }()

	deps, err := buildDeps(cfg, sqlDB, logger)
	if err != nil {
		logger.Error("startup failed", slog.String("error", err.Error()))
		return ExitError
	}
	handler := httpapi.NewRouter(deps)
	if err := serve(ctx, logger, cfg.HTTPAddr, handler); err != nil {
		logger.Error("server failed", slog.String("error", err.Error()))
		return ExitError
	}
	return ExitOK
}

// licenceIssuer resolves the licence-document signing key: the configured
// file-mounted key, or — only when no key file is configured — the
// embedded DEV-ONLY issuer (with a loud warning). An explicitly
// configured key that is unreadable or invalid fails startup: silently
// signing production licences with a public key would be worse.
func licenceIssuer(cfg config.Config, logger *slog.Logger) (*licensing.Issuer, error) {
	if cfg.LicenceSigningKeyFile == "" {
		issuer, err := licensing.DevIssuer()
		if err != nil {
			return nil, err
		}
		logger.Warn("licence_signing_key_file unset; using embedded DEV issuer key — never for production",
			slog.String("kid", issuer.KID()))
		return issuer, nil
	}
	contents, err := secrets.ReadString(cfg.LicenceSigningKeyFile)
	if err != nil {
		return nil, fmt.Errorf("licence signing key: %w", err)
	}
	issuer, err := licensing.LoadIssuer(cfg.LicenceIssuerKID, contents)
	if err != nil {
		return nil, fmt.Errorf("licence signing key: %w", err)
	}
	return issuer, nil
}

// serve runs the HTTP server until ctx is cancelled, then shuts it down
// gracefully. It returns nil after a clean shutdown.
func serve(ctx context.Context, logger *slog.Logger, addr string, handler http.Handler) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
		BaseContext:       func(net.Listener) context.Context { return context.WithoutCancel(ctx) },
	}

	info := version.Get()
	logger.Info("sp-portal listening",
		slog.String("addr", ln.Addr().String()),
		slog.String("version", info.Version),
		slog.String("commit", info.Commit),
	)

	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		// Serve only returns on failure here (Shutdown hasn't been called).
		return fmt.Errorf("serve: %w", err)
	case <-ctx.Done():
	}

	logger.Info("shutting down", slog.Duration("timeout", shutdownTimeout))
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve: %w", err)
	}
	return nil
}
