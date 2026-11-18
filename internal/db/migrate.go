package db

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/technofish-au/sp-portal/internal/config"
)

//go:embed migrations/*.sql
var embedded embed.FS

// Migrations returns the embedded goose SQL migrations (forward-only; the
// Down sections exist for developer convenience).
func Migrations() fs.FS {
	sub, err := fs.Sub(embedded, "migrations")
	if err != nil {
		panic(err) // the embed pattern guarantees the directory exists
	}
	return sub
}

// versionTable is goose's bookkeeping table.
const versionTable = "goose_db_version"

// MigrationStatus is one migration's state.
type MigrationStatus struct {
	Version   int64
	Name      string
	Applied   bool
	AppliedAt time.Time // zero if pending
}

// ErrNotMigrated means the database schema is older than this binary.
var ErrNotMigrated = errors.New("db: database schema is not up to date; run `sp-portal migrate`")

// Migrate applies all pending migrations and returns the resulting
// version. A MySQL table lock serialises concurrent runs.
func Migrate(ctx context.Context, cfg config.Config) (int64, error) {
	var version int64
	err := withProvider(ctx, cfg, func(p *goose.Provider) error {
		return migrateWith(ctx, p, &version)
	})
	return version, err
}

// Up is Migrate on an already-open pool (tests, tools).
func Up(ctx context.Context, sqlDB *sql.DB) (int64, error) {
	p, err := newProvider(sqlDB)
	if err != nil {
		return 0, err
	}
	var version int64
	return version, migrateWith(ctx, p, &version)
}

func migrateWith(ctx context.Context, p *goose.Provider, version *int64) error {
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("db: migrate: %w", err)
	}
	v, err := p.GetDBVersion(ctx)
	*version = v
	return err
}

// Status lists every embedded migration and whether it is applied.
func Status(ctx context.Context, cfg config.Config) ([]MigrationStatus, error) {
	var out []MigrationStatus
	err := withProvider(ctx, cfg, func(p *goose.Provider) error {
		st, err := p.Status(ctx)
		if err != nil {
			return fmt.Errorf("db: migration status: %w", err)
		}
		for _, s := range st {
			out = append(out, MigrationStatus{
				Version:   s.Source.Version,
				Name:      path.Base(s.Source.Path),
				Applied:   s.State == goose.StateApplied,
				AppliedAt: s.AppliedAt,
			})
		}
		return nil
	})
	return out, err
}

// CurrentVersion returns the applied schema version, or 0 for an empty
// database. Unlike Migrate and Status it never creates goose's tables.
func CurrentVersion(ctx context.Context, sqlDB *sql.DB) (int64, error) {
	var name string
	err := sqlDB.QueryRowContext(ctx,
		"SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
		versionTable).Scan(&name)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("db: check schema version: %w", err)
	}
	p, err := newProvider(sqlDB)
	if err != nil {
		return 0, err
	}
	v, err := p.GetDBVersion(ctx)
	if err != nil {
		return 0, fmt.Errorf("db: schema version: %w", err)
	}
	return v, nil
}

// ExpectedVersion is the highest embedded migration version, i.e. the
// schema version this binary needs.
func ExpectedVersion() int64 {
	entries, err := fs.ReadDir(Migrations(), ".")
	if err != nil {
		panic(err)
	}
	var maxVersion int64
	for _, e := range entries {
		v, err := goose.NumericComponent(e.Name())
		if err != nil {
			panic(fmt.Sprintf("db: bad migration file name %q: %v", e.Name(), err))
		}
		maxVersion = max(maxVersion, v)
	}
	return maxVersion
}

// CheckVersion returns ErrNotMigrated unless the database is at
// ExpectedVersion (serve refuses to start otherwise). A database that is
// newer than the binary is also an error.
func CheckVersion(ctx context.Context, sqlDB *sql.DB) error {
	current, err := CurrentVersion(ctx, sqlDB)
	if err != nil {
		return err
	}
	switch want := ExpectedVersion(); {
	case current < want:
		return fmt.Errorf("%w (database version %d, expected %d)", ErrNotMigrated, current, want)
	case current > want:
		return fmt.Errorf("db: database schema version %d is newer than this binary (%d); upgrade sp-portal", current, want)
	}
	return nil
}

func withProvider(ctx context.Context, cfg config.Config, fn func(*goose.Provider) error) error {
	sqlDB, err := Open(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()
	p, err := newProvider(sqlDB)
	if err != nil {
		return err
	}
	return fn(p)
}

func newProvider(sqlDB *sql.DB) (*goose.Provider, error) {
	locker, err := lock.NewMySQLTableLocker()
	if err != nil {
		return nil, fmt.Errorf("db: migration lock: %w", err)
	}
	p, err := goose.NewProvider(goose.DialectMySQL, sqlDB, Migrations(),
		goose.WithLocker(locker),
		goose.WithDisableGlobalRegistry(true),
	)
	if err != nil {
		return nil, fmt.Errorf("db: migrations: %w", err)
	}
	return p, nil
}
