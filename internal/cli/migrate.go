package cli

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/db"
)

// runMigrate implements `sp-portal migrate [up|status]` (up is the
// default). It applies the embedded goose migrations over the configured
// MariaDB connection (unix socket or TCP).
func runMigrate(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	sub := "up"
	if len(args) > 0 {
		sub = args[0]
	}
	if len(args) > 1 || (sub != "up" && sub != "status") {
		_, _ = fmt.Fprintf(stderr, "sp-portal migrate: usage: sp-portal migrate [up|status]\n")
		return ExitUsage
	}
	cfg, err := loadPortalConfig()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal migrate: %v\n", err)
		return ExitUsage
	}
	if sub == "status" {
		err = migrateStatus(ctx, cfg, stdout)
	} else {
		err = migrateUp(ctx, cfg, stdout)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "sp-portal migrate %s: %v\n", sub, err)
		return ExitError
	}
	return ExitOK
}

func migrateUp(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	sqlDB, err := db.Open(ctx, cfg)
	if err != nil {
		return err
	}
	before, err := db.CurrentVersion(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		return err
	}
	after, err := db.Migrate(ctx, cfg)
	if err != nil {
		return err
	}
	if after == before {
		_, _ = fmt.Fprintf(stdout, "database schema is up to date (version %d)\n", after)
		return nil
	}
	_, _ = fmt.Fprintf(stdout, "migrated database schema from version %d to %d\n", before, after)
	return nil
}

func migrateStatus(ctx context.Context, cfg config.Config, stdout io.Writer) error {
	st, err := db.Status(ctx, cfg)
	if err != nil {
		return err
	}
	sqlDB, err := db.Open(ctx, cfg)
	if err != nil {
		return err
	}
	current, err := db.CurrentVersion(ctx, sqlDB)
	_ = sqlDB.Close()
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "VERSION\tMIGRATION\tSTATE\tAPPLIED AT")
	for _, s := range st {
		state, at := "pending", "-"
		if s.Applied {
			state, at = "applied", s.AppliedAt.UTC().Format(time.RFC3339)
		}
		_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", s.Version, s.Name, state, at)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "current version %d, expected %d\n", current, db.ExpectedVersion())
	return nil
}
