// Package db owns the MariaDB connection pool, the DSN built from the
// resolved config (unix socket by default, TCP when db_host is set) and the
// embedded goose migrations.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/technofish-au/sp-portal/internal/config"
	"github.com/technofish-au/sp-portal/internal/secrets"
)

// DSN returns the go-sql-driver DSN for the config: unix socket transport
// by default, TCP (db_host:db_port) when configured. The password comes
// from ResolvePassword, never the DSN string the caller logs.
func DSN(cfg config.Config, password string) string {
	mcfg := mysql.NewConfig()
	mcfg.User = cfg.DBUser
	mcfg.Passwd = password
	mcfg.DBName = cfg.DBName
	if cfg.UseTCP() {
		mcfg.Net = "tcp"
		mcfg.Addr = cfg.DBAddr()
	} else {
		mcfg.Net = "unix"
		mcfg.Addr = cfg.DBSocket
	}
	mcfg.ParseTime = true // DATETIME(6) -> time.Time
	// goose runs migrations statement-by-statement but the locker's
	// heartbeat benefits; harmless elsewhere.
	mcfg.MultiStatements = true
	mcfg.Timeout = 10 * time.Second
	mcfg.Collation = "utf8mb4_unicode_ci"
	// UTC session so NOW()/UTC_TIMESTAMP semantics stay unambiguous.
	mcfg.Params = map[string]string{"time_zone": "'+00:00'"}
	return mcfg.FormatDSN()
}

// ResolvePassword returns the database password: the contents of
// db_password_file (mode 0400/0600 enforced) when set, else the inline
// db_password value.
func ResolvePassword(cfg config.Config) (string, error) {
	if cfg.DBPasswordFile != "" {
		pw, err := secrets.ReadString(cfg.DBPasswordFile)
		if err != nil {
			return "", fmt.Errorf("db: password file: %w", err)
		}
		return pw, nil
	}
	return cfg.DBPassword, nil
}

// Open returns a pinged connection pool for the config, honouring the
// pool-sizing options.
func Open(ctx context.Context, cfg config.Config) (*sql.DB, error) {
	password, err := ResolvePassword(cfg)
	if err != nil {
		return nil, err
	}
	sqlDB, err := sql.Open("mysql", DSN(cfg, password))
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.DBConnMaxLifetime)
	if err := sqlDB.PingContext(ctx); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("db: connect %s %s: %w", transport(cfg), cfg.DBAddr(), err)
	}
	return sqlDB, nil
}

// transport names the dial transport for logs ("unix" or "tcp").
func transport(cfg config.Config) string {
	if cfg.UseTCP() {
		return "tcp"
	}
	return "unix"
}
