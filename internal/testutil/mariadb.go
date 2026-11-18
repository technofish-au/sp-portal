// Package testutil provides a real MariaDB for integration tests: the
// SP_PORTAL_TEST_DSN environment variable when set, otherwise a throwaway
// docker container. Tests skip when neither is available.
package testutil

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/technofish-au/sp-portal/internal/db"
)

// MariaDBImage is the container image used for throwaway databases
// (must satisfy the project's MariaDB >= 10.6 requirement).
const MariaDBImage = "mariadb:11.4"

// EnvDSN names the variable holding a go-sql-driver DSN of an existing
// test database (e.g. the compose MariaDB during `make acceptance`).
const EnvDSN = "SP_PORTAL_TEST_DSN"

// MariaDB returns a migrated database pool. With EnvDSN set it uses that
// database; otherwise it starts a throwaway MariaDB container (requires
// docker on PATH) and removes it when the test ends. The test is skipped
// when neither works.
func MariaDB(t *testing.T) *sql.DB {
	t.Helper()
	var sqlDB *sql.DB
	if dsn := os.Getenv(EnvDSN); dsn != "" {
		var err error
		sqlDB, err = sql.Open("mysql", dsn)
		if err != nil {
			t.Fatalf("open %s: %v", EnvDSN, err)
		}
		waitPing(t, sqlDB, 30*time.Second)
	} else {
		sqlDB = startContainer(t)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := db.Up(ctx, sqlDB); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	return sqlDB
}

// startContainer runs a throwaway MariaDB on a random localhost port and
// returns a connected pool once it accepts queries.
func startContainer(t *testing.T) *sql.DB {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("no %s and no docker: %v", EnvDSN, err)
	}
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"-e", "MARIADB_ROOT_PASSWORD=root",
		"-e", "MARIADB_DATABASE=portal_test",
		"-e", "MARIADB_USER=portal",
		"-e", "MARIADB_PASSWORD=portal-test",
		"-p", "127.0.0.1::3306",
		MariaDBImage).Output()
	if err != nil {
		t.Skipf("docker run %s: %v", MariaDBImage, err)
	}
	cid := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", cid).Run()
	})
	portOut, err := exec.Command("docker", "port", cid, "3306/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	// "127.0.0.1:49153" (possibly several lines; first wins).
	hostport := strings.TrimSpace(strings.SplitN(string(portOut), "\n", 2)[0])
	dsn := fmt.Sprintf("portal:portal-test@tcp(%s)/portal_test?parseTime=true&multiStatements=true&timeout=10s", hostport)
	sqlDB, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open test dsn: %v", err)
	}
	waitPing(t, sqlDB, 120*time.Second)
	// Bound the pool so concurrent workers can't exhaust the container's
	// max_connections (MariaDB default 151).
	sqlDB.SetMaxOpenConns(64)
	return sqlDB
}

// waitPing polls Ping until the database answers or the deadline passes;
// it also verifies raw TCP connectivity first so driver-level errors
// surface quickly.
func waitPing(t *testing.T, sqlDB *sql.DB, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		last = sqlDB.PingContext(ctx)
		cancel()
		if last == nil {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("database did not become ready in %s: %v", timeout, last)
}
