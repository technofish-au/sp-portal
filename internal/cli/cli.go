// Package cli implements the sp-portal command line: subcommand dispatch
// with injectable args/stdout/stderr and exit codes, so it can be tested
// without spawning processes.
//
// Exit codes: 0 success, 1 runtime failure, 2 usage error.
package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/technofish-au/sp-portal/internal/version"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitError = 1
	ExitUsage = 2
)

const usage = `Usage: sp-portal <command> [arguments]

Commands:
  serve          Run the HTTP server (MariaDB + migrated schema required;
                 PORTAL_HTTP_ADDR default :8080)
  worker         Run the background job worker (same DB requirements)
  migrate [up|status]
                 Apply database migrations (default: up) or show their status
  admin create --email EMAIL [--display-name NAME]
                 Create a staff (is_platform_admin) user; prints the generated
                 password once
  healthcheck    GET http://127.0.0.1:<port>/healthz; exit 0 if healthy, 1 otherwise
  version        Print version information
  help           Show this help

Configuration: /etc/sp-portal/portal.yaml (PORTAL_CONFIG_FILE) plus PORTAL_*
environment variables; see internal/config for the key list.
`

// Run executes the command in args (without the program name) and returns
// the process exit code. ctx cancellation stops long-running commands
// (serve, worker) gracefully.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return ExitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return ExitOK
	case "version", "--version":
		_, _ = fmt.Fprintf(stdout, "sp-portal %s\n", version.Get())
		return ExitOK
	case "serve":
		return runServe(ctx, stderr)
	case "worker":
		return runWorker(ctx, stderr)
	case "migrate":
		return runMigrate(ctx, rest, stdout, stderr)
	case "admin":
		return runAdmin(ctx, rest, stdout, stderr)
	case "healthcheck":
		return runHealthcheck(ctx, stderr)
	default:
		_, _ = fmt.Fprintf(stderr, "sp-portal: unknown command %q\n\n%s", cmd, usage)
		return ExitUsage
	}
}
