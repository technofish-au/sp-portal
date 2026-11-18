// Command sp-portal is the ServerPerch customer portal: admin/customer API,
// embedded web UI and the background job worker in one binary. See
// internal/cli for the subcommands.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/technofish-au/sp-portal/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
