// Command omp is the Open MCP Portal command line: connect snippets, server
// registration and publishing for CI, and declarative export and import
// (docs/cli.md). It authenticates with an automation token only.
package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/ncecere/open-mcp-portal/internal/buildinfo"
	"github.com/ncecere/open-mcp-portal/internal/ompcli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	app := ompcli.NewApp(buildinfo.Version, buildinfo.Commit)
	code := app.Run(ctx, os.Args[1:])
	stop()
	os.Exit(code)
}
