// Package buildinfo exposes version metadata injected at link time.
package buildinfo

import "fmt"

// Set with -ldflags "-X github.com/ncecere/open-mcp-portal/internal/buildinfo.Version=..."
var (
	Version = "0.3.0"
	Commit  = "unknown"
)

func String() string { return fmt.Sprintf("open-mcp-portal %s (%s)", Version, Commit) }
