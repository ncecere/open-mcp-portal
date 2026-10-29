package httpapi_test

import (
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
)

// disableTasks builds the handler as a portal without the task store: the
// extension is not advertised, never negotiated, and the task methods are
// unknown.
func disableTasks(d *httpapi.Deps) {
	d.MCP.(*mcpgw.Handler).Tasks = nil
}
