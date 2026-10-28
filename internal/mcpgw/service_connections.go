package mcpgw

import (
	"fmt"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func (rc *request) serviceCallContext(o gateways.Offer) providers.ServiceCallContext {
	return providers.ServiceCallContext{Account: rc.principal.account.Account, Team: rc.principal.account.Team, ServerID: o.Server.ID, ServerOrigin: registry.OriginOf(o.Server.URL), ServerURL: o.Server.URL}
}
func (rc *request) serviceConnectionDenied(o gateways.Offer, e *providers.ServiceCredentialError, rec *calls.Call) {
	msg := fmt.Sprintf("%s requires an allowed, active shared %s connection. Ask your team's owner or admin to review Service accounts > Connections.", o.ExposedName, o.Requires.Provider.Name)
	n := rc.failData(codeDenied, msg, map[string]any{"reason": e.Reason, "provider": o.Requires.Provider.Slug})
	rec.Outcome, rec.ErrorClass = calls.OutcomeDenied, e.Reason
	rc.record(*rec, n)
}
