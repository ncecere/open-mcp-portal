package httpapi_test

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"testing"
)

func TestServiceConnectionPublishedDestinationTeamAccess(t *testing.T) {
	e := newProvEnv(t)
	path := "/v1/teams/other/mcp-servers/" + e.other.Id.String()
	var sv apitypes.McpServer
	code, ec := e.outsider.call("PATCH", path, map[string]any{"requirement": map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}}}, &sv, ifMatch(e.other.Revision))
	mustCode(t, "foreign requirement", code, ec, 200, "")
	e.publish(e.outsider, sv)
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(e.capID(e.owner, e.server, "tool", "provider_token"), e.capID(e.outsider, sv, "tool", "provider_token")))
	sa := createSA(t, e.owner, map[string]any{"name": "published-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "cross-team")
	code, ec, c = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, nil)
	mustCode(t, "assign", code, ec, 200, "")
	serviceDenied(t, e.callTool(key, "other-status__provider_token"), "service_connection_not_allowed")
	// The connection belongs to tools, but the allowed provider team must be
	// the destination's other team, not tools.
	otherTeam := e.scalar(`SELECT id::text FROM teams WHERE slug='other'`)
	e.provider = e.setAccess(e.provider, "restricted", []string{otherTeam}, nil)
	code, ec, _ = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: sv.Id, Origin: registry.OriginOf(sv.Url), Scopes: []string{"repo"}}})
	mustCode(t, "explicit published grant", code, ec, 200, "")
	if !e.providerReport(e.callTool(key, "other-status__provider_token")).Received {
		t.Fatal("published destination did not receive shared token")
	}
	serviceDenied(t, e.callTool(key, f3Tool), "provider_not_allowed")
	ownTeam := e.scalar(`SELECT id::text FROM teams WHERE slug='tools'`)
	e.provider = e.setAccess(e.provider, "restricted", []string{ownTeam}, nil)
	serviceDenied(t, e.callTool(key, "other-status__provider_token"), "provider_not_allowed")
}
