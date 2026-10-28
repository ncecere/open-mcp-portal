package httpapi_test

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"strings"
	"testing"
)

func TestServiceConnectionNeverFallbackForRelayedPerson(t *testing.T) {
	e, fx := newAgentEnv(t)
	c := connectShared(t, e.owner, e.provider.Id, "relay-shared")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{fx.account.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "relay assignment", code, ec, 200, "")
	_, out := fx.callTool("", f3Tool, nil)
	if !e.providerReport(out).Received {
		t.Fatal("genuine relay account could not use assigned shared connection")
	}
	for _, person := range []string{"user@localhost", "blair@localhost"} {
		code, out := fx.callTool(agentSpec{Email: person}, f3Tool, nil)
		text, isErr := toolText(t, out)
		if code != 200 || !isErr || !strings.Contains(text, "My connections") {
			t.Fatalf("relayed person fell back to shared: %v", out)
		}
		noLink(t, out, "relayed person without personal consent")
	}
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); n != "0" {
		t.Fatal("relayed service fallback created consent requests")
	}
	if n := e.toolCalls("provider_token"); n != 1 {
		t.Fatalf("upstream contacted %d times, want only the genuine service call", n)
	}
}
