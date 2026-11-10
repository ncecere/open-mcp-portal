package httpapi_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// TestServiceConnectionRefusalPrecedence pins which refusal a service call
// gets when several apply: each step breaks an earlier check while every
// later one stays broken, and the earlier check's refusal must win.
func TestServiceConnectionRefusalPrecedence(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "precedence-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "precedence")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "assign", code, ec, 200, "")
	if !e.providerReport(e.callTool(key, f3Tool)).Received {
		t.Fatal("assigned connection refused")
	}
	for _, step := range []struct{ name, sql, want string }{
		{"grant origin", `UPDATE service_connection_server_grants SET origin='https://elsewhere.example' WHERE connection_id=$1 RETURNING 'ok'`, "service_connection_not_allowed"},
		{"consent", `UPDATE service_connections SET status='needs_reconsent' WHERE id=$1 RETURNING 'ok'`, "service_connection_needs_reconsent"},
		{"connector", `UPDATE service_connections SET connected_by=NULL WHERE id=$1 RETURNING 'ok'`, "service_connection_lapsed"},
		{"assignment", `DELETE FROM service_connection_accounts WHERE connection_id=$1 RETURNING 'ok'`, "service_connection_missing"},
		{"provider", `UPDATE auth_providers SET enabled=false WHERE id=(SELECT provider_id FROM service_connections WHERE id=$1) RETURNING 'ok'`, "provider_disabled"},
	} {
		e.scalar(step.sql, c.Id)
		out := e.callTool(key, f3Tool)
		if _, _, data := rpcErr(out); data["reason"] != step.want {
			t.Fatalf("after breaking %s: want %s, got %v", step.name, step.want, out)
		}
		serviceDenied(t, out, step.want)
	}
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); n != "0" {
		t.Fatal("a refused service call created personal consent")
	}
}
