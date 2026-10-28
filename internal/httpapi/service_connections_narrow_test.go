package httpapi_test

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"strings"
	"testing"
)

func TestServiceConnectionInvalidScopeNeverFallsBack(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "no-fallback-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "no-fallback")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "assign", code, ec, 200, "")
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=true WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "invalid_scope" })
	serviceDenied(t, e.callTool(key, f3Tool), "provider_unavailable")
	if n := e.toolCalls("provider_token"); n != 0 {
		t.Fatal("invalid_scope fell back to stored full token")
	}
	if value := e.scalar(`SELECT (status='active' AND access_token_cipher IS NOT NULL AND refresh_token_cipher IS NOT NULL)::text FROM service_connections WHERE id=$1`, c.Id); value != "true" {
		t.Fatal("narrowing refusal destroyed base consent")
	}
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=false WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	if !e.providerReport(e.callTool(key, f3Tool)).Received {
		t.Fatal("explicit admin disabling narrowing did not restore ordinary token delivery")
	}
}
func TestServiceConnectionNarrowingUsesScopeSeparator(t *testing.T) {
	e := newProvEnv(t)
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo", "read:user"}})
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=true,scope_separator=',' WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true })
	sa := createSA(t, e.owner, map[string]any{"name": "comma-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "comma")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo", "read:user"}}})
	mustCode(t, "assign", code, ec, 200, "")
	if !e.providerReport(e.callTool(key, f3Tool)).Received {
		t.Fatal("comma-separated scoped refresh failed")
	}
	scopes := e.oauth.RefreshScopes()
	if len(scopes) != 1 || !strings.Contains(scopes[0], ",") || strings.Contains(scopes[0], " ") {
		t.Fatalf("scoped refresh ignored separator: %v", scopes)
	}
}
