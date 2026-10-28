package httpapi_test

import (
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/app"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionRefreshAcrossHandlers(t *testing.T) {
	var cfg config.Config
	e := newProvEnvHook(t, func(d *httpapi.Deps) { cfg = d.Config })
	sa := createSA(t, e.owner, map[string]any{"name": "refresh-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "refresh")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "assign", code, ec, 200, "")
	deps, err := app.NewDeps(cfg, e.app.Pool, testutil.Logger())
	if err != nil {
		t.Fatal(err)
	}
	replica := httptest.NewServer(httpapi.NewAPIHandler(deps))
	t.Cleanup(replica.Close)
	second := &testApp{URL: replica.URL, Pool: e.app.Pool}
	e.scalar(`UPDATE service_connections SET expires_at=now()+interval '10 seconds' WHERE id=$1 RETURNING 'ok'`, c.Id)
	old := e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 100 * time.Millisecond })
	before := e.oauth.RefreshRequests()
	results := make([]map[string]any, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := e.app
			if i%2 == 1 {
				target = second
			}
			_, _, results[i] = rawMCP(t, target, "POST", "support", key, rpc(i, "tools/call", map[string]any{"name": f3Tool}), nil)
		}(i)
	}
	wg.Wait()
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 0 })
	if got := e.oauth.RefreshRequests() - before; got != 1 {
		t.Fatalf("two handlers refreshed %d times", got)
	}
	for _, r := range results {
		if !e.providerReport(r).Received {
			t.Fatalf("refresh result = %v", r)
		}
	}
	if now := e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id); now == old {
		t.Fatal("rotated refresh token not committed")
	}
	// Each replica has its own narrowed-token cache, but every scoped refresh
	// shares the row lock and commits the rotating refresh token before use.
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=true WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true; f.RefreshDelay = 50 * time.Millisecond })
	before = e.oauth.RefreshRequests()
	results = make([]map[string]any, 8)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := e.app
			if i%2 == 1 {
				target = second
			}
			_, _, results[i] = rawMCP(t, target, "POST", "support", key, rpc(i, "tools/call", map[string]any{"name": f3Tool}), nil)
		}(i)
	}
	wg.Wait()
	for _, r := range results {
		if !e.providerReport(r).Received {
			t.Fatalf("concurrent narrowed refresh reused a rotated token: %v", r)
		}
	}
	if n := e.oauth.RefreshRequests() - before; n < 2 || n > 8 {
		t.Fatalf("narrowed refreshes across two replica caches: %d", n)
	}
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=false WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 0 })
	// Transient failure preserves both ciphers; a fatal failure erases both.
	e.scalar(`UPDATE service_connections SET expires_at=now() WHERE id=$1 RETURNING 'ok'`, c.Id)
	old = e.scalar(`SELECT encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "unavailable" })
	serviceDenied(t, e.callTool(key, f3Tool), "provider_unavailable")
	if status := e.scalar(`SELECT status||':'||encode(refresh_token_cipher,'hex') FROM service_connections WHERE id=$1`, c.Id); status != "active:"+old {
		t.Fatal("transient failure destroyed consent")
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "invalid_grant" })
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_needs_reconsent")
	if value := e.scalar(`SELECT (access_token_cipher IS NULL AND refresh_token_cipher IS NULL)::text FROM service_connections WHERE id=$1`, c.Id); value != "true" {
		t.Fatal("fatal refresh retained tokens")
	}
	if n := e.scalar(`SELECT count(*)::text FROM notification_events WHERE event='connection.needs_reconsent' AND subject_type='service_connection' AND recipient_user_id IS NULL`); n != "1" {
		t.Fatalf("shared reconsent notification count %s", n)
	}
}
func TestServiceConnectionNarrowingAndLiveCacheAuthorization(t *testing.T) {
	e := newProvEnv(t)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true })
	e.scalar(`UPDATE auth_providers SET narrow_on_refresh=true WHERE id=$1 RETURNING 'ok'`, e.provider.Id)
	sa := createSA(t, e.owner, map[string]any{"name": "narrow-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "narrow")
	grant := apitypes.ServiceConnectionGrant{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}
	code, ec, c := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{grant})
	mustCode(t, "assign", code, ec, 200, "")
	before := e.oauth.RefreshRequests()
	one := e.providerReport(e.callTool(key, f3Tool))
	e.scalar(`UPDATE service_connections SET last_used_at=now()-interval '2 hours' WHERE id=$1 RETURNING 'ok'`, c.Id)
	two := e.providerReport(e.callTool(key, f3Tool))
	if used := e.scalar(`SELECT (last_used_at>now()-interval '1 minute')::text FROM service_connections WHERE id=$1`, c.Id); used != "true" {
		t.Fatal("cached credential use did not update last_used_at")
	}

	if one.TokenSHA256 != two.TokenSHA256 || e.oauth.RefreshRequests() != before+1 {
		t.Fatal("narrow token not cached")
	}
	issued := e.oauth.Issued()
	if got := e.oauth.Introspect(issued[len(issued)-1]); len(got.Scopes) != 1 || got.Scopes[0] != "repo" {
		t.Fatalf("not narrowed: %+v", got)
	}
	// A warm cache never bypasses live grant and connector policy.
	e.scalar(`DELETE FROM service_connection_server_grants WHERE connection_id=$1 RETURNING 'ok'`, c.Id)
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_not_allowed")
	code, ec, c = assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{grant})
	mustCode(t, "restore grant", code, ec, 200, "")
	e.providerReport(e.callTool(key, f3Tool))
	if e.oauth.RefreshRequests() != before+2 {
		t.Fatal("new generation reused old cached token")
	}
	e.scalar(`UPDATE users SET status='suspended' WHERE id=(SELECT connected_by FROM service_connections WHERE id=$1) RETURNING 'ok'`, c.Id)
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_lapsed")
}
func TestServiceConnectionRefreshReducedScopesRefused(t *testing.T) {
	e := newProvEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "reduced-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, e.provider.Id, "reduced")
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
	mustCode(t, "assign", code, ec, 200, "")
	e.scalar(`UPDATE service_connections SET expires_at=now() WHERE id=$1 RETURNING 'ok'`, c.Id)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshGrantedScopes = []string{"read:user"} })
	serviceDenied(t, e.callTool(key, f3Tool), "service_connection_needs_reconsent")
	if n := e.toolCalls("provider_token"); n != 0 {
		t.Fatal("reduced-scope credential was forwarded")
	}
	if scopes := e.scalar(`SELECT array_to_string(scopes,',') FROM service_connections WHERE id=$1`, c.Id); !strings.Contains(scopes, "read:user") || strings.Contains(scopes, "repo") {
		t.Fatal("reduced scopes not saved")
	}
}
