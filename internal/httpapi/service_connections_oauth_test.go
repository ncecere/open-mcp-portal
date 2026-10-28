package httpapi_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func serviceOAuthSetup(t *testing.T) (*upEnv, apitypes.McpServer, apitypes.ServiceAccount, string, apitypes.ServiceConnection) {
	t.Helper()
	e := newUpEnv(t, true)
	code, raw := e.createOAuth(e.owner, "shared-oauth", e.pm.URL(), map[string]any{"registration": "auto", "scopes": []string{"repo"}}, nil)
	if code != 201 {
		t.Fatalf("create oauth %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	sv := created.Data.Server
	_, to := e.setup(e.owner, sv.Id.String())
	if !strings.Contains(to, "setup=connected") {
		t.Fatalf("setup = %s", to)
	}
	sv = e.get(e.owner, sv.Id.String())
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "shared-oauth-gw")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(e.capID(e.owner, sv, "tool", "whoami"), e.capID(e.owner, sv, "tool", "write"), e.capID(e.owner, sv, "tool", "echo_secrets")))
	sa := createSA(t, e.owner, map[string]any{"name": "oauth-ci"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	c := connectShared(t, e.owner, sv.Oauth.ProviderId, "server-oauth")
	code, ec, c := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: sv.Id, Origin: registry.OriginOf(sv.Url), Scopes: []string{"repo"}}})
	mustCode(t, "server grant", code, ec, 200, "")
	return e, sv, sa, key, c
}
func TestServiceConnectionsServerBoundOAuthAnd401403(t *testing.T) {
	e, sv, _, key, c := serviceOAuthSetup(t)
	who := whoamiOf(t, e.call(key, "shared-oauth-gw", "shared-oauth__whoami", nil))
	if !who.Verified || who.Claims["principal_type"] != "service_account" {
		t.Fatalf("identity = %+v", who)
	}
	if !strings.HasPrefix(e.lastAuthorization("whoami"), "Bearer ") {
		t.Fatal("server-bound token not in Authorization")
	}
	before := e.as.RefreshRequests()
	e.as.InvalidateAll(false)
	if out := e.call(key, "shared-oauth-gw", "shared-oauth__whoami", nil); out["result"] == nil {
		t.Fatalf("401 retry = %v", out)
	}
	if got := e.as.RefreshRequests() - before; got != 1 {
		t.Fatalf("401 refreshed %d times", got)
	}
	// 403 never starts consent or silently widens either connection or grant.
	beforeStates := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`)
	serviceDenied(t, e.call(key, "shared-oauth-gw", "shared-oauth__write", nil), "insufficient_scope")
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests`); n != beforeStates {
		t.Fatal("service step-up stored personal consent")
	}
	// Echoed tokens are redacted from answers and captures with the same path
	// as personal credentials; this connection is explicitly shared, not public.
	code, ec, _ := e.patch(e.owner, sv.Id.String(), map[string]any{"capturePayloads": true})
	mustCode(t, "capture", code, ec, 200, "")
	echoed := e.call(key, "shared-oauth-gw", "shared-oauth__echo_secrets", nil)
	b, _ := json.Marshal(echoed)
	for _, token := range append(e.as.Issued(), e.as.IssuedRefresh()...) {
		if strings.Contains(string(b)+e.logs.String(), token) {
			t.Fatal("service token leaked into response/log")
		}
	}
	// A second 401 erases only the credential generation used for the retry.
	e.pm.SetProtection(func(p *testutil.Protection) {
		p.Introspect = func(_ context.Context, _ string) testutil.Introspection { return testutil.Introspection{} }
	})
	before = e.as.RefreshRequests()
	serviceDenied(t, e.call(key, "shared-oauth-gw", "shared-oauth__whoami", nil), "service_connection_needs_reconsent")
	if e.as.RefreshRequests() != before+1 {
		t.Fatal("second 401 retried more than once")
	}
	if x := e.scalar(`SELECT (access_token_cipher IS NULL AND refresh_token_cipher IS NULL)::text FROM service_connections WHERE id=$1`, c.Id); x != "true" {
		t.Fatal("second rejection retained ciphers")
	}
}
func TestServiceConnectionCallbackIssuerAndResource(t *testing.T) {
	for _, kind := range []string{"issuer", "resource", "session_revoked"} {
		t.Run(kind, func(t *testing.T) {
			e, sv, _, _, _ := serviceOAuthSetup(t)
			st := startShared(t, e.owner, sv.Oauth.ProviderId, "pending-"+kind)
			loc := providerAuthorize(t, e.owner, st.AuthorizeUrl)
			switch kind {
			case "issuer":
				u, _ := url.Parse(loc)
				v := u.Query()
				v.Set("iss", "https://wrong.example")
				u.RawQuery = v.Encode()
				loc = u.String()
			case "resource":
				e.scalar(`UPDATE auth_providers SET resource='https://changed.example/mcp',revision=revision+1 WHERE id=$1 RETURNING 'ok'`, sv.Oauth.ProviderId)
			case "session_revoked":
				code, ec := e.owner.call("POST", "/v1/me/sessions/revoke-all", map[string]any{"keepCurrent": false}, nil, nil)
				mustCode(t, "revoke browser", code, ec, 200, "")
			}
			if to := callback(t, e.owner, loc); strings.Contains(to, "result=connected") {
				t.Fatal("stale or mixed-up service callback connected")
			}
		})
	}
}
