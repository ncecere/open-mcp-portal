package httpapi_test

import (
	"context"
	"net/url"
	"testing"
)

func TestCredentialToolScopesCorruptAccountAndKey(t *testing.T) {
	e := scopedRuntime(t)
	sa := createSA(t, e.owner, map[string]any{"name": "corrupt"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "corrupt"})
	for _, table := range []string{"service_accounts", "service_account_keys"} {
		id := sa.Id
		if table == "service_account_keys" {
			id = key.Key.Id
		}
		if _, err := e.app.Pool.Exec(context.Background(), "UPDATE "+table+" SET tool_scope='[\"read\"]' WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
		wantScopedList(t, e, false, "support", key.Secret)
		wantScopeDenied(t, e, true, "support", key.Secret, "status__whoami")
		if _, err := e.app.Pool.Exec(context.Background(), "UPDATE "+table+" SET tool_scope=NULL WHERE id=$1", id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope='{"classes":["admin"]}' WHERE id=$1`, e.grant); err != nil {
		t.Fatal(err)
	}
	wantScopedList(t, e, false, "shared", e.key.Secret)
	wantScopeDenied(t, e, true, "shared", e.key.Secret, "status__whoami")
}

func TestOAuthToolScopesCorruptStoredNamesFailClosed(t *testing.T) {
	e := scopedOAuthEnv(t)
	p := newPKCE()
	client := e.docs.client("/corrupt-scopes.json", "Corrupt", testRedirect)
	q := authQuery(e.app, client, "support", p, map[string]string{"scope": "omp:read"})
	loc := scopeConsent(t, e.member, q, nil, false)
	status, tokens := scopeExchange(t, e, client, codeFrom(t, e.app, "first", loc), p)
	if status != 200 {
		t.Fatal(tokens)
	}
	// Names are valid in the shared ToolScope shape but invalid for OAuth.
	// A corrupt grant must not advertise deny-all while still allowing names.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE oauth_grants SET tool_scope='{"tools":["status__echo"]}' WHERE client_id=$1`, client); err != nil {
		t.Fatal(err)
	}
	access := tokens["access_token"].(string)
	wantScopedList(t, e.rtEnv, false, "support", access)
	wantScopeDenied(t, e.rtEnv, true, "support", access, "status__echo")
	status, refreshed, _ := tokenCall(t, e.app, "/oauth/token", url.Values{"grant_type": {"refresh_token"}, "client_id": {client}, "refresh_token": {tokens["refresh_token"].(string)}})
	if status != 200 {
		t.Fatal(refreshed)
	}
	wantTokenScope(t, refreshed, "", true)
	wantScopedList(t, e.rtEnv, true, "support", refreshed["access_token"].(string))
}
