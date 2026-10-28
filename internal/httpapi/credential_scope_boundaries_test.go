package httpapi_test

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestCredentialToolScopesRelayedGrantIntersections(t *testing.T) {
	e := scopedRuntime(t)
	fx := setupRelay(t, e.gwEnv)
	code, ec := e.owner.call("DELETE", toolsTeam+"/members/"+e.userID("blair@localhost"), nil, nil, nil)
	mustCode(t, "remove person's team access", code, ec, 200, "")
	code, ec = e.admin.call("DELETE", e.shared+"/grants/"+e.grant, nil, nil, nil)
	mustCode(t, "remove initial", code, ec, 200, "")
	for _, body := range []map[string]any{
		{"subjectKind": "team", "team": "tools", "toolScope": classScope("read")},
		{"subjectKind": "user", "userEmail": "blair@localhost", "toolScope": nameScope("status__whoami", "status__check_outage")},
		{"subjectKind": "group", "group": "scope-person", "toolScope": classScope("write")},
	} {
		code, ec = e.admin.call("POST", e.shared+"/grants", body, nil, nil)
		mustCode(t, "scoped grant", code, ec, 201, "")
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET groups=ARRAY['scope-person'] WHERE email='blair@localhost'`); err != nil {
		t.Fatal(err)
	}
	patchSA(t, e.owner, fx.account.Id.String(), map[string]any{"toolScope": nameScope("status__whoami", "status__echo")})
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE service_account_keys SET tool_scope='{"tools":["status__whoami","status__echo"]}' WHERE service_account_id=$1`, fx.account.Id); err != nil {
		t.Fatal(err)
	}
	// A real personal credential is not part of an agent's request. Even an
	// existing deny-all personal key must not be grafted onto the relay.
	scopedKey(t, e.member, map[string]any{})
	person := agentSpec{Email: "blair@localhost", Mutate: func(c map[string]any) {
		c["tool_scope"] = map[string]any{"classes": []string{"read", "write", "destructive"}}
	}}
	list := func(want ...string) {
		t.Helper()
		status, out := fx.post(fx.key, fx.token(person), "shared", rpc(1, "tools/list", nil))
		if status != 200 {
			t.Fatal(out)
		}
		names := []string{}
		for _, v := range resultOf(t, out)["tools"].([]any) {
			names = append(names, v.(map[string]any)["name"].(string))
		}
		slices.Sort(want)
		if !slices.Equal(names, want) {
			t.Fatalf("relay scope list=%v want %v", names, want)
		}
	}
	deny := func(name string) {
		t.Helper()
		n := e.fake.Requests()
		status, out := fx.post(fx.key, fx.toolToken(person, name), "shared", rpc(2, "tools/call", toolCall(name, nil)))
		if status != 200 || rpcErrorCode(out) != -32602 || e.fake.Requests() != n {
			t.Fatalf("relay scope refusal=%d %v", status, out)
		}
		if got := e.scalar(`SELECT outcome||':'||coalesce(error_class,'') FROM mcp_calls WHERE method='tools/call' ORDER BY id DESC LIMIT 1`); got != "denied:tool_scope" {
			t.Fatal(got)
		}
	}
	list("status__whoami")
	deny("status__echo")
	deny("status__check_outage")
	// Widening just the relay's team grant cannot bypass its account/key layers.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope='{"classes":["write"]}' WHERE gateway_id=(SELECT id FROM gateways WHERE slug='shared') AND subject_kind='team'`); err != nil {
		t.Fatal(err)
	}
	list("status__echo")
	deny("status__whoami")
	patchSA(t, e.owner, fx.account.Id.String(), map[string]any{"toolScope": classScope("read")})
	list()
	deny("status__echo")
	patchSA(t, e.owner, fx.account.Id.String(), map[string]any{"toolScope": nil})
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE service_account_keys SET tool_scope='{}' WHERE service_account_id=$1`, fx.account.Id); err != nil {
		t.Fatal(err)
	}
	list()
	deny("status__echo")
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE service_account_keys SET tool_scope=NULL WHERE service_account_id=$1`, fx.account.Id); err != nil {
		t.Fatal(err)
	}
	list("status__echo")
}

func TestCredentialToolScopesRefuseBeforeConsentAndRetry(t *testing.T) {
	e := newProvEnv(t)
	k := scopedKey(t, e.member, map[string]any{})
	for _, modern := range []bool{false, true} {
		n := e.fake.Requests()
		before := e.connectRequests()
		var out map[string]any
		if modern {
			_, _, out = rawModern(t, e.app, "support", k.Secret, "tools/call", toolCall("status__provider_token", nil), urlCaps, nil)
		} else {
			_, _, out = rawMCP(t, e.app, "POST", "support", k.Secret, rpc(1, "tools/call", toolCall("status__provider_token", nil)), nil)
		}
		if rpcErrorCode(out) != -32602 {
			t.Fatalf("not scope refusal: %v", out)
		}
		noLink(t, out, "scope refusal")
		if e.fake.Requests() != n || e.connectRequests() != before {
			t.Fatal("scope refusal reached upstream or started consent")
		}
	}
	// An existing modern consent retry must recheck the live credential scope.
	out := e.mcall(e.key, "tools/call", toolCall("status__provider_token", nil), urlCaps)
	_, state := e.inputRequired(out, "Connect your Github account")
	before := e.connectRequests()
	n := e.fake.Requests()
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE api_keys SET tool_scope='{}' WHERE user_id=(SELECT id FROM users WHERE email='blair@localhost')`); err != nil {
		t.Fatal(err)
	}
	out = e.mcall(e.key, "tools/call", toolCall("status__provider_token", retryWith(state, "accept")), urlCaps)
	if rpcErrorCode(out) != -32602 {
		t.Fatalf("retry bypassed scope: %v", out)
	}
	noLink(t, out, "scope retry")
	if e.fake.Requests() != n || e.connectRequests() != before {
		t.Fatal("scoped retry reached upstream/created consent")
	}
	e.lastCall("denied tool_scope github")
}

func TestCredentialToolScopesReachableServers(t *testing.T) {
	var gw *gateways.Service
	e := newProvEnvHook(t, func(d *httpapi.Deps) { gw = d.Gateways })
	// Only this platform tool gateway remains reachable after team removal.
	g := e.createGateway(e.admin, "/v1/admin/gateways", "scoped-platform")
	base := "/v1/admin/gateways/" + g.Id.String()
	e.publish(e.owner, e.server)
	e.mustSetCaps(e.admin, base, sel(e.capID(e.owner, e.server, "tool", "provider_token")))
	var grant apitypes.GatewayGrant
	code, ec := e.admin.call("POST", base+"/grants", map[string]any{"subjectKind": "user", "userEmail": "blair@localhost", "toolScope": map[string]any{}}, &grant, nil)
	mustCode(t, "deny-all platform grant", code, ec, 201, "")
	code, ec = e.owner.call("DELETE", toolsTeam+"/members/"+e.userID("blair@localhost"), nil, nil, nil)
	mustCode(t, "remove team membership", code, ec, 200, "")
	q := dbgen.New(e.app.Pool)
	u, err := q.GetUser(context.Background(), uuid.MustParse(e.userID("blair@localhost")))
	if err != nil {
		t.Fatal(err)
	}
	uses, err := gw.UsesServer(context.Background(), u, e.server.Id)
	if err != nil || uses {
		t.Fatalf("hidden server usable=%v %v", uses, err)
	}
	servers, err := gw.ReachableServers(context.Background(), u)
	if err != nil || len(servers) != 0 {
		t.Fatalf("hidden server reachable=%v %v", servers, err)
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope='{"tools":["status__provider_token"]}' WHERE id=$1`, grant.Id); err != nil {
		t.Fatal(err)
	}
	servers, err = gw.ReachableServers(context.Background(), u)
	if err != nil || len(servers) != 1 || len(servers[0].Needs) != 1 {
		t.Fatalf("named server not reachable=%v %v", servers, err)
	}
	uses, err = gw.UsesServer(context.Background(), u, e.server.Id)
	if err != nil || !uses {
		t.Fatalf("named server not usable=%v %v", uses, err)
	}
}

func TestCredentialToolScopesPaginationRechecks(t *testing.T) {
	e := scopedRuntime(t)
	for _, name := range []string{"whoami", "check_outage"} {
		def := map[string]any{"name": name, "description": strings.Repeat("x", 300<<10), "inputSchema": map[string]any{"type": "object"}}
		raw, _ := json.Marshal(def)
		if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_capabilities SET definition=$1 WHERE server_id=$2 AND kind='tool' AND name=$3`, raw, e.server.Id, name); err != nil {
			t.Fatal(err)
		}
	}
	sa := createSA(t, e.owner, map[string]any{"name": "paged", "toolScope": nameScope("status__whoami", "status__check_outage")})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "paged"})
	for _, modern := range []bool{false, true} {
		patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": nameScope("status__whoami", "status__check_outage")})
		first := resultOf(t, scopeRPC(t, e, modern, "support", key.Secret, "tools/list", nil))
		cursor, _ := first["nextCursor"].(string)
		if cursor == "" || len(first["tools"].([]any)) != 1 {
			t.Fatal("fixture did not paginate")
		}
		second := resultOf(t, scopeRPC(t, e, modern, "support", key.Secret, "tools/list", map[string]any{"cursor": cursor}))
		if len(second["tools"].([]any)) != 1 || second["nextCursor"] != nil {
			t.Fatal("second scoped page wrong")
		}
		patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": map[string]any{}})
		second = resultOf(t, scopeRPC(t, e, modern, "support", key.Secret, "tools/list", map[string]any{"cursor": cursor}))
		if len(second["tools"].([]any)) != 0 || second["nextCursor"] != nil {
			t.Fatal("pagination retained stale scope")
		}
	}
}
