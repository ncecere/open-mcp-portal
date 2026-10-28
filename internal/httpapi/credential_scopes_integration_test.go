package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func classScope(classes ...string) map[string]any { return map[string]any{"classes": classes} }
func nameScope(names ...string) map[string]any    { return map[string]any{"tools": names} }

// Fixtures seed trusted owner classifications directly; classification's
// own authorization/review behavior is covered by the #28 integration tests.
func scopedRuntime(t *testing.T) *rtEnv {
	t.Helper()
	e := newRuntimeEnv(t)
	for name, class := range map[string]string{"whoami": "read", "echo": "write", "create_ticket": "destructive"} {
		if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_capabilities SET tool_class=$1 WHERE server_id=$2 AND kind='tool' AND name=$3`, class, e.server.Id, name); err != nil {
			t.Fatal(err)
		}
	}
	ids := []string{}
	for _, name := range []string{"whoami", "echo", "create_ticket", "check_outage"} {
		ids = append(ids, e.capID(e.owner, e.server, "tool", name))
	}
	ids = append(ids, e.capID(e.owner, e.server, "prompt", "incident_summary"), e.capID(e.owner, e.server, "resource", "status://services"))
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(ids...))
	e.mustSetCaps(e.admin, e.shared, sel(ids...))
	return e
}

func scopedKey(t *testing.T, s *session, scope any) apitypes.ApiKeyCreated {
	t.Helper()
	code, raw, k := createKey(t, s, map[string]any{"name": "scoped", "toolScope": scope})
	if code != 201 {
		t.Fatalf("create scoped key: %d %s", code, raw)
	}
	return k
}

func scopeRPC(t *testing.T, e *rtEnv, modern bool, slug, key, method string, params map[string]any) map[string]any {
	t.Helper()
	var status int
	var out map[string]any
	if modern {
		status, _, out = rawModern(t, e.app, slug, key, method, params, nil, nil)
	} else {
		status, _, out = rawMCP(t, e.app, "POST", slug, key, rpc(1, method, params), nil)
	}
	if status != 200 {
		t.Fatalf("%s: %d %v", method, status, out)
	}
	return out
}
func scopeList(t *testing.T, e *rtEnv, modern bool, slug, key string) []string {
	t.Helper()
	before := e.fake.Requests()
	out := scopeRPC(t, e, modern, slug, key, "tools/list", nil)
	tools, _ := resultOf(t, out)["tools"].([]any)
	names := []string{}
	for _, v := range tools {
		names = append(names, v.(map[string]any)["name"].(string))
	}
	if e.fake.Requests() != before {
		t.Fatal("listing contacted upstream")
	}
	return names
}
func wantScopedList(t *testing.T, e *rtEnv, modern bool, slug, key string, want ...string) {
	t.Helper()
	slices.Sort(want)
	if got := scopeList(t, e, modern, slug, key); !slices.Equal(got, want) {
		t.Fatalf("%s scope list=%v want %v", slug, got, want)
	}
}
func wantScopeDenied(t *testing.T, e *rtEnv, modern bool, slug, key, name string) {
	t.Helper()
	before := e.fake.Requests()
	out := scopeRPC(t, e, modern, slug, key, "tools/call", map[string]any{"name": name})
	if rpcErrorCode(out) != -32602 {
		t.Fatalf("not normal unknown-tool error: %v", out)
	}
	msg := out["error"].(map[string]any)["message"]
	if msg != "Unknown tool: "+name {
		t.Fatalf("message=%v", msg)
	}
	if e.fake.Requests() != before {
		t.Fatal("scope refusal reached upstream")
	}
	if got := e.scalar(`SELECT outcome||':'||coalesce(error_class,'') FROM mcp_calls WHERE method='tools/call' ORDER BY id DESC LIMIT 1`); got != "denied:tool_scope" {
		t.Fatalf("record=%s", got)
	}
}

func TestCredentialToolScopesPersonalKeys(t *testing.T) {
	e := scopedRuntime(t)
	for _, modern := range []bool{false, true} {
		t.Run(fmt.Sprintf("modern=%v", modern), func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				scope any
				want  []string
			}{
				{"read", classScope("read"), []string{"status__whoami"}},
				{"named unclassified", nameScope("status__check_outage"), []string{"status__check_outage"}},
				{"mixed", map[string]any{"classes": []string{"read"}, "tools": []string{"status__echo"}}, []string{"status__echo", "status__whoami"}},
				{"deny all", map[string]any{}, []string{}},
				{"explicit three", classScope("read", "write", "destructive"), []string{"status__create_ticket", "status__echo", "status__whoami"}},
				{"null", nil, []string{"status__check_outage", "status__create_ticket", "status__echo", "status__whoami"}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					k := scopedKey(t, e.member, tc.scope)
					wantScopedList(t, e, modern, "support", k.Secret, tc.want...)
					for _, name := range []string{"status__whoami", "status__echo", "status__create_ticket", "status__check_outage"} {
						if !slices.Contains(tc.want, name) {
							wantScopeDenied(t, e, modern, "support", k.Secret, name)
						} else {
							out := scopeRPC(t, e, modern, "support", k.Secret, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}})
							if out["error"] != nil {
								t.Fatalf("allowed call=%v", out)
							}
						}
					}
					// Tools only: deny-all does not hide prompts or resources.
					for method, key := range map[string]string{"prompts/list": "prompts", "resources/list": "resources"} {
						out := scopeRPC(t, e, modern, "support", k.Secret, method, nil)
						if len(resultOf(t, out)[key].([]any)) != 1 {
							t.Fatalf("scope affected %s: %v", method, out)
						}
					}
					if c, ec := e.member.call("DELETE", "/v1/me/api-keys/"+k.Key.Id.String(), nil, nil, nil); c != 200 {
						t.Fatalf("cleanup: %d %s", c, ec)
					}
				})
			}
		})
	}
	// Malformed stored JSON must deny, not turn into an absent ceiling.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE api_keys SET tool_scope='{"classes":["administrator"]}'::jsonb WHERE id=$1`, e.key.Key.Id); err != nil {
		t.Fatal(err)
	}
	wantScopedList(t, e, false, "support", e.key.Secret)
	wantScopeDenied(t, e, false, "support", e.key.Secret, "status__whoami")
	out := scopeRPC(t, e, false, "support", e.key.Secret, "tools/call", map[string]any{"name": "status__missing"})
	if rpcErrorCode(out) != -32602 || out["error"].(map[string]any)["message"] != "Unknown tool: status__missing" {
		t.Fatalf("unknown parity: %v", out)
	}
}

func TestCredentialToolScopesServiceAccountLiveCeiling(t *testing.T) {
	e := scopedRuntime(t)
	sa := createSA(t, e.owner, map[string]any{"name": "scoped-bot", "toolScope": classScope("read")})
	if sa.ToolScope == nil {
		t.Fatal("create omitted account scope")
	}
	// A default null key under a restricted account is valid and inherits it.
	inherited := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "inherits"})
	named := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "named", "toolScope": nameScope("status__whoami", "status__echo")})
	for _, modern := range []bool{false, true} {
		wantScopedList(t, e, modern, "support", inherited.Secret, "status__whoami")
		wantScopedList(t, e, modern, "support", named.Secret, "status__whoami")
		wantScopeDenied(t, e, modern, "support", inherited.Secret, "status__echo")
	}
	// Omission retains; explicit null clears; an object replaces immediately.
	sa = patchSA(t, e.owner, sa.Id.String(), map[string]any{"description": "retains ceiling"})
	if sa.ToolScope == nil {
		t.Fatal("omission cleared scope")
	}
	wantScopedList(t, e, false, "support", inherited.Secret, "status__whoami")
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": classScope("write")})
	wantScopedList(t, e, true, "support", inherited.Secret, "status__echo")
	wantScopedList(t, e, true, "support", named.Secret, "status__echo")
	wantScopeDenied(t, e, true, "support", named.Secret, "status__whoami")
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": nil})
	wantScopedList(t, e, false, "support", inherited.Secret, "status__check_outage", "status__create_ticket", "status__echo", "status__whoami")
	wantScopedList(t, e, false, "support", named.Secret, "status__echo", "status__whoami")
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"toolScope": map[string]any{}})
	wantScopedList(t, e, false, "support", inherited.Secret)
	var previews []apitypes.MyGateway
	if code := e.owner.get(saBase+"/"+sa.Id.String()+"/gateways", &previews); code != 200 {
		t.Fatal(code)
	}
	for _, g := range previews {
		if g.Slug == "support" && g.CapabilityCount != 2 {
			t.Fatalf("preview ignored live scope: %+v", g)
		}
	}
	var keys []apitypes.ServiceAccountKey
	if code := e.owner.get(saBase+"/"+sa.Id.String()+"/keys", &keys); code != 200 || len(keys) != 2 {
		t.Fatalf("list keys=%d %+v", code, keys)
	}
	if keys[0].ToolScope == nil && keys[1].ToolScope == nil {
		t.Fatal("key list omitted scope")
	}
	if got := e.scalar(`SELECT (after_state->'toolScope')::text FROM audit_log WHERE action='service_account.update' ORDER BY id DESC LIMIT 1`); got != "{}" {
		t.Fatalf("scope audit=%s", got)
	}
}

func TestCredentialToolScopesGrantUnionAndManagement(t *testing.T) {
	e := scopedRuntime(t)
	// Remove the initial unrestricted grant, and union a team, a user and two
	// group grants. Same-kind groups are independent alternatives, not one row.
	c, ec := e.admin.call("DELETE", e.shared+"/grants/"+e.grant, nil, nil, nil)
	mustCode(t, "remove initial", c, ec, 200, "")
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET groups=ARRAY['scope-a','scope-b'] WHERE email='blair@localhost'`); err != nil {
		t.Fatal(err)
	}
	add := func(body map[string]any) apitypes.GatewayGrant {
		t.Helper()
		var gr apitypes.GatewayGrant
		c, ec := e.admin.call("POST", e.shared+"/grants", body, &gr, nil)
		mustCode(t, "grant", c, ec, 201, "")
		return gr
	}
	read := add(map[string]any{"subjectKind": "team", "team": "tools", "toolScope": classScope("read")})
	add(map[string]any{"subjectKind": "user", "userEmail": "blair@localhost", "toolScope": nameScope("status__echo")})
	add(map[string]any{"subjectKind": "group", "group": "scope-a", "toolScope": nameScope("status__check_outage")})
	add(map[string]any{"subjectKind": "group", "group": "scope-b", "toolScope": map[string]any{}})
	if read.ToolScope == nil {
		t.Fatal("grant response omitted scope")
	}
	wantScopedList(t, e, false, "shared", e.key.Secret, "status__check_outage", "status__echo", "status__whoami")
	wantScopeDenied(t, e, false, "shared", e.key.Secret, "status__create_ticket")
	readKey := scopedKey(t, e.member, classScope("read"))
	wantScopedList(t, e, true, "shared", readKey.Secret, "status__whoami")
	// The team's grant applies to service accounts too; named key + class grant
	// intersects successfully even though the two arrays have no common entry.
	sa := createSA(t, e.owner, map[string]any{"name": "grant-bot"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "named", "toolScope": nameScope("status__whoami", "status__echo")})
	wantScopedList(t, e, false, "shared", key.Secret, "status__whoami")
	wantScopeDenied(t, e, false, "shared", key.Secret, "status__echo")
	var mine []apitypes.MyGateway
	if c := e.member.get("/v1/me/gateways", &mine); c != 200 {
		t.Fatal(c)
	}
	for _, g := range mine {
		if g.Slug == "shared" && g.CapabilityCount != 5 {
			t.Fatalf("grant union count=%d", g.CapabilityCount)
		}
	}
	var detail apitypes.MyGatewayDetail
	if c := e.member.get("/v1/me/gateways/"+strings.TrimPrefix(e.shared, "/v1/admin/gateways/"), &detail); c != 200 || len(detail.Capabilities) != 5 {
		t.Fatalf("grant detail=%d %+v", c, detail)
	}
	// A null matching grant dominates the grant union, but not the key layer.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope=NULL WHERE id=$1`, read.Id); err != nil {
		t.Fatal(err)
	}
	wantScopedList(t, e, false, "shared", e.key.Secret, "status__check_outage", "status__create_ticket", "status__echo", "status__whoami")
	wantScopedList(t, e, true, "shared", readKey.Secret, "status__whoami")
	// All grants deny all; selected prompts/resources are still visible, but
	// not the tools. Management previews must agree with runtime visibility.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET tool_scope='{}' WHERE gateway_id=(SELECT id FROM gateways WHERE slug='shared')`); err != nil {
		t.Fatal(err)
	}
	wantScopedList(t, e, false, "shared", e.key.Secret)
	mine = nil
	e.member.get("/v1/me/gateways", &mine)
	for _, g := range mine {
		if g.Slug == "shared" && g.CapabilityCount != 2 {
			t.Fatalf("denied count=%d", g.CapabilityCount)
		}
	}
}

func TestCredentialToolScopeValidationAPI(t *testing.T) {
	e := scopedRuntime(t)
	sa := createSA(t, e.owner, map[string]any{"name": "validate"})
	tooMany := make([]string, 501)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("s__t%d", i)
	}
	for _, bad := range []any{classScope("admin"), nameScope("status__*"), nameScope("status__" + strings.Repeat("x", 1100)), nameScope(strings.Repeat("界", 367)), nameScope("control\u0085"), nameScope(tooMany...)} {
		for _, tc := range []struct {
			s       *session
			path    string
			body    map[string]any
			headers map[string]string
		}{
			{e.member, "/v1/me/api-keys", map[string]any{"name": "bad", "toolScope": bad}, nil},
			{e.owner, saBase, map[string]any{"name": "bad", "toolScope": bad}, nil},
			{e.owner, saBase + "/" + sa.Id.String() + "/keys", map[string]any{"name": "bad", "toolScope": bad}, nil},
			{e.admin, e.shared + "/grants", map[string]any{"subjectKind": "group", "group": "bad", "toolScope": bad}, nil},
		} {
			code, ec := tc.s.call("POST", tc.path, tc.body, nil, tc.headers)
			mustCode(t, tc.path, code, ec, 400, "invalid_tool_scope")
		}
		code, ec := e.owner.call("PATCH", saBase+"/"+sa.Id.String(), map[string]any{"toolScope": bad}, nil, ifMatch(sa.Revision))
		mustCode(t, "patch invalid", code, ec, 400, "invalid_tool_scope")
	}
	// The allowed 1100-byte exact name is accepted, even before discovery.
	long := "s__" + strings.Repeat("x", 1097)
	k := scopedKey(t, e.member, nameScope(long))
	if k.Key.ToolScope == nil || len(*k.Key.ToolScope.Tools) != 1 || (*k.Key.ToolScope.Tools)[0] != long {
		t.Fatal("1100-byte bound mismatch")
	}
	for _, future := range []string{"create_issue_internal", "CreateIssue", "工单_创建", "s__" + strings.Repeat("界", 365) + "xy"} {
		alias := scopedKey(t, e.member, nameScope(future))
		if alias.Key.ToolScope == nil || (*alias.Key.ToolScope.Tools)[0] != future {
			t.Fatalf("future name changed: %+v", alias.Key.ToolScope)
		}
	}
	var keys []apitypes.ApiKey
	e.member.get("/v1/me/api-keys", &keys)
	found := false
	for _, v := range keys {
		if v.Id == k.Key.Id {
			found = v.ToolScope != nil
		}
	}
	if !found {
		t.Fatal("list omitted scope")
	}
	var audit map[string]any
	raw := e.scalar(`SELECT after_state::text FROM audit_log WHERE action='api_key.create' AND target_id=$1 ORDER BY id DESC LIMIT 1`, k.Key.Id.String())
	if json.Unmarshal([]byte(raw), &audit) != nil || audit["toolScope"] == nil || strings.Contains(raw, k.Secret) {
		t.Fatalf("scope audit=%s", raw)
	}
}
