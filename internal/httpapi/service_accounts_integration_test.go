package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Service accounts (docs/phase4-client-auth.md; decisions 22 and 23):
// team-owned identities whose keys use the team's own gateways (with the
// account's role) and platform gateways granted to the team.

const saBase = toolsTeam + "/service-accounts"

func createSA(t *testing.T, s *session, body map[string]any) apitypes.ServiceAccount {
	t.Helper()
	var out apitypes.ServiceAccount
	code, ec := s.call("POST", saBase, body, &out, nil)
	mustCode(t, "create service account", code, ec, 201, "")
	return out
}

func createSAKey(t *testing.T, s *session, saID string, body map[string]any) apitypes.ServiceAccountKeyCreated {
	t.Helper()
	var out apitypes.ServiceAccountKeyCreated
	code, ec := s.call("POST", saBase+"/"+saID+"/keys", body, &out, nil)
	mustCode(t, "create key", code, ec, 201, "")
	return out
}

func patchSA(t *testing.T, s *session, saID string, body map[string]any) apitypes.ServiceAccount {
	t.Helper()
	var cur, out apitypes.ServiceAccount
	if code := s.get(saBase+"/"+saID, &cur); code != 200 {
		t.Fatalf("get service account = %d", code)
	}
	code, ec := s.call("PATCH", saBase+"/"+saID, body, &out, ifMatch(cur.Revision))
	mustCode(t, "patch service account", code, ec, 200, "")
	return out
}

func toolList(t *testing.T, app *testApp, slug, key string) (int, []string) {
	t.Helper()
	code, _, out := rawMCP(t, app, "POST", slug, key, rpc(1, "tools/list", nil), nil)
	names := []string{}
	if r, ok := out["result"].(map[string]any); ok {
		tools, _ := r["tools"].([]any)
		for _, tool := range tools {
			names = append(names, tool.(map[string]any)["name"].(string))
		}
	}
	slices.Sort(names)
	return code, names
}

func TestServiceAccountsManagement(t *testing.T) {
	e := newGwEnv(t, nil)
	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot", "description": "Release pipeline"})
	if sa.Role != "member" || !sa.Enabled || sa.TeamSlug != "tools" || sa.ActiveKeyCount != 0 || sa.CreatedByName == nil || sa.Revision != 1 {
		t.Fatalf("service account = %+v", sa)
	}
	id := sa.Id.String()
	for _, c := range []struct {
		body map[string]any
		code int
		err  string
	}{
		{map[string]any{"name": "ci-bot"}, 409, "name_taken"},
		{map[string]any{"name": "CI Bot"}, 400, "invalid_name"},
		{map[string]any{"name": "-bot"}, 400, "invalid_name"},
		{map[string]any{"name": "ops", "role": "admin"}, 400, "invalid_role"},
		{map[string]any{"name": "ops", "role": "owner"}, 400, "invalid_role"},
	} {
		code, ec := e.owner.call("POST", saBase, c.body, nil, nil)
		mustCode(t, "create "+c.err, code, ec, c.code, c.err)
	}
	// Owners and admins manage; members and platform staff read; others
	// don't see the team.
	code, ec := e.member.call("POST", saBase, map[string]any{"name": "mine"}, nil, nil)
	mustCode(t, "member create", code, ec, 403, "forbidden")
	code, ec = e.editor.call("POST", saBase, map[string]any{"name": "mine"}, nil, nil)
	mustCode(t, "editor create", code, ec, 403, "forbidden")
	code, ec = e.admin.call("POST", saBase, map[string]any{"name": "mine"}, nil, nil)
	mustCode(t, "platform admin create", code, ec, 403, "forbidden")
	code, ec = e.outsider.call("GET", saBase, nil, nil, nil)
	mustCode(t, "outsider list", code, ec, 404, "team_not_found")
	var list []apitypes.ServiceAccount
	if code := e.member.get(saBase, &list); code != 200 || len(list) != 1 || list[0].Name != "ci-bot" {
		t.Fatalf("member list = %d %+v", code, list)
	}
	if code := e.auditor.get(saBase+"/"+id, nil); code != 200 {
		t.Errorf("auditor get = %d", code)
	}
	code, ec = e.member.call("GET", saBase+"/"+id+"/keys", nil, nil, nil)
	mustCode(t, "member keys", code, ec, 403, "forbidden")
	code, ec = e.owner.call("PATCH", saBase+"/"+id, map[string]any{"role": "editor"}, nil, nil)
	mustCode(t, "no If-Match", code, ec, 428, "")
	code, ec = e.owner.call("PATCH", saBase+"/"+id, map[string]any{"role": "editor"}, nil, ifMatch(9))
	mustCode(t, "stale", code, ec, 412, "")
	if got := patchSA(t, e.owner, id, map[string]any{"role": "editor", "description": "x"}); got.Role != "editor" || got.Revision != 2 {
		t.Fatalf("patched = %+v", got)
	}
	createSA(t, e.owner, map[string]any{"name": "other-bot"})
	code, ec = e.owner.call("PATCH", saBase+"/"+id, map[string]any{"name": "other-bot"}, nil, ifMatch(2))
	mustCode(t, "rename to a taken name", code, ec, 409, "name_taken")

	// Keys: at most two active (rotation), always expiring, shown once.
	k1 := createSAKey(t, e.owner, id, map[string]any{"name": "deploy"})
	if !strings.HasPrefix(k1.Secret, "omp_sa_") || len(k1.Secret) != len("omp_sa_")+43 || k1.Key.Prefix != k1.Secret[:len("omp_sa_")+8] || k1.Key.Status != "active" ||
		time.Until(k1.Key.ExpiresAt) < 89*24*time.Hour || len(k1.Key.Gateways) != 0 || k1.Key.CreatedByName == nil {
		t.Fatalf("key = %+v", k1)
	}
	for _, body := range []map[string]any{{"name": ""}, {"name": "x", "expiresInDays": 0}, {"name": "x", "expiresInDays": 366}} {
		code, ec := e.owner.call("POST", saBase+"/"+id+"/keys", body, nil, nil)
		mustCode(t, "invalid key", code, ec, 400, "")
	}
	k2 := createSAKey(t, e.owner, id, map[string]any{"name": "deploy-next", "expiresInDays": 365})
	code, ec = e.owner.call("POST", saBase+"/"+id+"/keys", map[string]any{"name": "third"}, nil, nil)
	mustCode(t, "third key", code, ec, 409, "too_many_keys")
	code, ec = e.member.call("DELETE", saBase+"/"+id+"/keys/"+k1.Key.Id.String(), nil, nil, nil)
	mustCode(t, "member revokes", code, ec, 403, "forbidden")
	code, ec = e.owner.call("DELETE", saBase+"/"+id+"/keys/"+k1.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke", code, ec, 200, "")
	code, ec = e.owner.call("DELETE", saBase+"/"+id+"/keys/"+k1.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke again", code, ec, 200, "")
	createSAKey(t, e.owner, id, map[string]any{"name": "rotated"})
	var keys []apitypes.ServiceAccountKey
	if code := e.auditor.get(saBase+"/"+id+"/keys", &keys); code != 200 || len(keys) != 3 || keys[0].Name != "rotated" || keys[2].Status != "revoked" {
		t.Fatalf("keys = %d %+v", code, keys)
	}
	var got apitypes.ServiceAccount
	if e.owner.get(saBase+"/"+id, &got); got.ActiveKeyCount != 2 {
		t.Errorf("active keys = %d", got.ActiveKeyCount)
	}
	if n := e.scalar(`SELECT count(*)::text FROM service_account_keys k WHERE position($1 in row_to_json(k)::text) > 0
		OR position($2 in row_to_json(k)::text) > 0`, k1.Secret, k2.Secret); n != "0" {
		t.Fatal("a secret is stored")
	}
	// A turned-off account gets no keys.
	patchSA(t, e.owner, id, map[string]any{"enabled": false})
	code, ec = e.owner.call("DELETE", saBase+"/"+id+"/keys/"+k2.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke while off", code, ec, 200, "")
	code, ec = e.owner.call("POST", saBase+"/"+id+"/keys", map[string]any{"name": "while off"}, nil, nil)
	mustCode(t, "key while off", code, ec, 409, "disabled")
	// Archived teams are read-only.
	e.setTeamStatus("tools", "archived")
	code, ec = e.owner.call("POST", saBase, map[string]any{"name": "late"}, nil, nil)
	mustCode(t, "create in an archived team", code, ec, 409, "team_archived")
	e.setTeamStatus("tools", "active")
	code, ec = e.owner.call("DELETE", saBase+"/"+id, nil, nil, nil)
	mustCode(t, "delete", code, ec, 200, "")
	code, ec = e.owner.call("GET", saBase+"/"+id, nil, nil, nil)
	mustCode(t, "deleted", code, ec, 404, "service_account_not_found")

	// Audited with the team, never with a secret.
	for _, action := range []string{"service_account.create", "service_account.update", "service_account.delete",
		"service_account_key.create", "service_account_key.revoke"} {
		if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = $1 AND team_id IS NOT NULL`, action); n == "0" {
			t.Errorf("no %s entries", action)
		}
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE target_type = 'service_account_key'`); n != "5" { // 3 created, 2 revoked
		t.Errorf("key audits = %s", n)
	}
	var page apitypes.AuditPage
	e.owner.get(toolsTeam+"/audit?action=service_account_key.revoke", &page)
	if len(page.Items) == 0 || page.Items[0].TargetLabel == nil || !strings.HasPrefix(*page.Items[0].TargetLabel, "ci-bot · ") {
		t.Errorf("revoke entry = %+v", page.Items)
	}
	audit := e.scalar(`SELECT string_agg(row_to_json(a)::text, '') FROM audit_log a`)
	if strings.Contains(audit, k1.Secret) || strings.Contains(audit, k2.Secret) {
		t.Error("the audit log contains a key")
	}
}

func TestServiceAccountsAtTheGateway(t *testing.T) {
	logs := &syncBuffer{}
	e := newGwEnv(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	jwks := e.app.URL + "/.well-known/jwks.json"
	e.fake.SetJWKS(jwks, e.fake.URL())
	e.publish(e.owner, e.server)
	whoami := e.capID(e.owner, e.server, "tool", "whoami")
	support := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	supportPath := toolsTeam + "/gateways/" + support.Id.String()
	e.mustSetCaps(e.owner, supportPath, sel(whoami, e.capID(e.owner, e.server, "tool", "echo")+":editor",
		e.capID(e.owner, e.server, "tool", "check_outage")+":admin"))
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	sharedPath := "/v1/admin/gateways/" + shared.Id.String()
	e.mustSetCaps(e.admin, sharedPath, sel(whoami))
	// A gateway granted only to a person of the team: not to its accounts.
	personal := e.createGateway(e.admin, "/v1/admin/gateways", "personal")
	e.mustSetCaps(e.admin, "/v1/admin/gateways/"+personal.Id.String(), sel(whoami))
	code, ec := e.admin.call("POST", "/v1/admin/gateways/"+personal.Id.String()+"/grants", map[string]any{"subjectKind": "user", "userEmail": "user@localhost"}, nil, nil)
	mustCode(t, "grant to a person", code, ec, 201, "")
	other := e.createGateway(e.outsider, "/v1/teams/other/gateways", "other-gw")

	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot"})
	id := sa.Id.String()
	key := createSAKey(t, e.owner, id, map[string]any{"name": "deploy"})

	// Role member: only capabilities without a minimum role above member.
	if code, names := toolList(t, e.app, "support", key.Secret); code != 200 || strings.Join(names, ",") != "status__whoami" {
		t.Fatalf("member tools = %d %v", code, names)
	}
	patchSA(t, e.owner, id, map[string]any{"role": "editor"})
	if _, names := toolList(t, e.app, "support", key.Secret); strings.Join(names, ",") != "status__echo,status__whoami" {
		t.Fatalf("editor tools = %v", names)
	}
	// Platform gateways: only through a grant to the team.
	for _, slug := range []string{"shared", "personal", "other-gw"} {
		if code, _ := toolList(t, e.app, slug, key.Secret); code != 404 {
			t.Errorf("%s without a team grant = %d", slug, code)
		}
	}
	var g apitypes.GatewayGrant
	code, ec = e.admin.call("POST", sharedPath+"/grants", map[string]any{"subjectKind": "team", "team": "tools"}, &g, nil)
	mustCode(t, "grant to the team", code, ec, 201, "")
	if code, names := toolList(t, e.app, "shared", key.Secret); code != 200 || strings.Join(names, ",") != "status__whoami" {
		t.Fatalf("shared with a team grant = %d %v", code, names)
	}

	// The identity names the service account, not a person.
	cs := connect(t, e.app, "support", key.Secret)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
	if err != nil || res.IsError {
		t.Fatalf("whoami: %v %+v", err, res)
	}
	var who testutil.WhoamiResult
	_ = json.Unmarshal([]byte(resultText(t, res)), &who)
	c := who.Claims
	if teams, _ := c["teams"].([]any); !who.Verified || c["principal_type"] != "service_account" || c["sub"] != id || c["name"] != "ci-bot" ||
		len(teams) != 1 || teams[0] != "tools" || c["email"] != nil || c["client"] != "deploy" || c["client_verified"] != nil || c["gateway"] != "support" {
		t.Fatalf("whoami = %+v", who)
	}
	// People's tokens say user.
	personKey := newKey(t, e.member, "laptop")
	res, _ = connect(t, e.app, "support", personKey.Secret).CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
	who = testutil.WhoamiResult{}
	_ = json.Unmarshal([]byte(resultText(t, res)), &who)
	if who.Claims["principal_type"] != "user" || who.Claims["email"] != "blair@localhost" {
		t.Fatalf("person whoami = %+v", who)
	}

	// A key limited to a gateway; scopes are gateways the account can use.
	code, ec = e.owner.call("POST", saBase+"/"+id+"/keys", map[string]any{"name": "bad scope", "gatewayIds": []string{other.Id.String()}}, nil, nil)
	mustCode(t, "scope to another team's gateway", code, ec, 422, "gateway_not_usable")
	scoped := createSAKey(t, e.owner, id, map[string]any{"name": "shared only", "gatewayIds": []string{shared.Id.String()}})
	if len(scoped.Key.Gateways) != 1 || scoped.Key.Gateways[0].Slug != "shared" {
		t.Fatalf("scoped key = %+v", scoped.Key)
	}
	if code, _ := toolList(t, e.app, "support", scoped.Secret); code != 404 {
		t.Errorf("scoped key elsewhere = %d", code)
	}
	if got := e.scalar(`SELECT coalesce(error_class, '') FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "key_scope" {
		t.Errorf("scope refusal recorded as %q", got)
	}
	if code, _ := toolList(t, e.app, "shared", scoped.Secret); code != 200 {
		t.Errorf("scoped key on its gateway = %d", code)
	}

	// Call records name the account; the serviceAccount filter finds them.
	// The team's calls include every call of its accounts, through any
	// gateway: the platform gateways and the other team's gateway too (all
	// nine of them, refusals included).
	var page apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls?serviceAccount="+id, &page); code != 200 || len(page.Items) != 9 {
		t.Fatalf("calls = %d %d", code, len(page.Items))
	}
	through := map[string]int{}
	for _, it := range page.Items {
		p := it.Principal
		through[it.Gateway.Slug]++
		if p.Kind != "service_account" || p.DisplayName != "ci-bot" || p.ServiceAccountId == nil || p.ServiceAccountId.String() != id ||
			p.ServiceAccountTeamSlug == nil || *p.ServiceAccountTeamSlug != "tools" || p.ApiKeyName == nil || p.UserId != nil || p.Email != nil ||
			p.ServiceAccountExists == nil || !*p.ServiceAccountExists || p.OauthClientVerified != nil {
			t.Errorf("principal = %+v", p)
		}
	}
	if through["support"] != 4 || through["shared"] != 3 || through["personal"] != 1 || through["other-gw"] != 1 {
		t.Errorf("calls by gateway = %v", through)
	}
	// The other team sees the refusal on its gateway (it went through it).
	page = apitypes.McpCallPage{}
	if code := e.outsider.get("/v1/teams/other/calls?serviceAccount="+id, &page); code != 200 || len(page.Items) != 1 || page.Items[0].Gateway.Slug != "other-gw" {
		t.Errorf("other team's calls by the account = %d %+v", code, page.Items)
	}
	page = apitypes.McpCallPage{}
	if code := e.auditor.get("/v1/admin/calls?serviceAccount="+id+"&gateway="+shared.Id.String(), &page); code != 200 || len(page.Items) < 2 {
		t.Errorf("admin calls = %d %d", code, len(page.Items))
	}
	if code := e.owner.get(toolsTeam+"/calls?serviceAccount=nope", nil); code != 400 {
		t.Errorf("bad filter = %d", code)
	}

	// Removing the team grant stops the account at the next request.
	code, ec = e.admin.call("DELETE", sharedPath+"/grants/"+g.Id.String(), nil, nil, nil)
	mustCode(t, "remove team grant", code, ec, 200, "")
	if code, _ := toolList(t, e.app, "shared", key.Secret); code != 404 {
		t.Errorf("after the grant is removed = %d", code)
	}

	// Turned off, archived team, revoked, expired, deleted: refused at the
	// next request, without reaching the server.
	check := func(what, secret string, want int) {
		t.Helper()
		before := e.fake.Requests()
		code, _, _ := rawMCP(t, e.app, "POST", "support", secret, rpc(1, "tools/call", map[string]any{"name": "status__whoami"}), nil)
		if code != want {
			t.Errorf("%s = %d, want %d", what, code, want)
		}
		if want != 200 && e.fake.Requests() != before {
			t.Errorf("%s: the refused call reached the server", what)
		}
	}
	check("before", key.Secret, 200)
	patchSA(t, e.owner, id, map[string]any{"enabled": false})
	check("turned off", key.Secret, 401)
	patchSA(t, e.owner, id, map[string]any{"enabled": true})
	check("turned on again", key.Secret, 200)
	e.setTeamStatus("tools", "archived")
	check("archived team", key.Secret, 401)
	e.setTeamStatus("tools", "active")
	check("unarchived team", key.Secret, 200)
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE service_account_keys SET created_at = now() - interval '2 days',
		expires_at = now() - interval '1 day' WHERE id = $1`, key.Key.Id); err != nil {
		t.Fatal(err)
	}
	check("expired", key.Secret, 401)
	code, ec = e.owner.call("DELETE", saBase+"/"+id+"/keys/"+scoped.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke", code, ec, 200, "")
	if code, _ := toolList(t, e.app, "shared", scoped.Secret); code != 401 {
		t.Errorf("revoked = %d", code)
	}
	fresh := createSAKey(t, e.owner, id, map[string]any{"name": "fresh"})
	check("fresh key", fresh.Secret, 200)
	if e.scalar(`SELECT (last_used_at IS NOT NULL)::text FROM service_accounts WHERE id = $1`, id) != "true" {
		t.Error("account last use not recorded")
	}
	code, ec = e.owner.call("DELETE", saBase+"/"+id, nil, nil, nil)
	mustCode(t, "delete", code, ec, 200, "")
	check("deleted account", fresh.Secret, 401)
	// Its records stay, with its name as it was.
	page = apitypes.McpCallPage{}
	if code := e.auditor.get("/v1/admin/calls?serviceAccount="+id+"&limit=1", &page); code != 200 || len(page.Items) != 1 ||
		page.Items[0].Principal.DisplayName != "ci-bot" || page.Items[0].Principal.ApiKeyName == nil || *page.Items[0].Principal.ApiKeyName != "fresh" ||
		page.Items[0].Principal.ServiceAccountExists == nil || *page.Items[0].Principal.ServiceAccountExists {
		t.Errorf("records after delete = %d %+v", code, page.Items)
	}

	// Keys appear nowhere but their creation responses.
	for what, text := range map[string]string{
		"mcp_calls": e.scalar(`SELECT string_agg(row_to_json(c)::text, '') FROM mcp_calls c`),
		"audit_log": e.scalar(`SELECT string_agg(row_to_json(a)::text, '') FROM audit_log a`),
		"logs":      logs.String(),
	} {
		for _, secret := range []string{key.Secret, scoped.Secret, fresh.Secret} {
			if strings.Contains(text, secret) {
				t.Errorf("%s contains a service account key", what)
			}
		}
	}
}

// GET .../service-accounts/{id}/gateways: what an account can use now, with
// its role applied (decision 23); and the admin list of every team's
// accounts.
func TestServiceAccountGatewaysAndAdminList(t *testing.T) {
	e := newGwEnv(t, nil)
	e.publish(e.owner, e.server)
	whoami := e.capID(e.owner, e.server, "tool", "whoami")
	support := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+support.Id.String(), sel(whoami, e.capID(e.owner, e.server, "tool", "echo")+":editor",
		e.capID(e.owner, e.server, "tool", "check_outage")+":admin"))
	off := e.createGateway(e.owner, toolsTeam+"/gateways", "off")
	var cur apitypes.Gateway
	e.owner.get(toolsTeam+"/gateways/"+off.Id.String(), &cur)
	code, ec := e.owner.call("PATCH", toolsTeam+"/gateways/"+off.Id.String(), map[string]any{"enabled": false}, nil, ifMatch(cur.Revision))
	mustCode(t, "turn a gateway off", code, ec, 200, "")
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	e.mustSetCaps(e.admin, "/v1/admin/gateways/"+shared.Id.String(), sel(whoami))
	code, ec = e.admin.call("POST", "/v1/admin/gateways/"+shared.Id.String()+"/grants", map[string]any{"subjectKind": "team", "team": "tools"}, nil, nil)
	mustCode(t, "grant to the team", code, ec, 201, "")
	personal := e.createGateway(e.admin, "/v1/admin/gateways", "personal")
	code, ec = e.admin.call("POST", "/v1/admin/gateways/"+personal.Id.String()+"/grants", map[string]any{"subjectKind": "user", "userEmail": "user@localhost"}, nil, nil)
	mustCode(t, "grant to a person", code, ec, 201, "")
	e.createGateway(e.outsider, "/v1/teams/other/gateways", "other-gw")

	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot"})
	path := saBase + "/" + sa.Id.String() + "/gateways"
	list := func(s *session) []apitypes.MyGateway {
		t.Helper()
		var out []apitypes.MyGateway
		if code := s.get(path, &out); code != 200 {
			t.Fatalf("gateways = %d", code)
		}
		return out
	}
	summary := func(gws []apitypes.MyGateway) string {
		parts := []string{}
		for _, g := range gws {
			access := []string{}
			for _, a := range g.Access {
				access = append(access, string(a))
			}
			parts = append(parts, g.Slug+":"+strings.Join(access, "+")+":"+strconv.FormatInt(g.CapabilityCount, 10))
		}
		return strings.Join(parts, " ")
	}
	// Role member: one of support's three capabilities; the team's grant
	// covers shared; a person's grant, another team's gateway and a gateway
	// that's off don't count.
	if got := summary(list(e.member)); got != "shared:team_grant:1 support:team_member:1" {
		t.Fatalf("member-role account = %q", got)
	}
	gws := list(e.auditor)
	if g := gws[1]; g.Url != e.app.URL+"/mcp/support" || g.TeamSlug == nil || *g.TeamSlug != "tools" || g.OwnerKind != "team" || g.Groups != nil {
		t.Errorf("support = %+v", g)
	}
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"role": "editor"})
	if got := summary(list(e.editor)); got != "shared:team_grant:1 support:team_member:2" {
		t.Errorf("editor-role account = %q", got)
	}
	// A turned-off account still lists them; an archived team none.
	patchSA(t, e.owner, sa.Id.String(), map[string]any{"enabled": false})
	if got := summary(list(e.owner)); got != "shared:team_grant:1 support:team_member:2" {
		t.Errorf("turned-off account = %q", got)
	}
	e.setTeamStatus("tools", "archived")
	if got := list(e.admin); len(got) != 0 {
		t.Errorf("archived team = %+v", got)
	}
	e.setTeamStatus("tools", "active")
	code, ec = e.outsider.call("GET", path, nil, nil, nil)
	mustCode(t, "outsider", code, ec, 404, "team_not_found")
	code, ec = e.owner.call("GET", saBase+"/00000000-0000-0000-0000-000000000000/gateways", nil, nil, nil)
	mustCode(t, "unknown account", code, ec, 404, "service_account_not_found")
	code, ec = e.outsider.call("GET", "/v1/teams/other/service-accounts/"+sa.Id.String()+"/gateways", nil, nil, nil)
	mustCode(t, "another team's account", code, ec, 404, "service_account_not_found")

	// Every team's accounts, for platform staff: by name, searchable, by team, paged.
	createSA(t, e.owner, map[string]any{"name": "a-tools-bot"})
	code, ec = e.outsider.call("POST", "/v1/teams/other/service-accounts", map[string]any{"name": "zz-other-bot"}, nil, nil)
	mustCode(t, "other team's account", code, ec, 201, "")
	names := func(s *session, query string) (int, []string, *string) {
		t.Helper()
		var page apitypes.ServiceAccountPage
		code := s.get("/v1/admin/service-accounts"+query, &page)
		out := []string{}
		for _, a := range page.Items {
			out = append(out, a.TeamSlug+"/"+a.Name)
		}
		return code, out, page.NextCursor
	}
	if code, got, next := names(e.auditor, ""); code != 200 || strings.Join(got, ",") != "tools/a-tools-bot,tools/ci-bot,other/zz-other-bot" || next != nil {
		t.Errorf("all = %d %v %v", code, got, next)
	}
	if _, got, _ := names(e.admin, "?team=other"); strings.Join(got, ",") != "other/zz-other-bot" {
		t.Errorf("team filter = %v", got)
	}
	if _, got, _ := names(e.admin, "?q=OTHER"); strings.Join(got, ",") != "other/zz-other-bot" {
		t.Errorf("search = %v", got)
	}
	if _, got, _ := names(e.admin, "?q=tools"); strings.Join(got, ",") != "tools/a-tools-bot,tools/ci-bot" {
		t.Errorf("search by team = %v", got)
	}
	if _, got, _ := names(e.admin, "?team=nope"); len(got) != 0 {
		t.Errorf("unknown team = %v", got)
	}
	_, first, next := names(e.admin, "?limit=2")
	if len(first) != 2 || next == nil {
		t.Fatalf("first page = %v %v", first, next)
	}
	if _, rest, last := names(e.admin, "?limit=2&cursor="+*next); strings.Join(rest, ",") != "other/zz-other-bot" || last != nil {
		t.Errorf("second page = %v %v", rest, last)
	}
	for _, s := range []*session{e.owner, e.member} {
		code, ec := s.call("GET", "/v1/admin/service-accounts", nil, nil, nil)
		mustCode(t, "non-staff", code, ec, 403, "forbidden")
	}
	for _, q := range []string{"?cursor=junk", "?limit=0", "?team=" + strings.Repeat("x", 101)} {
		code, _ := e.admin.call("GET", "/v1/admin/service-accounts"+q, nil, nil, nil)
		if code != 400 {
			t.Errorf("%s = %d", q, code)
		}
	}
}
