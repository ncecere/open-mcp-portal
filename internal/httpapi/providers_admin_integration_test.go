package httpapi_test

import (
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestAuthProviderManagement(t *testing.T) {
	e := newProvEnv(t)
	var p apitypes.AuthProvider
	if code := e.auditor.get(providersBase+"/"+e.provider.Id.String(), &p); code != 200 {
		t.Fatalf("get provider = %d", code)
	}
	if !p.HasClientSecret || p.ClientSecretHint != e.oauth.ClientSecret[len(e.oauth.ClientSecret)-4:] || p.RedirectUri != e.app.URL+"/connect/callback" ||
		p.ServerCount != 1 || p.TokenAuthMethod != "client_secret_post" || !p.Pkce || p.ScopeParam != "scope" || p.Kind != "oauth2" {
		t.Fatalf("provider = %+v", p)
	}
	base := providersBase + "/" + p.Id.String()
	mk := func(extra map[string]any) (int, string) {
		body := map[string]any{"slug": "x-" + strings.ReplaceAll(strings.ToLower(t.Name()), "/", "-")[:5], "name": "X", "clientId": "c",
			"clientSecret": "s3cret-value", "authorizationUrl": "https://auth.example.com/a", "tokenUrl": "https://auth.example.com/t"}
		for k, v := range extra {
			if v == nil {
				delete(body, k)
			} else {
				body[k] = v
			}
		}
		return e.admin.call("POST", providersBase, body, nil, nil)
	}
	code, ec := mk(map[string]any{"slug": "github"})
	mustCode(t, "slug taken", code, ec, 409, "slug_taken")
	code, ec = mk(map[string]any{"clientSecret": nil})
	mustCode(t, "no secret", code, ec, 422, "client_secret_required")
	code, ec = mk(map[string]any{"clientSecret": nil, "tokenAuthMethod": "none", "pkce": false})
	mustCode(t, "public without PKCE", code, ec, 422, "pkce_required")
	code, ec = mk(map[string]any{"tokenUrl": "https://user:pw@auth.example.com/t"})
	mustCode(t, "user info", code, ec, 422, "url_not_allowed")
	code, ec = mk(map[string]any{"tokenUrl": "http://auth.example.com/t"})
	mustCode(t, "plain http", code, ec, 422, "url_not_allowed")
	code, raw := e.admin.raw("POST", providersBase, map[string]any{"slug": "q", "name": "Q", "clientId": "c", "clientSecret": "s3cret-value",
		"authorizationUrl": "https://auth.example.com/a?x=1", "tokenUrl": "https://auth.example.com/t"}, nil)
	if code != 422 || !strings.Contains(string(raw), `"field":"authorizationUrl"`) || !strings.Contains(string(raw), `"reason":"query"`) {
		t.Fatalf("query = %d %s", code, raw)
	}
	code, raw = e.admin.raw("POST", providersBase, map[string]any{"slug": "r", "name": "R", "clientId": "c", "clientSecret": "s3cret-value",
		"authorizationUrl": "https://auth.example.com/a", "tokenUrl": "https://auth.example.com/t", "extraAuthorizeParams": map[string]string{"state": "x"}}, nil)
	if code != 422 || errorCode(raw) != "invalid_param" || !strings.Contains(string(raw), `"reason":"reserved"`) {
		t.Fatalf("reserved param = %d %s", code, raw)
	}
	code, ec = mk(map[string]any{"defaultScopes": []string{"bad scope"}})
	mustCode(t, "bad scope", code, ec, 400, "invalid_scope")

	// Presets.
	var presets []apitypes.AuthProviderPreset
	if code := e.auditor.get("/v1/admin/auth-provider-presets", &presets); code != 200 || len(presets) != 6 {
		t.Fatalf("presets = %d %d", code, len(presets))
	}
	names := []string{}
	for _, pr := range presets {
		names = append(names, string(pr.Preset))
		if pr.Preset == "microsoft" && (len(pr.UrlParameters) != 1 || pr.UrlParameters[0].Name != "tenant" || !strings.Contains(pr.TokenUrl, "{tenant}")) {
			t.Errorf("microsoft = %+v", pr)
		}
		if pr.Preset == "slack" && (pr.ScopeParam != "user_scope" || pr.ScopeSeparator != "," || pr.TokenResponseFormat != "slack_authed_user" || pr.Pkce) {
			t.Errorf("slack = %+v", pr)
		}
	}
	if presets[0].RedirectUri == nil || *presets[0].RedirectUri != e.app.URL+"/connect/callback" {
		t.Fatalf("preset redirect URI = %v", presets[0].RedirectUri)
	}
	code, raw = e.admin.raw("POST", providersBase, map[string]any{"slug": "done", "name": "D", "clientId": "c", "clientSecret": "s3cret-value",
		"authorizationUrl": "https://auth.example.com/a", "tokenUrl": "https://auth.example.com/t"}, nil)
	if code != 422 || errorCode(raw) != "invalid_slug" || !strings.Contains(string(raw), `"reason":"reserved"`) {
		t.Fatalf("reserved slug = %d %s", code, raw)
	}
	if !slices.Equal(names, []string{"github", "google", "microsoft", "atlassian", "slack", "gitlab"}) {
		t.Fatalf("presets = %v", names)
	}

	// The picker list hides endpoints and client IDs.
	_, raw = e.member.raw("GET", "/v1/auth-providers", nil, nil)
	if strings.Contains(string(raw), "clientId") || strings.Contains(string(raw), e.oauth.URL) || !strings.Contains(string(raw), `"slug":"github"`) {
		t.Fatalf("summaries = %s", raw)
	}

	// In use: can't delete; the admin server list filters by provider.
	code, raw = e.admin.raw("DELETE", base, nil, nil)
	if code != 409 || errorCode(raw) != "in_use" || !strings.Contains(string(raw), `"serverCount":1`) || !strings.Contains(string(raw), `"slug":"status"`) ||
		!strings.Contains(string(raw), `"name":"STATUS"`) {
		t.Fatalf("delete in use = %d %s", code, raw)
	}
	var sp apitypes.McpServerPage
	if code := e.admin.get("/v1/admin/mcp-servers?provider="+p.Id.String(), &sp); code != 200 || len(sp.Items) != 1 || sp.Items[0].Slug != "status" {
		t.Fatalf("filter = %d %+v", code, sp.Items)
	}

	// A consent link reports the connection as it is now, not as it was
	// when the link was made.
	stale := requestID(e.consentURL(e.callTool(e.key, "status__provider_token"), "not_connected"))
	linkReason := func(want string, granted []string, label bool) {
		t.Helper()
		var cr apitypes.ConnectRequest
		code, ec := e.member.call("GET", "/v1/connect/requests/"+stale, nil, &cr, nil)
		mustCode(t, "connect request", code, ec, 200, "")
		if string(cr.Reason) != want || !slices.Equal(cr.GrantedScopes, granted) || (cr.AccountLabel != nil) != label {
			t.Fatalf("request = %+v, want reason %s granted %v", cr, want, granted)
		}
	}
	e.connect(e.member, map[string]any{"providerId": p.Id, "scopes": []string{"read:user"}})
	linkReason("missing_scopes", []string{"read:user"}, true)

	// A repeated call reuses the link; it was made for not_connected.
	if again := requestID(e.consentURL(e.callTool(e.key, "status__provider_token"), "missing_scopes")); again != stale {
		t.Fatalf("link not reused: %s vs %s", again, stale)
	}

	// A client ID change resets connections.
	e.connect(e.member, map[string]any{"providerId": p.Id, "scopes": []string{"repo"}})
	var cur apitypes.AuthProvider
	e.admin.get(base, &cur)
	code, ec = e.admin.call("PATCH", base, map[string]any{"clientId": "another-app", "revocationUrl": nil}, &cur, ifMatch(cur.Revision))
	mustCode(t, "change client ID", code, ec, 200, "")
	if cur.RevocationUrl != nil || cur.ClientId != "another-app" || !cur.HasClientSecret {
		t.Fatalf("after update = %+v", cur)
	}
	if v := e.scalar(`SELECT status || ' ' || (access_token_cipher IS NULL)::text FROM provider_connections`); v != "needs_reconsent true" {
		t.Fatalf("connection after client change = %s", v)
	}
	// Tokens erased: the link says so, with no granted scopes (the account
	// label stays so the person knows what to reconnect).
	linkReason("needs_reconsent", []string{}, true)
	if v := e.scalar(`SELECT (metadata->>'connectionsReset') || ' ' || (metadata->>'clientSecretChanged') FROM audit_log
		WHERE action = 'auth_provider.update' ORDER BY id DESC LIMIT 1`); v != "1 false" {
		t.Fatalf("update audit = %s", v)
	}

	// Delete once no server requires it: connections are deleted with it.
	e.setRequirement(nil)
	e.admin.get(base, &cur)
	if cur.ServerCount != 0 || cur.ConnectionCount != 1 {
		t.Fatalf("counts = %+v", cur)
	}
	code, ec = e.auditor.call("DELETE", base, nil, nil, nil)
	mustCode(t, "auditor delete", code, ec, 403, "")
	code, ec = e.admin.call("DELETE", base, nil, nil, nil)
	mustCode(t, "delete", code, ec, 200, "")
	if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "0" {
		t.Fatalf("connections left: %s", n)
	}
	if v := e.scalar(`SELECT metadata->>'reason' || ' ' || (metadata->>'providerRevoked') FROM audit_log WHERE action = 'provider_connection.revoke'`); v != "provider_deleted not_supported" {
		t.Fatalf("revoke audit = %s", v)
	}
	if v := e.scalar(`SELECT metadata->>'connectionCount' FROM audit_log WHERE action = 'auth_provider.delete'`); v != "1" {
		t.Fatalf("delete audit = %s", v)
	}
	// The audit log names deleted targets from what it recorded.
	var ap apitypes.AuditPage
	if code := e.admin.get("/v1/admin/audit?targetType=auth_provider", &ap); code != 200 || len(ap.Items) == 0 {
		t.Fatalf("audit = %d", code)
	}
}

func TestConnectResponseFormatsAndAdmin(t *testing.T) {
	e := newProvEnv(t)
	blairID := e.userID("blair@localhost")

	// Form-encoded answers with comma-separated scopes (GitHub without
	// Accept), and a userinfo endpoint that fails (the label is optional).
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FormEncoded, f.FailUserinfo = true, true })
	link := e.consentURL(e.callTool(e.key, "status__provider_token"), "not_connected")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "result=connected") {
		t.Fatalf("form-encoded = %s", to)
	}
	var conns []apitypes.ProviderConnection
	if code := e.member.get("/v1/me/connections", &conns); code != 200 || len(conns) != 1 || conns[0].AccountLabel != nil ||
		!slices.Equal(conns[0].Scopes, []string{"repo"}) {
		t.Fatalf("connections = %+v", conns)
	}
	if rep := e.providerReport(e.callTool(e.key, "status__provider_token")); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}

	// Slack: user scopes in user_scope (comma-separated), the person's token
	// under authed_user (never the bot token).
	slackOAuth := testutil.NewFakeOAuth(t)
	slackOAuth.Set(func(f *testutil.FakeOAuth) { f.Slack, f.IssueRefresh, f.AccessTTL = true, false, 0 })
	slack := e.createProvider("slack", slackOAuth, map[string]any{"preset": "slack", "scopeParam": "user_scope", "scopeSeparator": ",",
		"tokenResponseFormat": "slack_authed_user", "pkce": false, "revocationUrl": nil, "userinfoUrl": nil,
		"defaultScopes": []string{"users:read", "chat:write"}})
	code, ec, st := e.start(e.member, map[string]any{"providerId": slack.Id})
	mustCode(t, "start slack", code, ec, 200, "")
	q := mustParse(t, st.AuthorizeUrl).Query()
	if q.Get("user_scope") != "users:read,chat:write" || q.Get("scope") != "" || q.Get("code_challenge") != "" {
		t.Fatalf("slack authorize = %s", st.AuthorizeUrl)
	}
	if to := callback(t, e.member, providerAuthorize(t, e.member, st.AuthorizeUrl)); to != "/connect/done?provider=slack&result=connected" {
		t.Fatalf("slack = %s", to)
	}
	e.setRequirement(map[string]any{"providerId": slack.Id, "scopes": []string{"users:read"}})
	// Connected with the scopes, but the server isn't allowed yet: the link
	// goes to the confirm step, which makes no request to the provider.
	slackLink := e.consentURLFor(e.callTool(e.key, "status__provider_token"), "server_not_allowed", "slack")
	slackAuthorizes, slackTokenReqs := slackOAuth.AuthorizeRequests(), slackOAuth.TokenRequests()
	code, ec = e.member.call("POST", "/v1/connect/requests/"+requestID(slackLink)+"/confirm", nil, nil, nil)
	mustCode(t, "allow the server", code, ec, 200, "")
	if slackOAuth.AuthorizeRequests() != slackAuthorizes || slackOAuth.TokenRequests() != slackTokenReqs {
		t.Fatal("allowing a server contacted the provider")
	}
	rep := e.providerReport(e.callTool(e.key, "status__provider_token"))
	if issued := slackOAuth.Issued(); rep.Provider != "slack" || rep.TokenSHA256 != testutil.TokenDigest(issued[0]) {
		t.Fatalf("slack report = %+v", rep)
	}
	if code := e.member.get("/v1/me/connections", &conns); code != 200 || len(conns) != 2 || conns[1].ExpiresAt != nil || conns[1].Refreshable {
		t.Fatalf("connections = %+v", conns)
	}

	// Mix-up: a code of one provider presented with another provider's
	// state goes to the state's provider, which refuses it.
	code, ec, stA := e.start(e.member, map[string]any{"providerId": e.provider.Id})
	mustCode(t, "start A", code, ec, 200, "")
	code, ec, stB := e.start(e.member, map[string]any{"providerId": slack.Id})
	mustCode(t, "start B", code, ec, 200, "")
	backB := mustParse(t, providerAuthorize(t, e.member, stB.AuthorizeUrl)).Query()
	stateA := mustParse(t, stA.AuthorizeUrl).Query().Get("state")
	slackTokens := slackOAuth.TokenRequests()
	mixed := e.app.URL + "/connect/callback?" + url.Values{"code": {backB.Get("code")}, "state": {stateA}}.Encode()
	if to := callback(t, e.member, mixed); to != "/connect/done?provider=github&result=error" || slackOAuth.TokenRequests() != slackTokens {
		t.Fatalf("mix-up = %s", to)
	}

	// An expired consent link.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"admin:org"}})
	link = e.consentURL(e.callTool(e.key, "status__provider_token"), "missing_scopes")
	e.scalar(`UPDATE provider_connect_requests SET expires_at = now() - interval '1 second' RETURNING 'x'`)
	code, ec = e.member.call("GET", "/v1/connect/requests/"+requestID(link), nil, nil, nil)
	mustCode(t, "expired request", code, ec, 410, "connect_request_expired")
	code, ec, _ = e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)})
	mustCode(t, "start with an expired request", code, ec, 410, "connect_request_expired")
	// A fresh call makes a fresh link; at most 20 open per person.
	for i := 0; i < 22; i++ {
		e.scalar(`INSERT INTO provider_connect_requests (id_digest, id_cipher, user_id, provider_id, required_scopes, reason, gateway_id,
			gateway_slug, gateway_name, capability_id, capability_kind, exposed_name, expires_at)
			VALUES (substr(md5(random()::text) || md5(random()::text), 1, 43), '\x00', $1, $2, '{x}', 'not_connected', gen_random_uuid(),
			'g', 'G', gen_random_uuid(), 'tool', 't', now() + interval '5 minutes') RETURNING 'x'`, blairID, e.provider.Id)
	}
	e.consentURL(e.callTool(e.key, "status__provider_token"), "missing_scopes")
	if n := e.scalar(`SELECT count(*)::text FROM provider_connect_requests WHERE user_id = $1 AND used_at IS NULL AND expires_at > now()`, blairID); n != "20" {
		t.Fatalf("open requests = %s", n)
	}

	// Admins see metadata and disconnect; auditors only read.
	var adminConns []apitypes.ProviderConnection
	if code := e.auditor.get("/v1/admin/users/"+blairID+"/connections", &adminConns); code != 200 || len(adminConns) != 2 {
		t.Fatalf("admin list = %d %d", code, len(adminConns))
	}
	code, ec = e.auditor.call("DELETE", "/v1/admin/users/"+blairID+"/connections/"+adminConns[0].Id.String(), nil, nil, nil)
	mustCode(t, "auditor revoke", code, ec, 403, "")
	code, ec = e.admin.call("DELETE", "/v1/admin/users/"+e.userID("alex@localhost")+"/connections/"+adminConns[0].Id.String(), nil, nil, nil)
	mustCode(t, "revoke through another person", code, ec, 404, "connection_not_found")
	code, ec = e.admin.call("DELETE", "/v1/admin/users/"+blairID+"/connections/"+adminConns[0].Id.String(), nil, nil, nil)
	mustCode(t, "admin revoke", code, ec, 200, "")
	if v := e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action = 'provider_connection.revoke' AND target_id = $1`, adminConns[0].Id.String()); v != "admin" {
		t.Fatalf("revoke reason = %s", v)
	}
	code, ec = e.admin.call("GET", "/v1/admin/users/00000000-0000-0000-0000-000000000001/connections", nil, nil, nil)
	mustCode(t, "unknown user", code, ec, 404, "user_not_found")
	// The audit log labels connections "person · provider".
	var ap apitypes.AuditPage
	if code := e.admin.get("/v1/admin/audit?action=provider_connection.create", &ap); code != 200 || len(ap.Items) == 0 ||
		ap.Items[0].TargetLabel == nil || !ap.Items[0].TargetExists || !strings.Contains(*ap.Items[0].TargetLabel, " · ") {
		t.Fatalf("audit = %d %+v", code, ap.Items)
	}
}

func TestRequirementReview(t *testing.T) {
	e := newProvEnv(t)
	e.publish(e.owner, e.server)
	state := func() string {
		var sv apitypes.McpServer
		e.owner.get(e.serverPath(), &sv)
		return string(sv.PublishState)
	}
	reviews := func() string {
		return e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.publish_request' AND metadata->>'reason' = 'requirement_changed'`)
	}
	approve := func() {
		code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(t, e.admin, e.server.Id.String()), nil, nil)
		mustCode(t, "approve", code, ec, 200, "")
	}
	if state() != "published" {
		t.Fatalf("state = %s", state())
	}
	// Narrowing (fewer scopes, then none) never needs review.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}})
	if state() != "published" || reviews() != "0" {
		t.Fatalf("same requirement: %s %s", state(), reviews())
	}
	code, ec := e.override("echo", map[string]any{"mode": "none"})
	mustCode(t, "override none", code, ec, 200, "")
	if state() != "published" {
		t.Fatalf("narrowing override: %s", state())
	}
	// Widening: another scope.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo", "admin:org"}})
	if state() != "pending" || reviews() != "1" {
		t.Fatalf("wider scopes: %s %s", state(), reviews())
	}
	approve()
	// Widening through an override.
	code, ec = e.override("whoami", map[string]any{"mode": "scopes", "scopes": []string{"delete_repo"}})
	mustCode(t, "wider override", code, ec, 200, "")
	if state() != "pending" || reviews() != "2" {
		t.Fatalf("wider override: %s %s", state(), reviews())
	}
	approve()
	// Bad overrides.
	code, ec = e.override("whoami", map[string]any{"mode": "none", "scopes": []string{"x"}})
	mustCode(t, "scopes with none", code, ec, 400, "invalid_mode")
	code, ec = e.override("whoami", map[string]any{"mode": "scopes"})
	mustCode(t, "scopes mode without scopes", code, ec, 400, "invalid_mode")
	var cur apitypes.McpServer
	e.owner.get(e.serverPath(), &cur)
	code, ec = e.owner.call("PUT", e.serverPath()+"/capabilities/"+e.capID(e.owner, e.server, "tool", "whoami")+"/requirement",
		map[string]any{"mode": "inherit"}, nil, ifMatch(cur.Revision-1))
	mustCode(t, "stale revision", code, ec, 412, "")
	code, ec = e.member.call("PUT", e.serverPath()+"/capabilities/"+e.capID(e.owner, e.server, "tool", "whoami")+"/requirement",
		map[string]any{"mode": "inherit"}, nil, ifMatch(cur.Revision))
	mustCode(t, "member override", code, ec, 403, "")

	// Removing the requirement resets scope overrides (and narrows: no review).
	e.setRequirement(nil)
	var caps []apitypes.McpCapability
	e.owner.get(e.serverPath()+"/capabilities", &caps)
	for _, c := range caps {
		if c.Name == "whoami" && (c.RequirementOverride.Mode != "inherit" || c.Requires != nil) {
			t.Fatalf("whoami after removal = %+v", c.RequirementOverride)
		}
		if c.Name == "echo" && c.RequirementOverride.Mode != "none" {
			t.Fatalf("echo after removal = %+v", c.RequirementOverride)
		}
	}
	if state() != "published" {
		t.Fatalf("removal: %s", state())
	}
	code, ec = e.override("whoami", map[string]any{"mode": "scopes", "scopes": []string{"x"}})
	mustCode(t, "scopes without a server requirement", code, ec, 409, "no_server_requirement")
	// A provider where there was none widens.
	e.setRequirement(map[string]any{"providerId": e.provider.Id})
	if state() != "pending" || reviews() != "3" {
		t.Fatalf("new provider: %s %s", state(), reviews())
	}
	approve()
	// Default scopes apply when none are given; the catalog and options show it.
	e.owner.get(e.serverPath()+"/capabilities", &caps)
	for _, c := range caps {
		if c.Name == "whoami" && (c.Requires == nil || !slices.Equal(c.Requires.Scopes, []string{"read:user"})) {
			t.Fatalf("whoami requires = %+v", c.Requires)
		}
	}
	var cat apitypes.CatalogServerDetail
	if code := e.outsider.get("/v1/catalog/servers/"+e.server.Id.String(), &cat); code != 200 {
		t.Fatalf("catalog = %d", code)
	}
	for _, c := range cat.Capabilities {
		if (c.Name == "whoami") != (c.Requires != nil) && c.Name != "provider_token" && c.Name != "check_outage" && c.Name != "search_tickets" &&
			c.Name != "create_ticket" && c.Kind == "tool" && c.Name != "echo" {
			t.Errorf("catalog %s requires = %+v", c.Name, c.Requires)
		}
		if c.Name == "echo" && c.Requires != nil {
			t.Errorf("catalog echo requires = %+v", c.Requires)
		}
	}

	// Under self_publish the server stays published.
	var tp apitypes.TeamPublishing
	e.admin.get("/v1/admin/teams/tools/publishing", &tp)
	code, ec = e.admin.call("PUT", "/v1/admin/teams/tools/publishing", map[string]any{"override": "self_publish"}, nil, ifMatch(tp.Revision))
	mustCode(t, "self publish", code, ec, 200, "")
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"everything"}})
	if state() != "published" {
		t.Fatalf("self_publish: %s", state())
	}
}
