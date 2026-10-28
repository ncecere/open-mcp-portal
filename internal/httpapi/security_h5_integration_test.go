package httpapi_test

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// H-5 (docs/threat-model.md, decision 69, issue #27): a platform admin
// restricts a provider to named teams and servers; a new provider starts
// restricted with nobody listed and an existing one stays open. The list is
// checked when a requirement is saved, when a person allows a server, and on
// every call (an agent's relayed call too). With narrowing on, a call carries
// a token refreshed with only the scopes it needs.

func (e *provEnv) teamID(slug string) string {
	e.t.Helper()
	return e.scalar(`SELECT id::text FROM teams WHERE slug = $1`, slug)
}

func (e *provEnv) getAccess(s *session, p apitypes.AuthProvider) (int, apitypes.AuthProviderAccess) {
	e.t.Helper()
	var ac apitypes.AuthProviderAccess
	code := s.get(providersBase+"/"+p.Id.String()+"/access", &ac)
	return code, ac
}

// putAccess replaces a provider's access list and returns the status and error code.
func (e *provEnv) putAccess(s *session, p apitypes.AuthProvider, mode string, teams, servers []string, rev int64) (int, string) {
	e.t.Helper()
	return s.call("PUT", providersBase+"/"+p.Id.String()+"/access",
		map[string]any{"accessMode": mode, "teamIds": nonNilIDs(teams), "serverIds": nonNilIDs(servers)}, nil, ifMatch(rev))
}

// requirementCode sets a server's requirement as s and returns the status and error code.
func (e *provEnv) requirementCode(s *session, sv apitypes.McpServer, p apitypes.AuthProvider, scopes ...string) (int, string) {
	e.t.Helper()
	path := "/v1/teams/" + sv.TeamSlug + "/mcp-servers/" + sv.Id.String()
	var cur apitypes.McpServer
	if code := s.get(path, &cur); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	return s.call("PATCH", path, map[string]any{"requirement": map[string]any{"providerId": p.Id, "scopes": scopes}}, nil, ifMatch(cur.Revision))
}

func (e *provEnv) pickable(s *session, query string) []string {
	e.t.Helper()
	var list []apitypes.AuthProviderSummary
	if code := s.get("/v1/auth-providers"+query, &list); code != 200 {
		e.t.Fatalf("auth providers%s = %d", query, code)
	}
	out := []string{}
	for _, p := range list {
		out = append(out, p.Slug)
	}
	return out
}

func TestProviderAccessListGatesRequirements(t *testing.T) {
	e := newProvEnv(t)
	tools, other := e.teamID("tools"), e.teamID("other")

	// A provider created through the API starts restricted, nobody listed,
	// narrowing off; the one the fixture opened is open.
	jira := e.createRestrictedProvider("jira", testutil.NewFakeOAuth(t), nil)
	if jira.AccessMode != "restricted" || jira.NarrowOnRefresh || e.provider.AccessMode != "open" {
		t.Fatalf("modes: jira %q narrow %v, github %q", jira.AccessMode, jira.NarrowOnRefresh, e.provider.AccessMode)
	}
	code, ac := e.getAccess(e.admin, jira)
	if code != 200 || ac.AccessMode != "restricted" || len(ac.Teams) != 0 || len(ac.Servers) != 0 || ac.BlockedCount != 0 || ac.Revision != jira.Revision {
		t.Fatalf("access = %d %+v", code, ac)
	}
	if code, _ := e.getAccess(e.auditor, jira); code != 200 {
		t.Fatalf("an auditor reads the list: %d", code)
	}

	// Nobody may require it yet: a new server and a changed one are refused (422).
	body := map[string]any{"slug": "wiki", "name": "Wiki", "url": e.otherFake.URL(),
		"requirement": map[string]any{"providerId": jira.Id, "scopes": []string{}}}
	if code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers", body, nil, nil); code != 422 || ec != "provider_not_allowed" {
		t.Fatalf("create with a restricted provider = %d %s", code, ec)
	}
	if n := e.scalar(`SELECT count(*)::text FROM mcp_servers WHERE slug = 'wiki'`); n != "0" {
		t.Fatalf("the refused server was created (%s)", n)
	}
	if code, ec := e.requirementCode(e.owner, e.server, jira); code != 422 || ec != "provider_not_allowed" {
		t.Fatalf("patch with a restricted provider = %d %s", code, ec)
	}

	// The picker leaves it out for the team; without a team every provider is listed (connecting is not limited).
	if got := e.pickable(e.owner, "?team=tools"); slices.Contains(got, "jira") || !slices.Contains(got, "github") {
		t.Fatalf("picker for tools = %v", got)
	}
	if got := e.pickable(e.owner, ""); !slices.Contains(got, "jira") || !slices.Contains(got, "github") {
		t.Fatalf("unfiltered list = %v", got)
	}
	if code := e.outsider.get("/v1/auth-providers?team=tools", nil); code != 404 {
		t.Fatalf("a team the caller cannot see = %d", code)
	}

	// Only platform admins change the list, with the provider's revision.
	for who, s := range map[string]*session{"owner": e.owner, "auditor": e.auditor, "member": e.member} {
		if code, _ := e.putAccess(s, jira, "restricted", []string{tools}, nil, jira.Revision); code != 403 {
			t.Fatalf("%s changed the list: %d", who, code)
		}
	}
	if code, ec := e.putAccess(e.admin, jira, "restricted", []string{tools}, nil, jira.Revision+7); code != 412 {
		t.Fatalf("stale revision = %d %s", code, ec)
	}
	if code, ec := e.putAccess(e.admin, jira, "restricted", []string{"00000000-0000-4000-8000-000000000001"}, nil, jira.Revision); code != 422 || ec != "team_not_found" {
		t.Fatalf("unknown team = %d %s", code, ec)
	}
	if code, ec := e.putAccess(e.admin, jira, "restricted", nil, []string{"00000000-0000-4000-8000-000000000001"}, jira.Revision); code != 422 || ec != "server_not_found" {
		t.Fatalf("unknown server = %d %s", code, ec)
	}
	if code, ec := e.putAccess(e.admin, jira, "sometimes", nil, nil, jira.Revision); code != 400 || ec != "invalid_access_mode" {
		t.Fatalf("bad mode = %d %s", code, ec)
	}

	// Listing the team opens it to the team's servers and no other team's.
	jira = e.setAccess(jira, "restricted", []string{tools}, nil)
	if code, ec := e.requirementCode(e.owner, e.server, jira, "read"); code != 200 {
		t.Fatalf("patch with a listed team = %d %s", code, ec)
	}
	if code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers", body, nil, nil); code != 201 {
		t.Fatalf("create with a listed team = %d %s", code, ec)
	}
	if code, ec := e.requirementCode(e.outsider, e.other, jira); code != 422 || ec != "provider_not_allowed" {
		t.Fatalf("another team = %d %s", code, ec)
	}
	if got := e.pickable(e.owner, "?team=tools"); !slices.Contains(got, "jira") {
		t.Fatalf("picker for the listed team = %v", got)
	}
	if got := e.pickable(e.outsider, "?team=other"); slices.Contains(got, "jira") {
		t.Fatalf("picker for another team = %v", got)
	}

	// Listing one server opens it to that server alone.
	jira = e.setAccess(jira, "restricted", []string{tools}, []string{e.other.Id.String()})
	if got := e.pickable(e.outsider, "?team=other"); slices.Contains(got, "jira") {
		t.Fatalf("picker without the server = %v", got)
	}
	if got := e.pickable(e.outsider, "?team=other&serverId="+e.other.Id.String()); !slices.Contains(got, "jira") {
		t.Fatalf("picker with the listed server = %v", got)
	}
	if code, ec := e.requirementCode(e.outsider, e.other, jira); code != 200 {
		t.Fatalf("patch with a listed server = %d %s", code, ec)
	}
	if code, ac := e.getAccess(e.admin, jira); code != 200 || len(ac.Teams) != 1 || ac.Teams[0].Slug != "tools" || len(ac.Servers) != 1 ||
		ac.Servers[0].Slug != "other-status" || ac.Servers[0].TeamSlug != "other" || ac.BlockedCount != 0 {
		t.Fatalf("access = %d %+v", code, ac)
	}

	// Taking a team off the list leaves the requirement but shows what is blocked now.
	jira = e.setAccess(jira, "restricted", []string{other}, nil)
	code, ac = e.getAccess(e.admin, jira)
	if code != 200 || ac.BlockedCount != 2 || len(ac.Blocked) != 2 || ac.Blocked[0].TeamSlug != "other" && ac.Blocked[0].TeamSlug != "tools" {
		t.Fatalf("blocked = %d %+v", code, ac)
	}
	// An edit that keeps the provider is not blocked by it; a widening to another provider is judged by that one.
	if code, ec := e.requirementCode(e.owner, e.server, jira, "read"); code != 200 {
		t.Fatalf("keeping a provider the list no longer names = %d %s", code, ec)
	}
	// Open: lists are kept but not consulted.
	jira = e.setAccess(jira, "open", []string{other}, nil)
	if code, ac := e.getAccess(e.admin, jira); code != 200 || ac.AccessMode != "open" || ac.BlockedCount != 0 || len(ac.Teams) != 1 {
		t.Fatalf("open = %d %+v", code, ac)
	}

	// Audited with the list before and after, and no secret anywhere.
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'auth_provider.access_update' AND target_id = $1`, jira.Id.String()); n != "4" {
		t.Fatalf("access_update audits = %s", n)
	}
	if v := e.scalar(`SELECT (before_state->>'accessMode') || ' ' || (after_state->>'accessMode') || ' ' || jsonb_array_length(before_state->'teams')::text || ' ' ||
		(after_state->'teams'->0->>'slug') FROM audit_log WHERE action = 'auth_provider.access_update' AND target_id = $1 ORDER BY id DESC LIMIT 1`,
		jira.Id.String()); v != "restricted open 1 other" {
		t.Fatalf("last access_update audit = %q", v)
	}
	e.noSecretsAnywhere()
}

// Removing a team (or turning the list on) ends delivery on the next call:
// -32010 provider_not_allowed, recorded denied, no consent link, nothing sent
// to the server; listing the team (or the server) restores it.
func TestProviderAccessListIsCheckedOnEveryCall(t *testing.T) {
	e := newProvEnv(t)
	tools := e.teamID("tools")
	connected := func() bool {
		var detail apitypes.MyGatewayDetail
		if code := e.member.get("/v1/me/gateways/"+e.gateway.Id.String(), &detail); code != 200 {
			t.Fatalf("my gateway = %d", code)
		}
		for _, c := range detail.Capabilities {
			if c.Name == "provider_token" && c.Requires != nil && c.Requires.Connected != nil {
				return *c.Requires.Connected
			}
		}
		t.Fatal("no requirement on provider_token")
		return false
	}

	// Connect, allow the server, and the call carries the token.
	link := e.consentURL(e.callTool(e.key, f3Tool), "not_connected")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}
	if !connected() {
		t.Fatal("the capability is not shown as ready")
	}
	delivered, requests := e.toolCalls("provider_token"), e.connectRequests()

	denied := func(what string) {
		t.Helper()
		out := e.callTool(e.key, f3Tool)
		if c, msg, data := rpcErr(out); c != -32010 || data["reason"] != "provider_not_allowed" || data["provider"] != "github" ||
			!strings.Contains(msg, "access list") {
			t.Fatalf("%s: %v", what, out)
		}
		noLink(t, out, what)
		if last := e.scalar(`SELECT outcome || ' ' || error_class || ' ' || provider_slug FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "denied provider_not_allowed github" {
			t.Fatalf("%s: recorded %q", what, last)
		}
		if e.toolCalls("provider_token") != delivered || e.connectRequests() != requests {
			t.Fatalf("%s: the server was called or a consent request stored", what)
		}
		if connected() {
			t.Fatalf("%s: My gateways still shows the capability as ready", what)
		}
	}

	// Restricted with nobody listed: refused at once, with the grant and the connection untouched.
	e.provider = e.setAccess(e.provider, "restricted", nil, nil)
	denied("restricted, empty")
	if n := e.grantCount(e.server.Id.String()); n != "1" {
		t.Fatalf("grants = %s (the person's allowance is not the admin's to erase)", n)
	}
	// Listing the team restores delivery with the same token; removing it ends it again.
	e.provider = e.setAccess(e.provider, "restricted", []string{tools}, nil)
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report with the team listed = %+v", rep)
	}
	delivered = e.toolCalls("provider_token")
	if !connected() {
		t.Fatal("not ready with the team listed")
	}
	e.provider = e.setAccess(e.provider, "restricted", []string{e.teamID("other")}, nil)
	denied("another team listed")
	// Listing the server alone is enough.
	e.provider = e.setAccess(e.provider, "restricted", nil, []string{e.server.Id.String()})
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report with the server listed = %+v", rep)
	}
	delivered = e.toolCalls("provider_token")
	// Open again.
	e.provider = e.setAccess(e.provider, "open", nil, nil)
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report when open = %+v", rep)
	}
	e.noSecretsAnywhere()
}

// A person cannot allow a server the provider's list excludes, by My
// connections, a consent link's confirm step or the consent callback; such a
// server is not offered for allowing.
func TestProviderAccessListGatesAllowingAServer(t *testing.T) {
	e := newProvEnv(t)
	e.connectBroadly("repo")
	conn := e.myConnID()
	if got := e.allowableSlugs(conn); !slices.Equal(got, []string{"status"}) {
		t.Fatalf("allowable = %v", got)
	}
	st := findAllowable(t, e.allowable(e.member, conn), "status")

	// My connections.
	e.provider = e.setAccess(e.provider, "restricted", nil, nil)
	if got := e.allowableSlugs(conn); len(got) != 0 {
		t.Fatalf("allowable under a restricted provider = %v", got)
	}
	if code, ec, _ := e.allowCall(e.member, conn, allowBody(st)); code != 422 || ec != "provider_not_allowed" {
		t.Fatalf("allow = %d %s", code, ec)
	}
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("grants = %s", n)
	}
	e.provider = e.setAccess(e.provider, "restricted", []string{e.teamID("tools")}, nil)
	if got := e.allowableSlugs(conn); !slices.Equal(got, []string{"status"}) {
		t.Fatalf("allowable with the team listed = %v", got)
	}

	// A consent link made while the server could use the provider.
	link := e.consentURL(e.callTool(e.key, f3Tool), "server_not_allowed")
	e.provider = e.setAccess(e.provider, "restricted", nil, nil)
	if code, ec := e.confirmCode(e.member, link); code != 422 || ec != "provider_not_allowed" {
		t.Fatalf("confirm = %d %s", code, ec)
	}
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("grants after confirm = %s", n)
	}

	// The callback after a connect: the account is connected, nothing is allowed, and the page says why.
	e.provider = e.setAccess(e.provider, "open", nil, nil)
	if code, ec := e.member.call("DELETE", "/v1/me/connections/"+conn, nil, nil, nil); code != 200 {
		t.Fatalf("disconnect = %d %s", code, ec)
	}
	link = e.consentURL(e.callTool(e.key, f3Tool), "not_connected")
	e.provider = e.setAccess(e.provider, "restricted", nil, nil)
	to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)})
	if !strings.Contains(to, "result=not_allowed") {
		t.Fatalf("connect with a restricted provider = %s", to)
	}
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("grants after the callback = %s", n)
	}
	if st := e.scalar(`SELECT status FROM provider_connections WHERE user_id = $1`, e.userID("blair@localhost")); st != "active" {
		t.Fatalf("the connection = %s", st)
	}
	e.noSecretsAnywhere()
}

// An agent's relayed call honours the list as a person's own does (decisions
// 66 and 68): the server's tool is refused, no link is made, and listing the
// team restores it.

// With narrowing on, a call carries a token refreshed with only the scopes it
// needs (verified at the fake provider: introspection); the stored token and
// the connection keep everything granted, the narrowed token is cached in
// memory per scope set, a rotated refresh token is stored, and nothing reaches
// the stored data, the audit log or the logs.
func TestNarrowOnRefreshSendsOnlyTheScopesTheCallNeeds(t *testing.T) {
	e := newProvEnv(t)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true })
	second := testutil.NewFakeMCP(t)
	second.EnableGatewayTools()
	e.addServer("second", second, "read:user")
	// A person who granted more than any one server asks for.
	e.connectBroadly("repo", "read:user", "write")
	conn := e.myConnID()
	e.mustAllow(conn, findAllowable(t, e.allowable(e.member, conn), "status"))
	e.mustAllow(conn, findAllowable(t, e.allowable(e.member, conn), "second"))

	token := func(fake *testutil.FakeMCP) string {
		t.Helper()
		calls := fake.ToolCalls()
		return calls[len(calls)-1].Header.Get("MCP-Gateway-Provider-Token")
	}

	// Narrowing off (the default): the server gets the stored token with every granted scope.
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}
	full := e.oauth.Introspect(token(e.fake))
	if !full.Active || !slices.Equal(sortedCopy(full.Scopes), []string{"read:user", "repo", "write"}) {
		t.Fatalf("without narrowing the server's token has %+v", full)
	}
	if got := e.oauth.RefreshScopes(); len(got) != 0 {
		t.Fatalf("refreshes without narrowing = %v", got)
	}
	var conns []apitypes.ProviderConnection
	e.member.get("/v1/me/connections", &conns)
	if conns[0].NarrowsScopes || !conns[0].Refreshable {
		t.Fatalf("connection = %+v", conns[0])
	}

	// Narrowing on.
	var cur apitypes.AuthProvider
	e.admin.get(providersBase+"/"+e.provider.Id.String(), &cur)
	if code, ec := e.admin.call("PATCH", providersBase+"/"+e.provider.Id.String(), map[string]any{"narrowOnRefresh": true}, &cur, ifMatch(cur.Revision)); code != 200 || !cur.NarrowOnRefresh {
		t.Fatalf("turn narrowing on = %d %s %+v", code, ec, cur)
	}
	e.provider = cur
	e.member.get("/v1/me/connections", &conns)
	if !conns[0].NarrowsScopes {
		t.Fatalf("the connection does not say it narrows: %+v", conns[0])
	}
	storedBefore := e.scalar(`SELECT encode(access_token_cipher, 'hex') FROM provider_connections WHERE id = $1`, conn)

	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}
	got := e.oauth.Introspect(token(e.fake))
	if !got.Active || !slices.Equal(got.Scopes, []string{"repo"}) || token(e.fake) == "" {
		t.Fatalf("the server's token has %+v, want repo alone", got)
	}
	if rs := e.oauth.RefreshScopes(); !slices.Equal(rs, []string{"repo"}) {
		t.Fatalf("refresh scopes = %v", rs)
	}
	// The stored token and the granted scopes are untouched.
	if e.scalar(`SELECT encode(access_token_cipher, 'hex') FROM provider_connections WHERE id = $1`, conn) != storedBefore {
		t.Fatal("a narrowed refresh replaced the stored access token")
	}
	if sc := e.scalar(`SELECT array_to_string(scopes, ' ') FROM provider_connections WHERE id = $1`, conn); sc != "repo read:user write" {
		t.Fatalf("granted scopes = %q", sc)
	}

	// The same scopes again: the cached token, no provider round trip.
	refreshes := e.oauth.RefreshRequests()
	first := token(e.fake)
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received || token(e.fake) != first {
		t.Fatalf("second call = %+v", rep)
	}
	if e.oauth.RefreshRequests() != refreshes {
		t.Fatal("a cached narrowed token was refreshed again")
	}

	// Another server asks for another scope: its own token, narrowed to that; the
	// rotated refresh token (the fake retires the old one) was stored, or this fails.
	out := e.callTool(e.key, "second__provider_token")
	if rep := e.providerReport(out); !rep.Received {
		t.Fatalf("second server = %v", out)
	}
	if got := e.oauth.Introspect(token(second)); !got.Active || !slices.Equal(got.Scopes, []string{"read:user"}) {
		t.Fatalf("the second server's token has %+v", got)
	}
	if rs := e.oauth.RefreshScopes(); !slices.Equal(rs, []string{"repo", "read:user"}) {
		t.Fatalf("refresh scopes = %v", rs)
	}
	if token(second) == first {
		t.Fatal("two scope sets share a token")
	}

	// A provider that ignores scope on refresh returns its full token: nothing is narrowed there.
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = false })
	e.oauth.InvalidateAll(false)
	e.scalar(`UPDATE provider_connections SET connected_at = connected_at + interval '1 second' WHERE id = $1 RETURNING 'x'`, conn) // another consent: no cached token
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("ignoring provider = %+v", rep)
	}
	if got := e.oauth.Introspect(token(e.fake)); !got.Active || len(got.Scopes) != 3 {
		t.Fatalf("a provider that ignores scope returned %+v", got)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope = true })

	// A provider that is down: refused, nothing forwarded, the connection kept; one that refused the grant: asked again.
	e.scalar(`UPDATE provider_connections SET connected_at = connected_at + interval '1 second' WHERE id = $1 RETURNING 'x'`, conn)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "unavailable" })
	calls := e.toolCalls("provider_token")
	if c, _, data := rpcErr(e.callTool(e.key, f3Tool)); c != -32010 || data["reason"] != "provider_unavailable" || e.toolCalls("provider_token") != calls {
		t.Fatalf("outage: %v", data)
	}
	if st := e.scalar(`SELECT status FROM provider_connections WHERE id = $1`, conn); st != "active" {
		t.Fatalf("status after an outage = %s", st)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "invalid_grant" })
	e.consentURL(e.callTool(e.key, f3Tool), "needs_reconsent")
	if st := e.scalar(`SELECT status FROM provider_connections WHERE id = $1`, conn); st != "needs_reconsent" {
		t.Fatalf("status after a refused grant = %s", st)
	}

	// The audit log, call records, stored rows and logs hold no token.
	e.noSecretsAnywhere()
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

// Narrowing a connection that holds no refresh token is not possible: the
// stored token is sent, as before, and My connections says so.
func TestNarrowOnRefreshNeedsARefreshToken(t *testing.T) {
	e := newProvEnv(t)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.HonourRefreshScope, f.IssueRefresh = true, false })
	var cur apitypes.AuthProvider
	e.admin.get(providersBase+"/"+e.provider.Id.String(), &cur)
	if code, ec := e.admin.call("PATCH", providersBase+"/"+e.provider.Id.String(), map[string]any{"narrowOnRefresh": true}, &cur, ifMatch(cur.Revision)); code != http.StatusOK {
		t.Fatalf("patch = %d %s", code, ec)
	}
	e.connectBroadly("repo", "read:user")
	conn := e.myConnID()
	e.mustAllow(conn, findAllowable(t, e.allowable(e.member, conn), "status"))
	if rep := e.providerReport(e.callTool(e.key, f3Tool)); !rep.Received {
		t.Fatalf("report = %+v", rep)
	}
	calls := e.fake.ToolCalls()
	got := e.oauth.Introspect(calls[len(calls)-1].Header.Get("MCP-Gateway-Provider-Token"))
	if !got.Active || len(got.Scopes) != 2 {
		t.Fatalf("token = %+v", got)
	}
	var conns []apitypes.ProviderConnection
	e.member.get("/v1/me/connections", &conns)
	if conns[0].NarrowsScopes || conns[0].Refreshable || len(e.oauth.RefreshScopes()) != 0 {
		t.Fatalf("connection = %+v, refreshes %v", conns[0], e.oauth.RefreshScopes())
	}
}
