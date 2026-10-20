package httpapi_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// A person allows a server to use a connected account from Account › My
// connections, without a call or a consent link (decision 68, #60): the
// same grant the link's confirm step records, for the server's address now
// and the scopes it requires, only for servers the person may use through a
// gateway and that require the connection's provider.

// myConnID is blair's connection to the provider.
func (e *provEnv) myConnID() string {
	e.t.Helper()
	var conns []apitypes.ProviderConnection
	if code := e.member.get("/v1/me/connections", &conns); code != 200 {
		e.t.Fatalf("connections = %d", code)
	}
	for _, c := range conns {
		if c.Provider.Slug == e.provider.Slug {
			return c.Id.String()
		}
	}
	e.t.Fatal("blair has no connection to the provider")
	return ""
}

func (e *provEnv) allowable(s *session, connID string) []apitypes.AllowableServer {
	e.t.Helper()
	var out []apitypes.AllowableServer
	if code := s.get("/v1/me/connections/"+connID+"/allowable-servers", &out); code != 200 {
		e.t.Fatalf("allowable servers = %d", code)
	}
	return out
}

// allowableSlugs are the servers listed, by name.
func (e *provEnv) allowableSlugs(connID string) []string {
	e.t.Helper()
	out := []string{}
	for _, a := range e.allowable(e.member, connID) {
		out = append(out, a.Server.Slug)
	}
	return out
}

func findAllowable(t *testing.T, list []apitypes.AllowableServer, slug string) apitypes.AllowableServer {
	t.Helper()
	for _, a := range list {
		if a.Server.Slug == slug {
			return a
		}
	}
	t.Fatalf("%s isn't listed: %+v", slug, list)
	return apitypes.AllowableServer{}
}

// allowBody is what the page sends for a listed server.
func allowBody(a apitypes.AllowableServer) map[string]any {
	return map[string]any{"serverId": a.Server.Id, "origin": a.Origin, "scopes": a.Scopes}
}

func (e *provEnv) allowCall(s *session, connID string, body map[string]any) (int, string, map[string]any) {
	e.t.Helper()
	code, raw := s.raw("POST", "/v1/me/connections/"+connID+"/allow-server", body, nil)
	var env struct {
		Error struct {
			Code    string
			Details map[string]any
		}
	}
	_ = json.Unmarshal(raw, &env)
	return code, env.Error.Code, env.Error.Details
}

func (e *provEnv) mustAllow(connID string, a apitypes.AllowableServer) apitypes.ConnectConfirmed {
	e.t.Helper()
	var out apitypes.ConnectConfirmed
	code, ec := e.member.call("POST", "/v1/me/connections/"+connID+"/allow-server", allowBody(a), &out, nil)
	mustCode(e.t, "allow "+a.Server.Slug, code, ec, 200, "")
	return out
}

func TestAllowServerFromMyConnections(t *testing.T) {
	e := newProvEnv(t)
	second := testutil.NewFakeMCP(t)
	second.EnableGatewayTools()
	b := e.addServer("second", second, "repo")
	e.connectBroadly("repo")
	conn := e.myConnID()
	authorizes, tokenReqs, tokens := e.oauth.AuthorizeRequests(), e.oauth.TokenRequests(), len(e.oauth.Issued())

	// Listed with the name, the team, the address and the scopes it asks; the
	// account already covers them; nothing is allowed yet.
	list := e.allowable(e.member, conn)
	if len(list) != 2 || list[0].Server.Slug != "second" || list[1].Server.Slug != "status" {
		t.Fatalf("list = %+v", list)
	}
	st := findAllowable(t, list, "status")
	if st.Server.Name != "STATUS" || st.Server.TeamSlug != "tools" || st.Server.TeamName != "TOOLS" || st.Origin != originOfURL(e.fake.URL()) ||
		!slices.Equal(st.Scopes, []string{"repo"}) || !st.Covered || st.Allowed {
		t.Fatalf("status = %+v", st)
	}
	if len(e.myGrants()) != 0 {
		t.Fatal("a grant exists before anyone allowed")
	}

	// Without making a call: the grant is recorded, the provider isn't contacted.
	c := e.mustAllow(conn, st)
	if c.Server.Slug != "status" || !slices.Equal(c.Scopes, []string{"repo"}) || c.Provider.Slug != "github" {
		t.Fatalf("allowed = %+v", c)
	}
	if e.oauth.AuthorizeRequests() != authorizes || e.oauth.TokenRequests() != tokenReqs || len(e.oauth.Issued()) != tokens {
		t.Fatal("the provider was contacted")
	}
	if e.scalar(`SELECT count(*)::text FROM provider_connect_requests`) != "0" {
		t.Fatal("a consent request was stored")
	}
	if g := e.myGrants(); len(g) != 1 || g[0].Server.Slug != "status" || g[0].Origin != originOfURL(e.fake.URL()) || !slices.Equal(g[0].Scopes, []string{"repo"}) {
		t.Fatalf("grants = %+v", g)
	}
	// The list now says so, and allowing again changes nothing.
	if st = findAllowable(t, e.allowable(e.member, conn), "status"); !st.Allowed {
		t.Fatalf("status after allowing = %+v", st)
	}
	e.mustAllow(conn, st)
	if n := e.grantCount(e.server.Id.String()); n != "1" {
		t.Fatalf("%s grants of the server", n)
	}
	// A call of their own now goes through with their token, no link.
	rep := e.providerReport(e.callTool(e.key, f3Tool))
	issued := e.oauth.Issued()
	if !rep.Received || rep.TokenSHA256 != testutil.TokenDigest(issued[len(issued)-1]) {
		t.Fatalf("report = %+v", rep)
	}
	// The other server isn't allowed by that.
	e.consentURL(e.callTool(e.key, "second__provider_token"), "server_not_allowed")

	// The grant is the link's: for the second server, allow through its link
	// and compare the rows (origin and scopes), and the audit entries (only
	// viaRequest differs).
	e.allow(e.consentURL(e.callTool(e.key, "second__provider_token"), "server_not_allowed"))
	row := func(serverID string) string {
		return e.scalar(`SELECT origin || ' ' || scopes::text FROM provider_server_grants WHERE server_id = $1`, serverID)
	}
	if got, want := row(e.server.Id.String()), originOfURL(e.fake.URL())+" {repo}"; got != want {
		t.Fatalf("grant of status = %q, want %q", got, want)
	}
	if got, want := row(b.Id.String()), originOfURL(second.URL())+" {repo}"; got != want {
		t.Fatalf("grant of second = %q, want %q", got, want)
	}
	audit := func(server string) string {
		return e.scalar(`SELECT metadata->>'server' || ' ' || (metadata->>'origin') || ' ' || (metadata->'scopes')::text || ' ' || (metadata->>'viaRequest') || ' ' || actor_kind
			FROM audit_log WHERE action = 'provider_connection.server_allow' AND metadata->>'server' = $1 ORDER BY id DESC LIMIT 1`, server)
	}
	if got, want := audit("STATUS"), "STATUS "+originOfURL(e.fake.URL())+` ["repo"] false user`; got != want {
		t.Fatalf("audit of the allow = %q, want %q", got, want)
	}
	if got, want := audit("SECOND"), "SECOND "+originOfURL(second.URL())+` ["repo"] true user`; got != want {
		t.Fatalf("audit of the link = %q, want %q", got, want)
	}

	// Revoke one server's allowance: the connection stays, the other server
	// stays allowed, and the next call asks again.
	revoke := func(s *session, connID, serverID string) (int, string) {
		return s.call("DELETE", "/v1/me/connections/"+connID+"/allowed-servers/"+serverID, nil, nil, nil)
	}
	if code, ec := revoke(e.outsider, conn, e.server.Id.String()); code != 404 {
		t.Fatalf("another person revoked: %d %s", code, ec)
	}
	if code, ec := revoke(e.member, conn, e.other.Id.String()); code != 404 || ec != "server_grant_not_found" {
		t.Fatalf("revoke of a server never allowed: %d %s", code, ec)
	}
	code, ec := revoke(e.member, conn, e.server.Id.String())
	mustCode(t, "revoke", code, ec, 200, "")
	if g := e.myGrants(); len(g) != 1 || g[0].Server.Slug != "second" {
		t.Fatalf("grants after revoke = %+v", g)
	}
	if code, ec := revoke(e.member, conn, e.server.Id.String()); code != 404 || ec != "server_grant_not_found" {
		t.Fatalf("second revoke: %d %s", code, ec)
	}
	if findAllowable(t, e.allowable(e.member, conn), "status").Allowed {
		t.Fatal("status is still marked allowed")
	}
	e.consentURL(e.callTool(e.key, f3Tool), "server_not_allowed")
	if n := e.scalar(`SELECT count(*)::text FROM provider_connections`); n != "1" {
		t.Fatalf("%s connections after revoke", n)
	}
	if got := e.scalar(`SELECT metadata->>'server' || ' ' || (metadata->>'origin') FROM audit_log WHERE action = 'provider_connection.server_revoke'`); got != "STATUS "+originOfURL(e.fake.URL()) {
		t.Fatalf("revoke audit = %q", got)
	}
	e.noSecretsAnywhere()
}

func TestAllowServerRefusals(t *testing.T) {
	e := newProvEnv(t)
	e.connectBroadly("repo")
	conn := e.myConnID()
	st := findAllowable(t, e.allowable(e.member, conn), "status")

	refused := func(what string, s *session, connID string, body map[string]any, wantCode int, wantErr string) map[string]any {
		t.Helper()
		code, ec, details := e.allowCall(s, connID, body)
		if code != wantCode || ec != wantErr {
			t.Fatalf("%s = %d %s, want %d %s", what, code, ec, wantCode, wantErr)
		}
		if n := e.grantCount(e.server.Id.String()); n != "0" {
			t.Fatalf("%s: %s grants after a refusal", what, n)
		}
		return details
	}

	// A server that moved since the page loaded (its address has another
	// origin now): refused, and the list shows the new address.
	e.patchServer(e.owner, e.server, map[string]any{"url": e.otherFake.URL()})
	refused("moved server", e.member, conn, allowBody(st), 409, "server_changed")
	moved := findAllowable(t, e.allowable(e.member, conn), "status")
	if moved.Origin != originOfURL(e.otherFake.URL()) || moved.Origin == st.Origin {
		t.Fatalf("listed origin = %s, was %s", moved.Origin, st.Origin)
	}
	e.mustAllow(conn, moved)
	if got := e.scalar(`SELECT origin FROM provider_server_grants WHERE server_id = $1`, e.server.Id.String()); got != originOfURL(e.otherFake.URL()) {
		t.Fatalf("the grant is for %s, not the server's current origin", got)
	}
	// The grant is for the origin of now only: moving it back deletes it.
	e.patchServer(e.owner, e.server, map[string]any{"url": e.fake.URL()})
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("%s grants after the server moved back", n)
	}
	st = findAllowable(t, e.allowable(e.member, conn), "status")

	// No address, or one that was never the server's.
	refused("no origin", e.member, conn, map[string]any{"serverId": st.Server.Id, "origin": "", "scopes": st.Scopes}, 400, "invalid_allow")
	refused("another origin", e.member, conn, map[string]any{"serverId": st.Server.Id, "origin": "https://evil.example.com", "scopes": st.Scopes},
		409, "server_changed")

	// The requirement widened since the list was loaded: refused (the page
	// shows what changed), and a connection without the new scope is sent to
	// the provider.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo", "read:org"}})
	refused("widened requirement", e.member, conn, allowBody(st), 409, "server_changed")
	wide := findAllowable(t, e.allowable(e.member, conn), "status")
	if wide.Covered || !slices.Equal(wide.Scopes, []string{"repo", "read:org"}) {
		t.Fatalf("widened = %+v", wide)
	}
	details := refused("scopes not covered", e.member, conn, allowBody(wide), 409, "connect_required")
	if sc, _ := details["scopes"].([]any); len(sc) != 2 || details["providerId"] != e.provider.Id.String() {
		t.Fatalf("details = %v", details)
	}
	// The normal provider round trip for the scopes, then allow.
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "scopes": wide.Scopes}); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("the round trip allowed the server: %s grants", n)
	}
	wide = findAllowable(t, e.allowable(e.member, conn), "status")
	if !wide.Covered {
		t.Fatalf("after the round trip: %+v", wide)
	}
	if c := e.mustAllow(conn, wide); !slices.Equal(c.Scopes, []string{"repo", "read:org"}) {
		t.Fatalf("allowed = %+v", c)
	}
	// A requirement that narrows is fine for a page loaded before.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}})
	if c := e.mustAllow(conn, wide); !slices.Equal(c.Scopes, []string{"repo", "read:org"}) {
		t.Fatalf("allowed after narrowing = %+v", c)
	}

	// A connection that needs reconnecting covers nothing.
	e.scalar(`UPDATE provider_connections SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL, expires_at = NULL RETURNING id::text`)
	if l := e.allowable(e.member, conn); len(l) != 1 || l[0].Covered {
		t.Fatalf("list of a connection to reconnect = %+v", l)
	}
	e.scalar(`DELETE FROM provider_server_grants RETURNING server_id::text`)
	refused("needs reconsent", e.member, conn, allowBody(st), 409, "connect_required")

	// Another person's connection is not found, and an unknown one too.
	refused("another person's connection", e.outsider, conn, allowBody(st), 404, "connection_not_found")
	refused("unknown connection", e.member, "00000000-0000-4000-8000-000000000000", allowBody(st), 404, "connection_not_found")
	if code := e.outsider.get("/v1/me/connections/"+conn+"/allowable-servers", nil); code != 404 {
		t.Fatalf("another person's list = %d", code)
	}
	// Strict body.
	if code, _ := e.member.raw("POST", "/v1/me/connections/"+conn+"/allow-server", map[string]any{"serverId": st.Server.Id, "origin": st.Origin, "scopes": st.Scopes, "x": 1}, nil); code != 400 {
		t.Fatalf("unknown field = %d", code)
	}
}

func TestAllowServerRequiresTheProviderAndVisibility(t *testing.T) {
	e := newProvEnv(t)
	e.connectBroadly("repo")
	conn := e.myConnID()
	st := findAllowable(t, e.allowable(e.member, conn), "status")
	unknownBody := map[string]any{"serverId": "00000000-0000-4000-8000-000000000000", "origin": st.Origin, "scopes": st.Scopes}

	// A server of the team on its gateway that requires no account, and one
	// that requires another provider: visible, but not for this connection.
	plain := e.createServer(e.owner, "tools", "plain", e.otherFake.URL(), nil)
	gitlab := e.createProvider("gitlab", testutil.NewFakeOAuth(t), nil)
	third := testutil.NewFakeMCP(t)
	third.EnableGatewayTools()
	lab := e.createServer(e.owner, "tools", "lab", third.URL(), nil)
	e.patchServerReq(lab, map[string]any{"providerId": gitlab.Id, "scopes": []string{"api"}})
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(
		e.capID(e.owner, e.server, "tool", "provider_token"), e.capID(e.owner, plain, "tool", "whoami"), e.capID(e.owner, lab, "tool", "provider_token")))
	if got := e.allowableSlugs(conn); !slices.Equal(got, []string{"status"}) {
		t.Fatalf("list = %v: only servers requiring this provider belong in it", got)
	}
	for _, sv := range []apitypes.McpServer{plain, lab} {
		code, ec, _ := e.allowCall(e.member, conn, map[string]any{"serverId": sv.Id, "origin": st.Origin, "scopes": []string{"repo"}})
		if code != 422 || ec != "server_does_not_require_provider" {
			t.Fatalf("%s = %d %s", sv.Slug, code, ec)
		}
		if n := e.grantCount(sv.Id.String()); n != "0" {
			t.Fatalf("%s grants of %s", n, sv.Slug)
		}
	}

	// Another team's private server that requires the provider is not
	// visible, and answers exactly as a server that doesn't exist.
	e.patchServer(e.outsider, e.other, map[string]any{"requirement": map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}}})
	otherBody := map[string]any{"serverId": e.other.Id, "origin": originOfURL(e.otherFake.URL()), "scopes": []string{"repo"}}
	code, ec, _ := e.allowCall(e.member, conn, otherBody)
	code2, ec2, _ := e.allowCall(e.member, conn, unknownBody)
	if code != 404 || ec != "server_not_found" || code2 != code || ec2 != ec {
		t.Fatalf("another team's server = %d %s, unknown = %d %s", code, ec, code2, ec2)
	}
	// Published to the catalog, but on no gateway the person can use: still not.
	e.publish(e.outsider, e.other)
	if code, ec, _ := e.allowCall(e.member, conn, otherBody); code != 404 || ec != "server_not_found" {
		t.Fatalf("published, on no gateway = %d %s", code, ec)
	}
	if got := e.allowableSlugs(conn); !slices.Equal(got, []string{"status"}) {
		t.Fatalf("list = %v", got)
	}
	// On a platform gateway granted to someone else (casey): not blair's.
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	sharedPath := "/v1/admin/gateways/" + shared.Id.String()
	e.mustSetCaps(e.admin, sharedPath, sel(e.capID(e.outsider, e.other, "tool", "check_outage")))
	if code, ec := e.admin.call("POST", sharedPath+"/grants", map[string]any{"subjectKind": "user", "userEmail": "casey@localhost"}, nil, nil); code != 201 {
		t.Fatalf("grant casey = %d %s", code, ec)
	}
	if code, ec, _ := e.allowCall(e.member, conn, otherBody); code != 404 || ec != "server_not_found" {
		t.Fatalf("on someone else's gateway = %d %s", code, ec)
	}
	// Granted to blair: the published server is in the list, with its team,
	// and can be allowed (the catalog path).
	if code, ec := e.admin.call("POST", sharedPath+"/grants", map[string]any{"subjectKind": "user", "userEmail": "blair@localhost"}, nil, nil); code != 201 {
		t.Fatalf("grant blair = %d %s", code, ec)
	}
	list := e.allowable(e.member, conn)
	if len(list) != 2 || list[0].Server.Slug != "other-status" {
		t.Fatalf("list = %+v", list)
	}
	if o := list[0]; o.Server.TeamSlug != "other" || o.Server.TeamName != "OTHER" || !o.Covered || o.Origin != originOfURL(e.otherFake.URL()) {
		t.Fatalf("catalog server = %+v", o)
	}
	if c := e.mustAllow(conn, list[0]); c.Server.TeamSlug != "other" || !slices.Equal(c.Scopes, []string{"repo"}) {
		t.Fatalf("allowed = %+v", c)
	}
	// The owner's team stops using it (the gateway grant goes): it can't be allowed again.
	e.scalar(`DELETE FROM gateway_grants WHERE gateway_id = $1 AND user_id IS NOT NULL AND user_id = $2 RETURNING id::text`, shared.Id.String(), e.userID("blair@localhost"))
	if code, ec, _ := e.allowCall(e.member, conn, otherBody); code != 404 || ec != "server_not_found" {
		t.Fatalf("after the grant was removed = %d %s", code, ec)
	}
	e.noSecretsAnywhere()
}

// Allowing is the person's own decision in a browser session: no API key,
// automation token, connected app or service account can do it (and none is
// counted against the person's limit).
func TestAllowServerIsSessionOnlyAndRateLimited(t *testing.T) {
	e, fx := newAgentEnv(t)
	e.connectBroadly("repo")
	conn := e.myConnID()
	st := findAllowable(t, e.allowable(e.member, conn), "status")
	body := allowBody(st)
	var tok struct{ Secret string }
	code, ec := e.owner.call("POST", toolsTeam+"/automation-tokens", map[string]any{"name": "ci", "scopes": []string{"servers:write"}, "expiresInDays": 30}, &tok, nil)
	mustCode(t, "token", code, ec, 201, "")
	var plat struct{ Secret string }
	code, ec = e.admin.call("POST", "/v1/admin/automation-tokens", map[string]any{"name": "ops", "scopes": []string{"platform:write"}, "expiresInDays": 30}, &plat, nil)
	mustCode(t, "platform token", code, ec, 201, "")
	for name, secret := range map[string]string{"personal key": e.key, "service account key": fx.key, "team token": tok.Secret, "platform token": plat.Secret} {
		for _, req := range []struct{ method, path string }{
			{"POST", "/v1/me/connections/" + conn + "/allow-server"},
			{"GET", "/v1/me/connections/" + conn + "/allowable-servers"},
			{"DELETE", "/v1/me/connections/" + conn + "/allowed-servers/" + e.server.Id.String()},
		} {
			b, _ := json.Marshal(body)
			r, _ := http.NewRequest(req.method, e.app.URL+req.path, strings.NewReader(string(b)))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+secret)
			res, err := http.DefaultClient.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			res.Body.Close()
			if res.StatusCode != 401 && res.StatusCode != 403 {
				t.Fatalf("%s on %s %s = %d", name, req.method, req.path, res.StatusCode)
			}
		}
	}
	if n := e.grantCount(e.server.Id.String()); n != "0" {
		t.Fatalf("%s grants after refused credentials", n)
	}

	// 20 a minute per person, shared with revoking; the 21st waits.
	for i := 0; i < 20; i++ {
		if c := e.mustAllow(conn, st); c.Server.Slug != "status" {
			t.Fatal(c)
		}
	}
	raw := func() (int, string) {
		code, b := e.member.raw("POST", "/v1/me/connections/"+conn+"/allow-server", body, nil)
		var env struct{ Error struct{ Code string } }
		_ = json.Unmarshal(b, &env)
		return code, env.Error.Code
	}
	if code, ec := raw(); code != 429 || ec != "slow_down" {
		t.Fatalf("21st allow = %d %s", code, ec)
	}
	if code, ec := e.member.call("DELETE", "/v1/me/connections/"+conn+"/allowed-servers/"+e.server.Id.String(), nil, nil, nil); code != 429 || ec != "slow_down" {
		t.Fatalf("revoke over the limit = %d %s", code, ec)
	}
	// Another person has their own.
	if code, ec, _ := e.allowCall(e.outsider, conn, body); code != 404 {
		t.Fatalf("another person = %d %s", code, ec)
	}
}

// An agent calling for a person gets no link (decision 66): when the server
// isn't allowed it is told to allow it under Account › My connections; once
// the person has, with no call of their own, the agent's call goes through.
func TestAgentCallsAfterAllowingFromMyConnections(t *testing.T) {
	e, fx := newAgentEnv(t)
	blair := agentSpec{Email: "blair@localhost"}
	const tool = "status__provider_token"
	e.connectBroadly("repo")

	// Before: link-free, names the server and where to allow it.
	code, out := fx.callTool(fx.token(blair), tool, nil)
	text, isErr := toolText(t, out)
	const want = "needs you to allow STATUS (tools) to use your Github account (repo), which you haven't. Allow STATUS under Account › My connections in Open MCP Portal, then try again."
	if code != 200 || !isErr || !strings.HasSuffix(text, want) {
		t.Fatalf("before allowing = %d %q", code, text)
	}
	noLink(t, out, "before allowing")
	if strings.Contains(text, "yourself") || strings.Contains(text, "MCP client") {
		t.Fatalf("the message still sends the person to a call: %q", text)
	}
	if n := e.connectRequests(); n != "0" || e.toolCalls("provider_token") != 0 {
		t.Fatalf("%s consent requests, %d calls", n, e.toolCalls("provider_token"))
	}

	// The person allows it from My connections, making no call.
	st := findAllowable(t, e.allowable(e.member, e.myConnID()), "status")
	e.mustAllow(e.myConnID(), st)
	if n := e.connectRequests(); n != "0" {
		t.Fatalf("%s consent requests", n)
	}

	// After: the agent's call is served with the person's token, no link.
	id := fx.lastCallID()
	code, out = fx.callTool(fx.token(blair), tool, nil)
	rep := e.providerReport(out)
	issued := e.oauth.Issued()
	if code != 200 || !rep.Received || rep.TokenSHA256 != testutil.TokenDigest(issued[len(issued)-1]) {
		t.Fatalf("after allowing = %d %+v", code, rep)
	}
	noLink(t, out, "after allowing")
	if r := fx.recordAfter(id); r.Outcome != "ok" || r.User != e.userID("blair@localhost") || r.Agent == "" {
		t.Fatalf("record = %+v", r)
	}
	// Another person's agent still can't use blair's allowance.
	_, out = fx.callTool(fx.token(agentSpec{Email: "user@localhost"}), tool, nil)
	if text, isErr := toolText(t, out); !isErr || !strings.HasSuffix(text, wantConnect) {
		t.Fatalf("owner through the relay = %q", text)
	}

	// Revoking the allowance sends the agent back to the same message.
	if code, ec := e.member.call("DELETE", fmt.Sprintf("/v1/me/connections/%s/allowed-servers/%s", e.myConnID(), e.server.Id), nil, nil, nil); code != 200 {
		t.Fatalf("revoke = %d %s", code, ec)
	}
	_, out = fx.callTool(fx.token(blair), tool, nil)
	if text, isErr := toolText(t, out); !isErr || !strings.HasSuffix(text, want) {
		t.Fatalf("after revoking = %q", text)
	}
	noLink(t, out, "after revoking")
	fx.noSecrets(e.logs)
	e.noSecretsAnywhere()
}
