package httpapi_test

import (
	"context"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Delegated credentials end to end (docs/phase5-delegated-credentials.md):
// auth providers against a fake OAuth provider, server requirements and
// overrides, the connect flow, and the runtime at /mcp/{slug} against the
// fake MCP server's provider_token tool.

func TestDelegatedCredentialsEndToEnd(t *testing.T) {
	e := newProvEnv(t)
	ctx := context.Background()
	blairID := e.userID("blair@localhost")

	// Lists still show tools that need an account, and nothing reaches the
	// server without consent.
	if code, names := toolList(t, e.app, "support", e.key); code != 200 || !slices.Contains(names, "status__provider_token") {
		t.Fatalf("tools/list = %d %v", code, names)
	}
	out := e.callTool(e.key, "status__provider_token")
	link := e.consentURL(out, "not_connected")
	if _, msg, _ := rpcErr(out); !strings.Contains(msg, "needs your Github account (repo)") {
		t.Fatalf("message = %q", msg)
	}
	if n := e.toolCalls("provider_token"); n != 0 {
		t.Fatalf("server contacted %d times without consent", n)
	}
	// A repeated call reuses the link.
	if again := e.consentURL(e.callTool(e.key, "status__provider_token"), "not_connected"); again != link {
		t.Fatalf("link not reused: %s vs %s", again, link)
	}
	rid := requestID(link)

	// The link is only for blair.
	code, ec := e.editor.call("GET", "/v1/connect/requests/"+rid, nil, nil, nil)
	mustCode(t, "another person's request", code, ec, 404, "connect_request_not_found")
	code, ec = e.member.call("GET", "/v1/connect/requests/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", nil, nil, nil)
	mustCode(t, "unknown request", code, ec, 404, "connect_request_not_found")
	var cr apitypes.ConnectRequest
	code, ec = e.member.call("GET", "/v1/connect/requests/"+rid, nil, &cr, nil)
	mustCode(t, "own request", code, ec, 200, "")
	if cr.Reason != "not_connected" || !slices.Equal(cr.RequiredScopes, []string{"repo"}) || !slices.Equal(cr.RequestScopes, []string{"repo"}) ||
		len(cr.GrantedScopes) != 0 || cr.Gateway.Slug != "support" || cr.Capability.ExposedName != "status__provider_token" ||
		cr.Provider.Slug != "github" || cr.AccountLabel != nil {
		t.Fatalf("request = %+v", cr)
	}

	// Start: open redirects, another person's request, the wrong provider.
	for _, bad := range []string{"//evil.example", "https://evil.example/x", `/\evil.example`, "/a//b", "javascript:alert(1)", "relative",
		"/" + strings.Repeat("a", 2000)} {
		code, ec, _ := e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid, "returnTo": bad})
		mustCode(t, "returnTo "+bad, code, ec, 400, "invalid_return_to")
	}
	code, ec, _ = e.start(e.editor, map[string]any{"providerId": e.provider.Id, "requestId": rid})
	mustCode(t, "start with another person's request", code, ec, 404, "connect_request_not_found")
	otherOAuth := testutil.NewFakeOAuth(t)
	other := e.createProvider("other", otherOAuth, nil)
	code, ec, _ = e.start(e.member, map[string]any{"providerId": other.Id, "requestId": rid})
	mustCode(t, "provider mismatch", code, ec, 409, "provider_mismatch")
	code, ec, _ = e.start(e.member, map[string]any{"providerId": e.provider.Id, "scopes": []string{"has space"}})
	mustCode(t, "bad scope", code, ec, 400, "invalid_scope")

	// The authorization request is built from the stored settings, with
	// PKCE S256 and a state.
	code, ec, st := e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid})
	mustCode(t, "start", code, ec, 200, "")
	au, _ := url.Parse(st.AuthorizeUrl)
	aq := au.Query()
	if !strings.HasPrefix(st.AuthorizeUrl, e.oauth.URL+"/authorize?") || aq.Get("client_id") != e.oauth.ClientID ||
		aq.Get("redirect_uri") != e.app.URL+"/connect/callback" || aq.Get("scope") != "repo" || aq.Get("code_challenge_method") != "S256" ||
		len(aq.Get("code_challenge")) != 43 || len(aq.Get("state")) != 43 || aq.Get("response_type") != "code" ||
		!slices.Equal(st.Scopes, []string{"repo"}) {
		t.Fatalf("authorize URL = %s", st.AuthorizeUrl)
	}
	back := providerAuthorize(t, e.member, st.AuthorizeUrl)
	// Another person's browser can't complete it (OAuth CSRF), and the state
	// is then used up.
	if to := callback(t, e.editor, back); to != "/connect/done?provider=github&result=wrong_person" {
		t.Fatalf("wrong person = %s", to)
	}
	if to := callback(t, e.member, back); to != "/connect/done?result=expired" {
		t.Fatalf("reused state = %s", to)
	}
	// Signed out: the same.
	code, ec, st = e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid})
	mustCode(t, "start again", code, ec, 200, "")
	if to := callback(t, anonSession(t, e.app), providerAuthorize(t, e.member, st.AuthorizeUrl)); !strings.Contains(to, "result=wrong_person") {
		t.Fatalf("signed out = %s", to)
	}
	// An expired state.
	code, ec, st = e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid})
	mustCode(t, "start again", code, ec, 200, "")
	back = providerAuthorize(t, e.member, st.AuthorizeUrl)
	e.scalar(`UPDATE provider_auth_states SET expires_at = now() - interval '1 second' RETURNING 'x'`)
	if to := callback(t, e.member, back); !strings.Contains(to, "result=expired") {
		t.Fatalf("expired state = %s", to)
	}
	// The provider says no.
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.Deny = true })
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid}); to != "/connect/done?provider=github&result=denied" {
		t.Fatalf("denied = %s", to)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.Deny = false })

	// Connect, back to the given path.
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": rid, "returnTo": "/settings/connections?x=1"}); to != "/settings/connections?x=1" {
		t.Fatalf("connected = %s", to)
	}
	code, ec = e.member.call("GET", "/v1/connect/requests/"+rid, nil, nil, nil)
	mustCode(t, "used request", code, ec, 410, "connect_request_expired")
	var conns []apitypes.ProviderConnection
	if code := e.member.get("/v1/me/connections", &conns); code != 200 || len(conns) != 1 || conns[0].Status != "active" ||
		!slices.Equal(conns[0].Scopes, []string{"repo"}) || conns[0].AccountLabel == nil || *conns[0].AccountLabel != "octocat" ||
		!conns[0].Refreshable || conns[0].ExpiresAt == nil || conns[0].Provider.Slug != "github" {
		t.Fatalf("connections = %d %+v", code, conns)
	}

	// The retry carries the token and the provider claim; the server checks
	// the identity token and that its provider claim names the header's.
	rep := e.providerReport(e.callTool(e.key, "status__provider_token"))
	issued := e.oauth.Issued()
	if !rep.Received || rep.Provider != "github" || rep.TokenSHA256 != testutil.TokenDigest(issued[len(issued)-1]) || rep.Claim != "github" ||
		!rep.ClaimMatches || !rep.Verified {
		t.Fatalf("provider report = %+v", rep)
	}
	calls := e.fake.ToolCalls()
	if h := calls[len(calls)-1].Header; h.Get("MCP-Gateway-Provider-Token") != issued[len(issued)-1] || strings.HasPrefix(h.Get("MCP-Gateway-Provider-Token"), "Bearer") {
		t.Fatalf("token header = %v", h)
	}
	if last := e.scalar(`SELECT outcome || ' ' || provider_slug FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "ok github" {
		t.Fatalf("recorded %q", last)
	}
	var page apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls?limit=1", &page); code != 200 || page.Items[0].ProviderSlug == nil || *page.Items[0].ProviderSlug != "github" {
		t.Fatalf("calls = %d %+v", code, page.Items)
	}

	// An override of none: no token, no header, no claim.
	code, ec = e.override("echo", map[string]any{"mode": "none"})
	mustCode(t, "override none", code, ec, 200, "")
	before := len(e.fake.ToolCalls())
	e.callTool(e.key, "status__echo")
	calls = e.fake.ToolCalls()
	if len(calls) != before+1 || calls[len(calls)-1].Header.Get("MCP-Gateway-Provider-Token") != "" || calls[len(calls)-1].Header.Get("MCP-Gateway-Provider") != "" {
		t.Fatalf("echo got a provider token: %v", calls[len(calls)-1].Header)
	}
	if who := testutil.Whoami(ctx, calls[len(calls)-1].Header, "", ""); who.Claims["provider"] != nil {
		t.Fatalf("echo's identity names a provider: %v", who.Claims)
	}
	// Resources without... the resource inherits the requirement.
	code, _, rd := rawMCP(t, e.app, "POST", "support", e.key, rpc(8, "resources/read", map[string]any{"uri": "omp://status/status://services"}), nil)
	reads := e.fake.ResourceReads()
	if code != 200 || rd["result"] == nil || len(reads) != 1 || reads[0].Header.Get("MCP-Gateway-Provider") != "github" {
		t.Fatalf("read = %d %v %v", code, rd, reads)
	}

	// My gateways says what is connected.
	var detail apitypes.MyGatewayDetail
	if code := e.member.get("/v1/me/gateways/"+e.gateway.Id.String(), &detail); code != 200 {
		t.Fatalf("my gateway = %d", code)
	}
	for _, c := range detail.Capabilities {
		switch c.Name {
		case "provider_token", "whoami":
			if c.Requires == nil || c.Requires.Connected == nil || !*c.Requires.Connected || !slices.Equal(c.Requires.Scopes, []string{"repo"}) {
				t.Errorf("%s requires = %+v", c.Name, c.Requires)
			}
		case "echo":
			if c.Requires != nil {
				t.Errorf("echo requires = %+v", c.Requires)
			}
		}
	}

	// Insufficient scopes: whoami now needs read:org as well.
	code, ec = e.override("whoami", map[string]any{"mode": "scopes", "scopes": []string{"repo", "read:org"}})
	mustCode(t, "override scopes", code, ec, 200, "")
	link = e.consentURL(e.callTool(e.key, "status__whoami"), "missing_scopes")
	// The provider grants less than asked: the person is told.
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.GrantScopes = []string{"repo"} })
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); to != "/connect/done?missing=read%3Aorg&provider=github&result=missing_scopes" {
		t.Fatalf("missing scopes = %s", to)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.GrantScopes = nil })
	link = e.consentURL(e.callTool(e.key, "status__whoami"), "missing_scopes")
	code, ec, st = e.start(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)})
	mustCode(t, "start for more scopes", code, ec, 200, "")
	if !slices.Equal(st.Scopes, []string{"repo", "read:org"}) {
		t.Fatalf("union = %v", st.Scopes)
	}
	if to := callback(t, e.member, providerAuthorize(t, e.member, st.AuthorizeUrl)); to != "/connect/done?provider=github&result=connected" {
		t.Fatalf("reconnect = %s", to)
	}
	if out := e.callTool(e.key, "status__whoami"); out["result"] == nil {
		t.Fatalf("whoami after more scopes = %v", out)
	}

	// Refresh before expiry, with rotation.
	connID := e.scalar(`SELECT id::text FROM provider_connections WHERE user_id = $1`, blairID)
	oldRefresh := e.scalar(`SELECT encode(refresh_token_cipher, 'hex') FROM provider_connections WHERE id = $1`, connID)
	e.scalar(`UPDATE provider_connections SET expires_at = now() + interval '30 seconds' WHERE id = $1 RETURNING 'x'`, connID)
	refreshes := e.oauth.RefreshRequests()
	rep = e.providerReport(e.callTool(e.key, "status__provider_token"))
	issued = e.oauth.Issued()
	if e.oauth.RefreshRequests() != refreshes+1 || rep.TokenSHA256 != testutil.TokenDigest(issued[len(issued)-1]) {
		t.Fatalf("refresh: %d requests, report %+v", e.oauth.RefreshRequests()-refreshes, rep)
	}
	if e.scalar(`SELECT encode(refresh_token_cipher, 'hex') FROM provider_connections WHERE id = $1`, connID) == oldRefresh ||
		e.scalar(`SELECT (refreshed_at IS NOT NULL AND expires_at > now() + interval '30 minutes')::text FROM provider_connections WHERE id = $1`, connID) != "true" {
		t.Fatal("the refresh wasn't stored")
	}

	// Concurrent calls refresh once: the row lock makes the others wait and
	// use the new token (a rotated refresh token is never used twice).
	e.scalar(`UPDATE provider_connections SET expires_at = now() + interval '30 seconds' WHERE id = $1 RETURNING 'x'`, connID)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 200e6 })
	refreshes = e.oauth.RefreshRequests()
	var wg sync.WaitGroup
	results := make([]map[string]any, 4)
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, results[i] = rawMCP(t, e.app, "POST", "support", e.key, rpc(i, "tools/call", map[string]any{"name": "status__provider_token"}), nil)
		}(i)
	}
	wg.Wait()
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.RefreshDelay = 0 })
	for i, r := range results {
		if r["result"] == nil {
			t.Fatalf("concurrent call %d = %v", i, r)
		}
	}
	if n := e.oauth.RefreshRequests() - refreshes; n != 1 {
		t.Fatalf("%d refreshes for concurrent calls", n)
	}

	// The provider is down: refused, nothing forwarded, the connection kept.
	e.scalar(`UPDATE provider_connections SET expires_at = now() + interval '30 seconds' WHERE id = $1 RETURNING 'x'`, connID)
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "unavailable" })
	before = e.toolCalls("provider_token")
	out = e.callTool(e.key, "status__provider_token")
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "provider_unavailable" || e.toolCalls("provider_token") != before {
		t.Fatalf("outage = %v", out)
	}
	if st := e.scalar(`SELECT status FROM provider_connections WHERE id = $1`, connID); st != "active" {
		t.Fatalf("status after outage = %s", st)
	}
	if last := e.scalar(`SELECT outcome || ' ' || error_class FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "upstream_error provider_unavailable" {
		t.Fatalf("recorded %q", last)
	}

	// A refused refresh: the tokens are erased, the person asked again.
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "invalid_grant" })
	e.consentURL(e.callTool(e.key, "status__provider_token"), "needs_reconsent")
	if v := e.scalar(`SELECT status || ' ' || (access_token_cipher IS NULL)::text || ' ' || (refresh_token_cipher IS NULL)::text || ' ' || last_error_class
		FROM provider_connections WHERE id = $1`, connID); v != "needs_reconsent true true invalid_grant" {
		t.Fatalf("after failed refresh: %s", v)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'provider_connection.refresh_failed' AND actor_kind = 'system'
		AND target_id = $1 AND metadata->>'reason' = 'invalid_grant'`, connID); n != "1" {
		t.Fatalf("refresh_failed audits = %s", n)
	}
	if code := e.member.get("/v1/me/connections", &conns); code != 200 || conns[0].Status != "needs_reconsent" || conns[0].Refreshable ||
		!slices.Contains(conns[0].Scopes, "repo") {
		t.Fatalf("connection after failed refresh = %+v", conns)
	}
	e.oauth.Set(func(f *testutil.FakeOAuth) { f.FailRefresh = "" })

	// Expired without a refresh token: the same, reason expired.
	link = e.consentURL(e.callTool(e.key, "status__provider_token"), "needs_reconsent")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "result=connected") {
		t.Fatalf("reconnect = %s", to)
	}
	e.scalar(`UPDATE provider_connections SET refresh_token_cipher = NULL, expires_at = now() - interval '1 minute' WHERE id = $1 RETURNING 'x'`, connID)
	e.consentURL(e.callTool(e.key, "status__provider_token"), "needs_reconsent")
	if v := e.scalar(`SELECT last_error_class FROM provider_connections WHERE id = $1`, connID); v != "expired" {
		t.Fatalf("reason = %s", v)
	}

	// Disconnect: revoked at the provider, and the next call asks again.
	link = e.consentURL(e.callTool(e.key, "status__provider_token"), "needs_reconsent")
	e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)})
	refreshTokens := e.oauth.IssuedRefresh()
	code, ec = e.editor.call("DELETE", "/v1/me/connections/"+connID, nil, nil, nil)
	mustCode(t, "disconnect another person's", code, ec, 404, "connection_not_found")
	code, ec = e.member.call("DELETE", "/v1/me/connections/"+connID, nil, nil, nil)
	mustCode(t, "disconnect", code, ec, 200, "")
	if rv := e.oauth.Revoked(); len(rv) != 1 || rv[0] != refreshTokens[len(refreshTokens)-1] {
		t.Fatalf("revoked = %d tokens", len(rv))
	}
	if v := e.scalar(`SELECT metadata->>'providerRevocation' || ' ' || (metadata->>'reason') FROM audit_log WHERE action = 'provider_connection.revoke'
		AND target_id = $1`, connID); v != "best_effort_after_commit user" {
		t.Fatalf("revoke intent audit = %s", v)
	}
	if v := e.scalar(`SELECT metadata->>'providerRevoked' FROM audit_log WHERE action = 'provider_connection.revocation_result'
		AND target_id = $1 AND actor_kind = 'system' AND actor_user_id IS NULL`, connID); v != "true" {
		t.Fatalf("post-commit revoke result audit = %s", v)
	}
	e.consentURL(e.callTool(e.key, "status__provider_token"), "not_connected")

	// The sentinel: no token, refresh token or client secret in responses,
	// audit, call records or logs.
	secrets := append(append(e.oauth.Issued(), e.oauth.IssuedRefresh()...), e.oauth.ClientSecret)
	dump := e.scalar(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) + e.logs.String() + strings.Join(e.responses, " ")
	var raw []byte
	for _, p := range []string{"/v1/me/connections", providersBase, providersBase + "/" + e.provider.Id.String(), "/v1/auth-providers",
		"/v1/admin/users/" + blairID + "/connections", "/v1/admin/audit?limit=200", "/v1/admin/calls?limit=200"} {
		_, raw = e.admin.raw("GET", p, nil, nil)
		dump += string(raw)
	}
	for _, sec := range secrets {
		if strings.Contains(dump, sec) {
			t.Fatalf("a token or secret leaked (%d chars)", len(sec))
		}
	}
}

// TestConnectReturnToEncoded: percent-encoded slashes and backslashes (any
// case, also double-encoded) can't smuggle an open redirect through
// returnTo; plain paths still work. (Its own person: start is rate limited.)
func TestConnectReturnToEncoded(t *testing.T) {
	e := newProvEnv(t)
	for _, bad := range []string{"/%2F%2Fevil.example", "/%2fevil.example", "/%5Cevil.example", "/%5cevil.example", "/%252F%252Fevil.example",
		"/%255cevil.example", "/settings%2Fconnections"} {
		code, ec, _ := e.start(e.member, map[string]any{"providerId": e.provider.Id, "returnTo": bad})
		mustCode(t, "returnTo "+bad, code, ec, 400, "invalid_return_to")
	}
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "returnTo": "/settings/connections?connected=github"}); to != "/settings/connections?connected=github" {
		t.Fatalf("connected = %s", to)
	}
}

func TestDelegatedCredentialRefusals(t *testing.T) {
	e := newProvEnv(t)

	// Service accounts are refused with a clear error; lists still show it.
	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot", "role": "member"})
	saKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	if code, names := toolList(t, e.app, "support", saKey); code != 200 || !slices.Contains(names, "status__provider_token") {
		t.Fatalf("service account tools/list = %d %v", code, names)
	}
	out := e.callTool(saKey, "status__provider_token")
	if c, msg, data := rpcErr(out); c != -32010 || data["reason"] != "service_connection_missing" ||
		!strings.Contains(msg, "shared Github connection") {
		t.Fatalf("service account = %v", out)
	}
	if last := e.scalar(`SELECT outcome || ' ' || error_class || ' ' || provider_slug FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "denied service_connection_missing github" {
		t.Fatalf("recorded %q", last)
	}
	// What it reaches leaves out what needs a person's account, and says
	// how much that is.
	saReach := func() string {
		t.Helper()
		var gws []apitypes.MyGateway
		if code := e.owner.get(saBase+"/"+sa.Id.String()+"/gateways", &gws); code != 200 || len(gws) != 1 || gws[0].NeedsPersonCount == nil {
			t.Fatalf("service account gateways = %d %+v", code, gws)
		}
		return fmt.Sprintf("%d+%d", gws[0].CapabilityCount, *gws[0].NeedsPersonCount)
	}
	if got := saReach(); got != "0+4" {
		t.Fatalf("service account reach = %s", got)
	}
	// Echo without a requirement works for it, with no provider header.
	code, ec := e.override("echo", map[string]any{"mode": "none"})
	mustCode(t, "override none", code, ec, 200, "")
	if out := e.callTool(saKey, "status__echo"); out["result"] == nil {
		t.Fatalf("service account echo = %v", out)
	}
	if got := saReach(); got != "1+3" {
		t.Fatalf("service account reach after override = %s", got)
	}
	// A person's view of the same gateway counts them all, without the field.
	var mine []apitypes.MyGateway
	if code := e.member.get("/v1/me/gateways", &mine); code != 200 || len(mine) != 1 || mine[0].Slug != "support" || mine[0].CapabilityCount != 4 ||
		mine[0].NeedsPersonCount != nil {
		t.Fatalf("my gateways = %d %+v", code, mine)
	}

	// A turned-off provider: refused, and nobody can connect.
	var cur apitypes.AuthProvider
	e.admin.get(providersBase+"/"+e.provider.Id.String(), &cur)
	code, ec = e.admin.call("PATCH", providersBase+"/"+e.provider.Id.String(), map[string]any{"enabled": false}, nil, ifMatch(cur.Revision))
	mustCode(t, "turn off", code, ec, 200, "")
	out = e.callTool(e.key, "status__provider_token")
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "provider_disabled" {
		t.Fatalf("disabled = %v", out)
	}
	if last := e.scalar(`SELECT outcome || ' ' || error_class FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "denied provider_disabled" {
		t.Fatalf("recorded %q", last)
	}
	code, ec, _ = e.start(e.member, map[string]any{"providerId": e.provider.Id})
	mustCode(t, "start with a turned-off provider", code, ec, 404, "provider_not_found")
	var summaries []apitypes.AuthProviderSummary
	if code := e.member.get("/v1/auth-providers", &summaries); code != 200 || len(summaries) != 0 {
		t.Fatalf("summaries = %+v", summaries)
	}
	if e.toolCalls("provider_token") != 0 {
		t.Fatal("a refused call reached the server")
	}
	// The server keeps the turned-off provider; a new server can't choose it.
	var sv apitypes.McpServer
	e.owner.get(e.serverPath(), &sv)
	if sv.Requirement == nil || sv.Requirement.ProviderEnabled {
		t.Fatalf("requirement = %+v", sv.Requirement)
	}
	code, ec = e.owner.call("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "second", "name": "Second", "url": e.otherFake.URL(),
		"requirement": map[string]any{"providerId": e.provider.Id}}, nil, nil)
	mustCode(t, "require a turned-off provider", code, ec, 422, "provider_not_found")
	code, ec = e.owner.call("PATCH", e.serverPath(), map[string]any{"description": "kept"}, nil, ifMatch(sv.Revision))
	mustCode(t, "keep a turned-off provider", code, ec, 200, "")

	// Reserved header names.
	for _, h := range []string{"MCP-Gateway-Provider", "mcp-gateway-provider-token"} {
		code, ec = e.owner.call("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "hdr", "name": "Hdr", "url": e.otherFake.URL(),
			"authHeaderName": h, "authValue": "x-123456789"}, nil, nil)
		mustCode(t, "reserved header "+h, code, ec, 400, "invalid_auth_header")
	}
}
