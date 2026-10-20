package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Delegated credentials end to end (docs/phase5-delegated-credentials.md):
// auth providers against a fake OAuth provider, server requirements and
// overrides, the connect flow, and the runtime at /mcp/{slug} against the
// fake MCP server's provider_token tool.

const providersBase = "/v1/admin/auth-providers"

// provEnv is gwEnv with a fake OAuth provider configured as "github", the
// server "status" requiring it (scope repo), and the team gateway "support"
// selecting provider_token, whoami and echo; blair (member) has an API key.
type provEnv struct {
	*gwEnv
	logs     *syncBuffer
	oauth    *testutil.FakeOAuth
	provider apitypes.AuthProvider
	gateway  apitypes.Gateway
	key      string
	// responses collects every API body read, for the secret sentinel.
	responses []string
}

func newProvEnv(t *testing.T) *provEnv { return newProvEnvHook(t, nil) }

// newProvEnvHook is newProvEnv with a hook that adjusts the services before
// the handler is built (nil: none).
func newProvEnvHook(t *testing.T, hook func(*httpapi.Deps)) *provEnv {
	t.Helper()
	logs := &syncBuffer{}
	e := &provEnv{gwEnv: newGwEnvHook(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), hook), logs: logs}
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	e.oauth = testutil.NewFakeOAuth(t)
	e.provider = e.createProvider("github", e.oauth, nil)
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}})
	e.gateway = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(
		e.capID(e.owner, e.server, "tool", "provider_token"), e.capID(e.owner, e.server, "tool", "whoami"),
		e.capID(e.owner, e.server, "tool", "echo"), e.capID(e.owner, e.server, "resource", "status://services")))
	e.key = newKey(t, e.member, "laptop").Secret
	return e
}

// createProvider configures a provider at a fake OAuth provider and opens it
// to every team: a new provider starts restricted with an empty list
// (decision 69), which the tests of the access list use (createRestrictedProvider).
func (e *provEnv) createProvider(slug string, f *testutil.FakeOAuth, extra map[string]any) apitypes.AuthProvider {
	e.t.Helper()
	return e.setAccess(e.createRestrictedProvider(slug, f, extra), "open", nil, nil)
}

// setAccess replaces a provider's access list (as an admin, in a browser
// session) and returns the provider as it is after.
func (e *provEnv) setAccess(p apitypes.AuthProvider, mode string, teams, servers []string) apitypes.AuthProvider {
	e.t.Helper()
	code, ec := e.admin.call("PUT", providersBase+"/"+p.Id.String()+"/access",
		map[string]any{"accessMode": mode, "teamIds": nonNilIDs(teams), "serverIds": nonNilIDs(servers)}, nil, ifMatch(p.Revision))
	mustCode(e.t, "set access", code, ec, 200, "")
	var out apitypes.AuthProvider
	if code := e.admin.get(providersBase+"/"+p.Id.String(), &out); code != 200 {
		e.t.Fatalf("get provider = %d", code)
	}
	return out
}

func nonNilIDs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// createRestrictedProvider is createProvider as the API leaves it: restricted,
// with nobody listed.
func (e *provEnv) createRestrictedProvider(slug string, f *testutil.FakeOAuth, extra map[string]any) apitypes.AuthProvider {
	e.t.Helper()
	body := map[string]any{
		"slug": slug, "name": strings.ToUpper(slug[:1]) + slug[1:], "preset": "github", "clientId": f.ClientID, "clientSecret": f.ClientSecret,
		"authorizationUrl": f.URL + "/authorize", "tokenUrl": f.URL + "/token", "revocationUrl": f.URL + "/revoke",
		"userinfoUrl": f.URL + "/userinfo", "defaultScopes": []string{"read:user"},
	}
	for k, v := range extra {
		body[k] = v
	}
	var out apitypes.AuthProvider
	code, raw := e.admin.raw("POST", providersBase, body, nil)
	e.responses = append(e.responses, string(raw))
	if code != 201 {
		e.t.Fatalf("create provider %s: %d %s", slug, code, raw)
	}
	var env struct{ Data apitypes.AuthProvider }
	_ = json.Unmarshal(raw, &env)
	out = env.Data
	return out
}

func (e *provEnv) serverPath() string { return toolsTeam + "/mcp-servers/" + e.server.Id.String() }

// setRequirement PATCHes the server's requirement (nil body value removes it).
func (e *provEnv) setRequirement(req any) apitypes.McpServer {
	e.t.Helper()
	var cur, out apitypes.McpServer
	if code := e.owner.get(e.serverPath(), &cur); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	code, ec := e.owner.call("PATCH", e.serverPath(), map[string]any{"requirement": req}, &out, ifMatch(cur.Revision))
	mustCode(e.t, "set requirement", code, ec, 200, "")
	return out
}

// override sets a capability's requirement override.
func (e *provEnv) override(capName string, body map[string]any) (int, string) {
	e.t.Helper()
	var cur apitypes.McpServer
	e.owner.get(e.serverPath(), &cur)
	return e.owner.call("PUT", e.serverPath()+"/capabilities/"+e.capID(e.owner, e.server, "tool", capName)+"/requirement", body, nil,
		ifMatch(cur.Revision))
}

// callTool calls a tool through the gateway with key.
func (e *provEnv) callTool(key, name string) map[string]any {
	e.t.Helper()
	code, _, out := rawMCP(e.t, e.app, "POST", "support", key, rpc(7, "tools/call", map[string]any{"name": name, "arguments": map[string]any{}}), nil)
	if code != 200 {
		e.t.Fatalf("tools/call %s = %d %v", name, code, out)
	}
	b, _ := json.Marshal(out)
	e.responses = append(e.responses, string(b))
	return out
}

func rpcErr(out map[string]any) (code float64, msg string, data map[string]any) {
	er, _ := out["error"].(map[string]any)
	c, _ := er["code"].(float64)
	m, _ := er["message"].(string)
	d, _ := er["data"].(map[string]any)
	return c, m, d
}

// consentURL checks a -32042 answer and returns its link.
func (e *provEnv) consentURL(out map[string]any, reason string) string {
	e.t.Helper()
	return e.consentURLFor(out, reason, e.provider.Slug)
}

// consentURLFor is consentURL for the provider with the given slug.
func (e *provEnv) consentURLFor(out map[string]any, reason, slug string) string {
	e.t.Helper()
	code, msg, data := rpcErr(out)
	if code != -32042 {
		e.t.Fatalf("want -32042, got %v", out)
	}
	els, _ := data["elicitations"].([]any)
	if len(els) != 1 {
		e.t.Fatalf("elicitations = %v", data)
	}
	el := els[0].(map[string]any)
	link, _ := el["url"].(string)
	if el["mode"] != "url" || !strings.HasPrefix(link, e.app.URL+"/connect/"+slug+"?request=") ||
		!strings.Contains(msg, link) || el["elicitationId"] != strings.TrimPrefix(link, e.app.URL+"/connect/"+slug+"?request=") ||
		!strings.Contains(el["message"].(string), "SUPPORT gateway") {
		e.t.Fatalf("-32042 = %q %v", msg, el)
	}
	var last string
	_ = e.app.Pool.QueryRow(context.Background(), `SELECT outcome || ' ' || error_class || ' ' || provider_slug FROM mcp_calls ORDER BY id DESC LIMIT 1`).Scan(&last)
	if last != "needs_authorization "+reason+" "+slug {
		e.t.Fatalf("recorded %q, want needs_authorization %s", last, reason)
	}
	return link
}

func requestID(link string) string { return link[strings.Index(link, "?request=")+len("?request="):] }

func noRedirects(s *session) *http.Client {
	return &http.Client{Jar: s.client.Jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// providerAuthorize sends a browser to the provider's authorization URL and returns
// where the provider sends it back (the gateway's callback).
func providerAuthorize(t *testing.T, s *session, authorizeURL string) string {
	t.Helper()
	res, err := noRedirects(s).Get(authorizeURL)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("authorize = %d", res.StatusCode)
	}
	return res.Header.Get("Location")
}

// callback follows the provider's redirect back as s and returns where the
// gateway sends the browser.
func callback(t *testing.T, s *session, location string) string {
	t.Helper()
	res, err := noRedirects(s).Get(location)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("callback = %d", res.StatusCode)
	}
	return res.Header.Get("Location")
}

// start begins connecting as s.
func (e *provEnv) start(s *session, body map[string]any) (int, string, apitypes.ConnectStarted) {
	e.t.Helper()
	var out apitypes.ConnectStarted
	code, ec := s.call("POST", "/v1/me/connections/start", body, &out, nil)
	return code, ec, out
}

// connect runs the whole flow as s and returns the callback's redirect.
func (e *provEnv) connect(s *session, body map[string]any) string {
	e.t.Helper()
	code, ec, st := e.start(s, body)
	mustCode(e.t, "start", code, ec, 200, "")
	return callback(e.t, s, providerAuthorize(e.t, s, st.AuthorizeUrl))
}

func (e *provEnv) providerReport(out map[string]any) testutil.ProviderReport {
	e.t.Helper()
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) != 1 {
		e.t.Fatalf("result = %v", out)
	}
	var rep testutil.ProviderReport
	if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &rep); err != nil {
		e.t.Fatal(err)
	}
	return rep
}

func (e *provEnv) toolCalls(name string) int {
	n := 0
	for _, c := range e.fake.ToolCalls() {
		if c.Tool == name {
			n++
		}
	}
	return n
}

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
	if v := e.scalar(`SELECT metadata->>'providerRevoked' || ' ' || (metadata->>'reason') FROM audit_log WHERE action = 'provider_connection.revoke'
		AND target_id = $1`, connID); v != "true user" {
		t.Fatalf("revoke audit = %s", v)
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
	if c, msg, data := rpcErr(out); c != -32010 || data["reason"] != "service_account" ||
		msg != "This tool needs a person's Github account; service accounts can't use it" {
		t.Fatalf("service account = %v", out)
	}
	if last := e.scalar(`SELECT outcome || ' ' || error_class || ' ' || provider_slug FROM mcp_calls ORDER BY id DESC LIMIT 1`); last != "denied service_account github" {
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
