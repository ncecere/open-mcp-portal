package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Per-person OAuth to OAuth-protected MCP servers end to end
// (docs/phase7-upstream-oauth.md): detection, saving (DCR, manual, platform
// provider), the setup sign-in and capability read, the runtime with each
// person's own token, refresh on 401, step-up on 403, sendIdentity,
// revocation, health, review, and the secret sentinel.

// upEnv is gwEnv with a fake authorization server (GitHub-like: issuer
// /login/oauth, iss in responses) and a protected fake MCP server.
type upEnv struct {
	*gwEnv
	logs      *syncBuffer
	as        *testutil.FakeOAuth
	pm        *testutil.FakeMCP
	reg       *registry.Service
	responses []string
}

func newUpEnv(t *testing.T, dcr bool) *upEnv {
	t.Helper()
	logs := &syncBuffer{}
	var reg *registry.Service
	e := &upEnv{gwEnv: newGwEnvHook(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		func(d *httpapi.Deps) { reg = d.Registry }), logs: logs}
	e.reg = reg
	e.as = testutil.NewFakeOAuth(t)
	e.as.Set(func(f *testutil.FakeOAuth) {
		f.IssuerPath, f.IssParam, f.DCR, f.ScopesSupported = "/login/oauth", true, dcr, []string{"repo", "read:user", "write"}
	})
	e.pm = e.protectedFake(t)
	return e
}

func (e *upEnv) protectedFake(t *testing.T) *testutil.FakeMCP {
	pm := testutil.NewFakeMCP(t)
	pm.EnableGatewayTools()
	pm.EnableEchoSecrets()
	pm.SetJWKS(e.app.URL+"/.well-known/jwks.json", pm.URL())
	pm.Protect(testutil.Protection{Issuer: e.as.Issuer(), ChallengeScope: "repo", ScopesSupported: []string{"repo", "read:user", "write"},
		Introspect: func(_ context.Context, tok string) testutil.Introspection { return e.as.Introspect(tok) }})
	return pm
}

const serversBase = toolsTeam + "/mcp-servers"

func (e *upEnv) detect(s *session, u string) (int, string, apitypes.DetectAuthResult) {
	e.t.Helper()
	var out apitypes.DetectAuthResult
	code, ec := s.call("POST", serversBase+"/detect-auth", map[string]any{"url": u}, &out, nil)
	return code, ec, out
}

func (e *upEnv) createOAuth(s *session, slug, u string, oauth map[string]any, extra map[string]any) (int, []byte) {
	e.t.Helper()
	body := map[string]any{"slug": slug, "name": strings.ToUpper(slug), "url": u, "authMode": "oauth", "oauth": oauth}
	for k, v := range extra {
		body[k] = v
	}
	code, raw := s.raw("POST", serversBase, body, nil)
	e.responses = append(e.responses, string(raw))
	return code, raw
}

func (e *upEnv) get(s *session, id string) apitypes.McpServer {
	e.t.Helper()
	var sv apitypes.McpServer
	if code := s.get(serversBase+"/"+id, &sv); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	b, _ := json.Marshal(sv)
	e.responses = append(e.responses, string(b))
	return sv
}

func (e *upEnv) patch(s *session, id string, body map[string]any) (int, string, apitypes.McpServer) {
	e.t.Helper()
	cur := e.get(s, id)
	var out apitypes.McpServer
	code, ec := s.call("PATCH", serversBase+"/"+id, body, &out, ifMatch(cur.Revision))
	return code, ec, out
}

// setup signs in for setup as s and returns where the browser lands.
func (e *upEnv) setup(s *session, id string) (apitypes.ConnectStarted, string) {
	e.t.Helper()
	var st apitypes.ConnectStarted
	code, ec := s.call("POST", serversBase+"/"+id+"/oauth/authorize-setup", nil, &st, nil)
	mustCode(e.t, "authorize-setup", code, ec, 200, "")
	return st, callback(e.t, s, providerAuthorize(e.t, s, st.AuthorizeUrl))
}

func (e *upEnv) call(key, gateway, name string, args map[string]any) map[string]any {
	e.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	code, _, out := rawMCP(e.t, e.app, "POST", gateway, key, rpc(9, "tools/call", map[string]any{"name": name, "arguments": args}), nil)
	if code != 200 {
		e.t.Fatalf("tools/call %s = %d %v", name, code, out)
	}
	b, _ := json.Marshal(out)
	e.responses = append(e.responses, string(b))
	return out
}

// link checks a -32042 answer for the server-bound provider and returns
// its consent link.
func (e *upEnv) link(out map[string]any, slug, class string) string {
	e.t.Helper()
	code, msg, data := rpcErr(out)
	if code != -32042 {
		e.t.Fatalf("want -32042, got %v", out)
	}
	els, _ := data["elicitations"].([]any)
	el, _ := els[0].(map[string]any)
	l, _ := el["url"].(string)
	if !strings.HasPrefix(l, e.app.URL+"/connect/"+slug+"?request=") || !strings.Contains(msg, l) || !strings.Contains(msg, "GH") {
		e.t.Fatalf("-32042 = %q %v", msg, el)
	}
	e.recorded("needs_authorization " + class + " " + slug)
	return l
}

// recorded waits for the latest call record to be want (calls are
// recorded after the answer is written).
func (e *upEnv) recorded(want string) {
	e.t.Helper()
	last := ""
	for range 100 {
		last = e.scalar(`SELECT coalesce((SELECT outcome || ' ' || coalesce(error_class, '') || ' ' || coalesce(provider_slug, '')
			FROM mcp_calls ORDER BY id DESC LIMIT 1), '')`)
		if last == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("recorded %q, want %q", last, want)
}

// connectVia follows a consent link as s.
func (e *upEnv) connectVia(s *session, providerID, l string) string {
	e.t.Helper()
	var st apitypes.ConnectStarted
	code, ec := s.call("POST", "/v1/me/connections/start", map[string]any{"providerId": providerID, "requestId": requestID(l)}, &st, nil)
	mustCode(e.t, "start", code, ec, 200, "")
	return callback(e.t, s, providerAuthorize(e.t, s, st.AuthorizeUrl))
}

func whoamiOf(t *testing.T, out map[string]any) testutil.WhoamiResult {
	t.Helper()
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("result = %v", out)
	}
	var who testutil.WhoamiResult
	if err := json.Unmarshal([]byte(content[0].(map[string]any)["text"].(string)), &who); err != nil {
		t.Fatal(err)
	}
	return who
}

func (e *upEnv) lastAuthorization(tool string) string {
	calls := e.pm.ToolCalls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Tool == tool {
			return calls[i].Authorization
		}
	}
	return ""
}

func problemCodes(r apitypes.DetectAuthResult) []string {
	var out []string
	for _, p := range r.Problems {
		out = append(out, string(p.Code))
	}
	return out
}

func TestUpstreamOAuthDetect(t *testing.T) {
	e := newUpEnv(t, true)
	audits := e.scalar(`SELECT count(*)::text FROM audit_log`)

	code, ec, r := e.detect(e.editor, e.pm.URL())
	mustCode(t, "detect", code, ec, 200, "")
	if r.Outcome != "oauth" || r.AuthorizationServer == nil || r.AuthorizationServer.Issuer != e.as.Issuer() ||
		r.AuthorizationServer.MetadataUrl != e.as.URL+"/.well-known/oauth-authorization-server/login/oauth" ||
		!r.AuthorizationServer.IssParameterSupported || r.Registration == nil || r.Registration.Recommended != "dcr" ||
		!slices.Equal(r.Registration.Options, []apitypes.McpServerOAuthRegistration{"dcr", "manual"}) ||
		r.Registration.CimdUnavailableReason == nil || *r.Registration.CimdUnavailableReason != "not_supported" ||
		r.Registration.RedirectUri != e.app.URL+"/connect/callback" || !slices.Equal(r.SuggestedScopes, []string{"repo"}) ||
		r.Challenge == nil || r.ResourceMetadata == nil || r.ResourceMetadata.Resource != e.pm.URL() || len(r.Steps) != 3 {
		t.Fatalf("detect dcr = %+v", r)
	}
	// CIMD is supported but APP_URL is loopback: not offered.
	e.as.Set(func(f *testutil.FakeOAuth) { f.CIMD = true })
	if _, _, r = e.detect(e.editor, e.pm.URL()); r.Registration.CimdUnavailableReason == nil || *r.Registration.CimdUnavailableReason != "app_url_not_public" ||
		slices.Contains(r.Registration.Options, "cimd") {
		t.Fatalf("cimd on loopback = %+v", r.Registration)
	}
	// No DCR (GitHub): manual only; a platform provider with the same
	// endpoints is offered to link.
	e.as.Set(func(f *testutil.FakeOAuth) { f.DCR, f.CIMD = false, false })
	var prov apitypes.AuthProvider
	code, ec = e.admin.call("POST", providersBase, map[string]any{"slug": "gh-platform", "name": "GitHub platform", "clientId": e.as.ClientID,
		"clientSecret": e.as.ClientSecret, "authorizationUrl": e.as.URL + "/authorize", "tokenUrl": e.as.URL + "/token"}, &prov, nil)
	mustCode(t, "platform provider", code, ec, 201, "")
	_, _, r = e.detect(e.editor, e.pm.URL())
	if r.Registration.Recommended != "manual" || !slices.Equal(r.Registration.Options, []apitypes.McpServerOAuthRegistration{"platform_provider", "manual"}) ||
		len(r.Registration.MatchingProviders) != 1 || r.Registration.MatchingProviders[0].Id != prov.Id ||
		!slices.Contains(problemCodes(r), "no_registration") {
		t.Fatalf("detect no-dcr = %+v", r.Registration)
	}
	// The resource doesn't match: a trailing slash is suggested; another
	// resource is blocking.
	e.pm.SetProtection(func(p *testutil.Protection) { p.Resource = e.pm.URL() + "/" })
	if _, _, r = e.detect(e.editor, e.pm.URL()); r.SuggestedUrl == nil || *r.SuggestedUrl != e.pm.URL()+"/" || !slices.Contains(problemCodes(r), "resource_mismatch") {
		t.Fatalf("near mismatch = %+v", r)
	}
	e.pm.SetProtection(func(p *testutil.Protection) { p.Resource = "https://evil.example/mcp" })
	if _, _, r = e.detect(e.editor, e.pm.URL()); r.SuggestedUrl != nil || r.AuthorizationServer != nil || !slices.Contains(problemCodes(r), "resource_mismatch") {
		t.Fatalf("mismatch = %+v", r)
	}
	// Saving refuses it (discovery runs again on save).
	code, raw := e.createOAuth(e.editor, "evil", e.pm.URL(), map[string]any{"registration": "manual", "clientId": "x", "clientSecret": "secret-123456"}, nil)
	if code != 422 || errorCode(raw) != "oauth_discovery_failed" {
		t.Fatalf("save mismatched = %d %s", code, raw)
	}
	e.pm.SetProtection(func(p *testutil.Protection) { p.Resource = "" })
	// Unprotected servers.
	if _, _, r = e.detect(e.editor, e.fake.URL()); r.Outcome != "no_auth" || r.Registration != nil {
		t.Fatalf("plain = %+v", r)
	}
	// Members can't; detection changed nothing.
	code, ec, _ = e.detect(e.member, e.pm.URL())
	mustCode(t, "member detect", code, ec, 403, "")
	if got := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action NOT LIKE 'auth_provider.%'`); got != audits {
		t.Fatalf("detect audited: %s -> %s", audits, got)
	}
	// 10 a minute per person.
	limited := false
	for range 11 {
		if code, ec, _ := e.detect(e.owner, e.fake.URL()); code == 429 && ec == "slow_down" {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("detect isn't rate limited")
	}
}

// Without the development allowance, detection refuses loopback and
// internal addresses before sending anything.
func TestUpstreamOAuthDetectGuard(t *testing.T) {
	e := newRegistryEnvWith(t, func(d *httpapi.Deps, _ *testutil.FakeMCP) { d.Registry.Client().AllowPrivate = false })
	for u, reason := range map[string]string{"https://10.20.0.5/mcp": "private_address", "https://169.254.169.254/latest": "blocked_address",
		e.fake.URL(): "scheme"} {
		code, raw := e.editor.raw("POST", serversBase+"/detect-auth", map[string]any{"url": u}, nil)
		if code != 422 || errorCode(raw) != "url_not_allowed" || errorDetails(raw)["reason"] != reason {
			t.Fatalf("detect %s = %d %s", u, code, raw)
		}
	}
	if n := e.fake.Requests(); n != 0 {
		t.Fatalf("the fake was contacted %d times", n)
	}
}

func TestUpstreamOAuthEndToEnd(t *testing.T) {
	e := newUpEnv(t, true)
	ctx := context.Background()

	// Conflicts: one credential per call.
	code, raw := e.createOAuth(e.editor, "gh", e.pm.URL(), nil, map[string]any{"authHeaderName": "Authorization", "authValue": "Bearer static-1234"})
	if code != 422 || errorCode(raw) != "auth_conflict" || errorDetails(raw)["reason"] != "static_authorization" {
		t.Fatalf("static Authorization = %d %s", code, raw)
	}
	// Save with automatic registration (DCR); capabilities aren't read yet.
	code, raw = e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "auto", "scopes": []string{"repo"}}, nil)
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	sv := created.Data.Server
	id := sv.Id.String()
	o := sv.Oauth
	if created.Data.SetupRequired == nil || !*created.Data.SetupRequired || created.Data.Refresh != nil || sv.AuthMode == nil || *sv.AuthMode != "oauth" ||
		o == nil || o.Registration != "dcr" || !strings.HasPrefix(o.ProviderSlug, "mcp-") || len(o.ProviderSlug) != 16 || !o.HasClientSecret ||
		o.Resource != e.pm.URL() || o.Issuer != e.as.Issuer() || o.SetupConnection.Status != "missing" || o.RedirectUri == nil ||
		*o.RedirectUri != e.app.URL+"/connect/callback" || !slices.Equal(o.Scopes, []string{"repo"}) || o.TokenAuthMethod != "client_secret_basic" ||
		sv.RefreshedAt != nil || sv.SendIdentity == nil || !*sv.SendIdentity {
		t.Fatalf("created = %+v / %+v", created.Data, o)
	}
	slug, providerID := o.ProviderSlug, o.ProviderId.String()
	if n := len(e.as.RegisteredClients()); n != 1 {
		t.Fatalf("registered %d clients", n)
	}
	// The UI resends registration and sendResource: nothing is registered
	// again and nothing changes.
	audits := e.scalar(`SELECT count(*)::text FROM audit_log`)
	code, ec, same := e.patch(e.editor, id, map[string]any{"authMode": "oauth", "oauth": map[string]any{"registration": "dcr", "sendResource": true}})
	mustCode(t, "resend dcr", code, ec, 200, "")
	code, ec, _ = e.patch(e.editor, id, map[string]any{"oauth": map[string]any{"registration": "auto", "sendResource": true}})
	mustCode(t, "resend auto", code, ec, 200, "")
	if n := len(e.as.RegisteredClients()); n != 1 || same.Revision != sv.Revision || e.scalar(`SELECT count(*)::text FROM audit_log`) != audits {
		t.Fatalf("resending registered again (%d clients) or changed the server (rev %d -> %d)", n, sv.Revision, same.Revision)
	}
	// Overrides don't apply to oauth servers.
	code, ec = e.editor.call("PUT", serversBase+"/"+id+"/capabilities/"+"00000000-0000-0000-0000-000000000000"+"/requirement",
		map[string]any{"mode": "none"}, nil, ifMatch(sv.Revision))
	mustCode(t, "override", code, ec, 409, "upstream_oauth")

	// Refresh needs a setup sign-in.
	code, raw = e.editor.raw("POST", serversBase+"/"+id+"/refresh", nil, nil)
	if code != 409 || errorCode(raw) != "setup_reconsent_required" || errorDetails(raw)["status"] != "missing" {
		t.Fatalf("refresh before setup = %d %s", code, raw)
	}
	code, ec = e.member.call("POST", serversBase+"/"+id+"/oauth/authorize-setup", nil, nil, nil)
	mustCode(t, "member setup", code, ec, 403, "")
	code, ec = e.editor.call("POST", serversBase+"/"+e.server.Id.String()+"/oauth/authorize-setup", nil, nil, nil)
	mustCode(t, "setup of a non-oauth server", code, ec, 409, "not_oauth")

	// The setup sign-in: PKCE S256, resource, the server's scopes, the
	// registered client; afterwards capabilities are read as alex.
	st, to := e.setup(e.editor, id)
	aq := mustParse(t, st.AuthorizeUrl).Query()
	if aq.Get("resource") != e.pm.URL() || aq.Get("code_challenge_method") != "S256" || aq.Get("scope") != "repo" ||
		aq.Get("client_id") != e.as.RegisteredClients()[0] || to != "/teams/tools/servers/"+id+"?setup=connected" {
		t.Fatalf("setup = %s -> %s", st.AuthorizeUrl, to)
	}
	if rs := e.as.Resources(); len(rs) != 1 || rs[0] != e.pm.URL() {
		t.Fatalf("token request resources = %v", rs)
	}
	sv = e.get(e.editor, id)
	if sv.RefreshedAt == nil || sv.Counts.Tools < 4 || sv.Oauth.SetupConnection.Status != "active" || sv.Oauth.SetupConnection.PersonName == nil ||
		sv.Oauth.ConnectionCount != 1 {
		t.Fatalf("after setup = %+v %+v", sv.Counts, sv.Oauth.SetupConnection)
	}
	if v := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.auth_update' AND metadata ? 'setupBy'`); v != "1" {
		t.Fatalf("setupBy audits = %s", v)
	}
	var tr apitypes.McpTestResult
	code, ec = e.editor.call("POST", serversBase+"/"+id+"/test", nil, &tr, nil)
	if mustCode(t, "test", code, ec, 200, ""); !tr.Ok || tr.ReadAs == nil || *tr.ReadAs != *sv.Oauth.SetupConnection.PersonName {
		t.Fatalf("test = %+v", tr)
	}

	// A team gateway with the server's tools.
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "ghgw")
	gwSel := sel(e.capID(e.owner, sv, "tool", "whoami"), e.capID(e.owner, sv, "tool", "write"), e.capID(e.owner, sv, "tool", "echo_secrets"))
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), gwSel)
	blairKey, ownerKey := newKey(t, e.member, "laptop").Secret, newKey(t, e.owner, "desk").Secret

	// Lists never reach the server; calls without a connection get a link.
	before := e.pm.Requests()
	if code, names := toolList(t, e.app, "ghgw", blairKey); code != 200 || !slices.Contains(names, "gh__whoami") {
		t.Fatalf("tools/list = %d %v", code, names)
	}
	l := e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "not_connected")
	if e.pm.Requests() != before {
		t.Fatal("the server was contacted without a connection")
	}
	var cr apitypes.ConnectRequest
	if code := e.member.get("/v1/connect/requests/"+requestID(l), &cr); code != 200 || cr.Provider.Kind == nil || *cr.Provider.Kind != "mcp_server" ||
		cr.Provider.Server == nil || cr.Provider.Server.Id != sv.Id || cr.AuthorizationServerHost == nil || *cr.AuthorizationServerHost != "127.0.0.1" {
		t.Fatalf("connect request = %d %+v", code, cr)
	}
	// The iss check (RFC 9207): a wrong issuer exchanges nothing.
	e.as.Set(func(f *testutil.FakeOAuth) { f.WrongIss = true })
	if to := e.connectVia(e.member, providerID, l); !strings.Contains(to, "result=error") {
		t.Fatalf("wrong iss = %s", to)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.WrongIss, f.OmitIss = false, true })
	if to := e.connectVia(e.member, providerID, l); !strings.Contains(to, "result=error") {
		t.Fatalf("missing iss = %s", to)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.OmitIss = false })
	if to := e.connectVia(e.member, providerID, l); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}
	// The owner connects proactively (they can use the server in a gateway).
	var ost apitypes.ConnectStarted
	code, ec = e.owner.call("POST", "/v1/me/connections/start", map[string]any{"providerId": providerID}, &ost, nil)
	mustCode(t, "owner start", code, ec, 200, "")
	callback(t, e.owner, providerAuthorize(t, e.owner, ost.AuthorizeUrl))
	// The auditor can't (no gateway with the server).
	code, ec = e.auditor.call("POST", "/v1/me/connections/start", map[string]any{"providerId": providerID}, nil, nil)
	mustCode(t, "auditor start", code, ec, 404, "provider_not_found")

	// Each person's call carries their own token, as the bearer; the
	// identity token moves to MCP-Gateway-Identity, without a provider claim.
	issued := e.as.Issued()
	blairWho := whoamiOf(t, e.call(blairKey, "ghgw", "gh__whoami", nil))
	blairTok := strings.TrimPrefix(e.lastAuthorization("whoami"), "Bearer ")
	ownerWho := whoamiOf(t, e.call(ownerKey, "ghgw", "gh__whoami", nil))
	ownerTok := strings.TrimPrefix(e.lastAuthorization("whoami"), "Bearer ")
	if blairWho.BearerSHA256 == "" || blairWho.BearerSHA256 == ownerWho.BearerSHA256 || blairWho.BearerSHA256 != testutil.TokenDigest(blairTok) ||
		ownerWho.BearerSHA256 != testutil.TokenDigest(ownerTok) || !slices.Contains(issued, blairTok) || !slices.Contains(issued, ownerTok) {
		t.Fatalf("tokens: blair %+v owner %+v", blairWho, ownerWho)
	}
	if blairWho.Header != "MCP-Gateway-Identity" || !blairWho.Verified || blairWho.Claims["email"] != "blair@localhost" ||
		blairWho.Claims["provider"] != nil {
		t.Fatalf("identity = %+v", blairWho)
	}
	for _, c := range e.pm.ToolCalls() {
		if c.Header.Get("MCP-Gateway-Provider") != "" || c.Header.Get("MCP-Gateway-Provider-Token") != "" {
			t.Fatal("provider headers sent to an oauth server")
		}
	}
	// A second protected server never sees blair's token.
	if e.fake.ToolCalls() != nil {
		for _, c := range e.fake.ToolCalls() {
			if strings.Contains(c.Authorization, blairTok) {
				t.Fatal("token sent to another server")
			}
		}
	}

	// Upstream 401 invalid_token: one refresh (with resource) and a retry.
	refreshes := e.as.RefreshRequests()
	e.as.Invalidate(blairTok)
	who := whoamiOf(t, e.call(blairKey, "ghgw", "gh__whoami", nil))
	if who.BearerSHA256 == blairWho.BearerSHA256 || e.as.RefreshRequests() != refreshes+1 || e.as.Resources()[len(e.as.Resources())-1] != e.pm.URL() {
		t.Fatalf("refresh on 401: %+v (%d refreshes)", who, e.as.RefreshRequests()-refreshes)
	}
	// Refresh refused too: needs_reconsent and a link.
	e.as.InvalidateAll(true)
	e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "upstream_unauthorized")
	if v := e.scalar(`SELECT status FROM provider_connections WHERE provider_id = $1 AND user_id = $2`, providerID, e.userID("blair@localhost")); v != "needs_reconsent" {
		t.Fatalf("connection = %s", v)
	}
	if v := e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action = 'provider_connection.refresh_failed' ORDER BY id DESC LIMIT 1`); v != "upstream_rejected" {
		t.Fatalf("refresh_failed reason = %s", v)
	}
	l = e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "needs_reconsent")
	if to := e.connectVia(e.member, providerID, l); !strings.Contains(to, "result=connected") {
		t.Fatalf("reconnect = %s", to)
	}

	// 403 insufficient_scope: step-up within the reviewed scopes.
	l = e.link(e.call(blairKey, "ghgw", "gh__write", nil), slug, "insufficient_scope")
	var cr2 apitypes.ConnectRequest
	e.member.get("/v1/connect/requests/"+requestID(l), &cr2)
	if !slices.Contains(cr2.RequiredScopes, "write") || cr2.Reason != "missing_scopes" {
		t.Fatalf("step-up request = %+v", cr2)
	}
	e.connectVia(e.member, providerID, l)
	if out := e.call(blairKey, "ghgw", "gh__write", nil); out["result"] == nil {
		t.Fatalf("write after step-up = %v", out)
	}
	// A scope that wasn't reviewed: refused, no loop.
	e.pm.SetProtection(func(p *testutil.Protection) { p.WriteScope = "admin:org" })
	if c, _, data := rpcErr(e.call(blairKey, "ghgw", "gh__write", nil)); c != -32010 || data["reason"] != "insufficient_scope" {
		t.Fatalf("unreviewed scope = %v %v", c, data)
	}
	e.recorded("denied insufficient_scope " + slug)
	e.pm.SetProtection(func(p *testutil.Protection) { p.WriteScope = "write" })

	// sendIdentity off: no identity token at all.
	code, ec, _ = e.patch(e.editor, id, map[string]any{"sendIdentity": false})
	mustCode(t, "sendIdentity off", code, ec, 200, "")
	who = whoamiOf(t, e.call(blairKey, "ghgw", "gh__whoami", nil))
	last := e.pm.ToolCalls()[len(e.pm.ToolCalls())-1]
	if who.Header != "" || last.Identity != "" || !strings.HasPrefix(last.Authorization, "Bearer fat_") {
		t.Fatalf("sendIdentity false: %+v %q", who, last.Identity)
	}
	var au struct{ Before, After string }
	if err := e.app.Pool.QueryRow(ctx, `SELECT before_state::text, after_state::text FROM audit_log WHERE action = 'mcp_server.auth_update'
		ORDER BY id DESC LIMIT 1`).Scan(&au.Before, &au.After); err != nil || !strings.Contains(au.Before, `"sendIdentity": true`) ||
		!strings.Contains(au.After, `"sendIdentity": false`) || !strings.Contains(au.After, `"registration": "dcr"`) {
		t.Fatalf("auth_update audit = %+v %v", au, err)
	}

	// Service accounts are refused.
	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot", "role": "member"})
	saKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
	if c, msg, data := rpcErr(e.call(saKey, "ghgw", "gh__whoami", nil)); c != -32010 || data["reason"] != "service_connection_missing" ||
		!strings.Contains(msg, "shared GH connection") {
		t.Fatalf("service account = %v %q", c, msg)
	}

	// Captured payloads never hold the person's token, even echoed back.
	code, ec, _ = e.patch(e.owner, id, map[string]any{"capturePayloads": true})
	mustCode(t, "capture", code, ec, 200, "")
	echoed := e.call(blairKey, "ghgw", "gh__echo_secrets", nil)
	if b, _ := json.Marshal(echoed); !strings.Contains(string(b), "authorization=Bearer [REDACTED]") {
		t.Fatalf("the echoed token reached the client: %s", b)
	}
	callID := ""
	for range 100 {
		if callID = e.scalar(`SELECT coalesce(max(call_id)::text, '') FROM mcp_call_payloads`); callID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, payload := e.admin.raw("GET", "/v1/admin/calls/"+callID+"/payload", nil, nil)
	if !strings.Contains(string(payload), "REDACTED") || !strings.Contains(string(payload), "authorization=") {
		t.Fatalf("payload = %s", payload)
	}
	e.responses = append(e.responses, string(payload))

	// Health: the scheduled probe uses nobody's token; the expected 401
	// counts as healthy, requiring sign-in.
	if _, err := e.app.Pool.Exec(ctx, `DELETE FROM mcp_health_checks`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RunHealthChecks(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	sv = e.get(e.editor, id)
	if sv.Health.Status != "healthy" || sv.Health.SignInRequired == nil || !*sv.Health.SignInRequired {
		t.Fatalf("health = %+v", sv.Health)
	}
	var checks []apitypes.McpHealthCheck
	e.editor.get(serversBase+"/"+id+"/health-checks", &checks)
	if len(checks) == 0 || checks[0].Trigger != "scheduled" || checks[0].SignInRequired == nil || !*checks[0].SignInRequired {
		t.Fatalf("checks = %+v", checks)
	}

	// Revocation: disconnecting revokes at the authorization server; the
	// next call asks again.
	var conns []apitypes.ProviderConnection
	e.member.get("/v1/me/connections", &conns)
	if len(conns) != 1 || conns[0].Provider.Kind == nil || *conns[0].Provider.Kind != "mcp_server" || conns[0].Provider.Server == nil ||
		conns[0].Provider.Server.TeamSlug != "tools" || conns[0].Provider.Name != "GH" {
		t.Fatalf("my connections = %+v", conns)
	}
	revoked := len(e.as.Revoked())
	code, ec = e.member.call("DELETE", "/v1/me/connections/"+conns[0].Id.String(), nil, nil, nil)
	mustCode(t, "disconnect", code, ec, 200, "")
	if len(e.as.Revoked()) != revoked+1 {
		t.Fatal("not revoked at the authorization server")
	}
	e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "not_connected")

	// The setup person loses the editor role: the setup connection counts no
	// more and refresh asks for a new sign-in.
	alexID := e.userID("alex@localhost")
	rev := e.scalar(`SELECT revision::text FROM team_members WHERE user_id = $1`, alexID)
	code, ec = e.owner.call("PATCH", toolsTeam+"/members/"+alexID, map[string]any{"role": "member"}, nil, map[string]string{"If-Match": `"` + rev + `"`})
	mustCode(t, "demote alex", code, ec, 200, "")
	code, raw = e.owner.raw("POST", serversBase+"/"+id+"/refresh", nil, nil)
	if code != 409 || errorCode(raw) != "setup_reconsent_required" || errorDetails(raw)["status"] != "missing" {
		t.Fatalf("refresh after role loss = %d %s", code, raw)
	}
	if sv := e.get(e.owner, id); sv.Oauth.SetupConnection.Status != "missing" {
		t.Fatalf("setup after role loss = %+v", sv.Oauth.SetupConnection)
	}

	// Deleting the server revokes and deletes its connections.
	code, ec = e.owner.call("DELETE", serversBase+"/"+id, nil, nil, nil)
	mustCode(t, "delete", code, ec, 200, "")
	if v := e.scalar(`SELECT count(*)::text FROM auth_providers WHERE kind = 'mcp_server'`); v != "0" {
		t.Fatalf("server-bound providers left: %s", v)
	}
	if v := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'provider_connection.revoke' AND metadata->>'reason' = 'server_deleted'`); v == "0" {
		t.Fatal("no server_deleted revocations audited")
	}

	// The sentinel: no token, refresh token or client secret anywhere.
	secrets := append(append(append(e.as.Issued(), e.as.IssuedRefresh()...), e.as.RegisteredSecrets()...), e.as.ClientSecret)
	dump := e.scalar(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(h)::text, ' '), '') FROM mcp_health_checks h`) + e.logs.String() + strings.Join(e.responses, " ")
	for _, p := range []string{"/v1/admin/audit?limit=200", "/v1/admin/calls?limit=200", "/v1/admin/mcp-servers?authMode=oauth"} {
		_, raw := e.admin.raw("GET", p, nil, nil)
		dump += string(raw)
	}
	for _, sec := range secrets {
		if sec != "" && strings.Contains(dump, sec) {
			t.Fatalf("a token or secret leaked (%d chars, %s…)", len(sec), sec[:4])
		}
	}
}

// GitHub's case: no registration, a client entered by hand; linking a
// platform provider; review triggers; leaving oauth.
func TestUpstreamOAuthManualLinkAndReview(t *testing.T) {
	e := newUpEnv(t, false)
	ctx := context.Background()

	code, raw := e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "auto"}, nil)
	if code != 422 || errorCode(raw) != "registration_unavailable" {
		t.Fatalf("auto without registration = %d %s", code, raw)
	}
	code, raw = e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "manual", "clientId": e.as.ClientID}, nil)
	if code != 422 || errorCode(raw) != "client_required" {
		t.Fatalf("manual without secret = %d %s", code, raw)
	}
	code, raw = e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "manual", "clientId": e.as.ClientID,
		"clientSecret": e.as.ClientSecret, "tokenAuthMethod": "client_secret_post", "scopes": []string{"repo"}}, nil)
	if code != 201 {
		t.Fatalf("manual = %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	sv := created.Data.Server
	id := sv.Id.String()
	if o := sv.Oauth; o.Registration != "manual" || o.ClientIdHint != e.as.ClientID[len(e.as.ClientID)-6:] || !o.HasClientSecret ||
		o.TokenAuthMethod != "client_secret_post" || !o.IssParameterSupported {
		t.Fatalf("manual oauth = %+v", o)
	}
	if _, to := e.setup(e.editor, id); !strings.Contains(to, "setup=connected") {
		t.Fatalf("setup = %s", to)
	}
	// Resending manual without the secret keeps it.
	code, ec, same := e.patch(e.editor, id, map[string]any{"oauth": map[string]any{"registration": "manual", "sendResource": true}})
	if mustCode(t, "resend manual", code, ec, 200, ""); !same.Oauth.HasClientSecret || same.Revision != e.get(e.editor, id).Revision {
		t.Fatalf("resend manual = %+v", same.Oauth)
	}

	// Review: under approval_required, widening scopes sends a published
	// server back; narrowing doesn't.
	e.publish(e.owner, sv)
	code, ec, sv = e.patch(e.editor, id, map[string]any{"oauth": map[string]any{"scopes": []string{"repo", "write"}}})
	mustCode(t, "widen", code, ec, 200, "")
	if sv.PublishState != "pending" || e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action = 'mcp_server.publish_request' ORDER BY id DESC LIMIT 1`) !=
		"upstream_auth_changed" {
		t.Fatalf("widened = %s", sv.PublishState)
	}
	code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil)
	mustCode(t, "approve", code, ec, 200, "")
	if code, ec, sv = e.patch(e.editor, id, map[string]any{"oauth": map[string]any{"scopes": []string{"repo"}}}); code != 200 || sv.PublishState != "published" {
		t.Fatalf("narrowed = %d %s %s", code, ec, sv.PublishState)
	}
	// Admin filter by mode.
	var page apitypes.McpServerPage
	if code := e.admin.get("/v1/admin/mcp-servers?authMode=oauth", &page); code != 200 || len(page.Items) != 1 || page.Items[0].Id != sv.Id {
		t.Fatalf("authMode filter = %d %+v", code, page.Items)
	}
	var cat apitypes.CatalogServerPage
	if e.member.get("/v1/catalog/servers", &cat); len(cat.Items) != 1 || cat.Items[0].AuthMode == nil || *cat.Items[0].AuthMode != "oauth" {
		t.Fatalf("catalog = %+v", cat.Items)
	}

	// Switching a published server to oauth goes back to review.
	plain := testutil.NewFakeMCP(t)
	plain.EnableGatewayTools()
	other := e.createServer(e.owner, "tools", "later", plain.URL(), nil)
	e.publish(e.owner, other)
	plain.Protect(testutil.Protection{Issuer: e.as.Issuer(), ScopesSupported: []string{"repo"},
		Introspect: func(_ context.Context, tok string) testutil.Introspection { return e.as.Introspect(tok) }})
	code, ec, other = e.patch(e.editor, other.Id.String(), map[string]any{"authMode": "oauth", "oauth": map[string]any{"registration": "manual",
		"clientId": e.as.ClientID, "clientSecret": e.as.ClientSecret}})
	if mustCode(t, "switch to oauth", code, ec, 200, ""); other.PublishState != "pending" || other.Oauth == nil {
		t.Fatalf("switched = %s", other.PublishState)
	}

	// Linking a platform provider: its client is used, its connections
	// never; it can't change its endpoints or be deleted while linked.
	var prov apitypes.AuthProvider
	code, ec = e.admin.call("POST", providersBase, map[string]any{"slug": "gh-platform", "name": "GitHub", "clientId": e.as.ClientID,
		"clientSecret": e.as.ClientSecret, "authorizationUrl": e.as.URL + "/authorize", "tokenUrl": e.as.URL + "/token"}, &prov, nil)
	mustCode(t, "platform provider", code, ec, 201, "")
	pm2 := e.protectedFake(t)
	code, raw = e.createOAuth(e.editor, "linked", pm2.URL(), map[string]any{"registration": "platform_provider", "platformProviderId": prov.Id}, nil)
	if code != 201 {
		t.Fatalf("linked = %d %s", code, raw)
	}
	_ = json.Unmarshal(raw, &created)
	linked := created.Data.Server
	if linked.Oauth.Registration != "platform_provider" || linked.Oauth.PlatformProvider == nil || linked.Oauth.PlatformProvider.Id != prov.Id {
		t.Fatalf("linked oauth = %+v", linked.Oauth)
	}
	code, ec = e.admin.call("PATCH", providersBase+"/"+prov.Id.String(), map[string]any{"tokenUrl": e.as.URL + "/token2"}, nil, ifMatch(prov.Revision))
	mustCode(t, "change linked endpoint", code, ec, 409, "in_use")
	code, ec = e.admin.call("DELETE", providersBase+"/"+prov.Id.String(), nil, nil, nil)
	mustCode(t, "delete linked", code, ec, 409, "in_use")
	var filtered apitypes.McpServerPage
	if e.admin.get("/v1/admin/mcp-servers?provider="+prov.Id.String(), &filtered); len(filtered.Items) != 1 || filtered.Items[0].Id != linked.Id {
		t.Fatalf("provider filter = %+v", filtered.Items)
	}
	if _, to := e.setup(e.editor, linked.Id.String()); !strings.Contains(to, "setup=connected") {
		t.Fatalf("linked setup = %s", to)
	}
	code, ec = e.admin.call("PATCH", providersBase+"/"+prov.Id.String(), map[string]any{"enabled": false}, nil, ifMatch(prov.Revision))
	mustCode(t, "turn off", code, ec, 200, "")
	code, ec = e.editor.call("POST", serversBase+"/"+linked.Id.String()+"/oauth/authorize-setup", nil, nil, nil)
	mustCode(t, "setup with the provider off", code, ec, 422, "provider_mismatch")
	// Server-bound providers aren't platform providers.
	var platform []apitypes.AuthProvider
	if e.admin.get(providersBase, &platform); len(platform) != 1 {
		t.Fatalf("platform providers = %d", len(platform))
	}
	code, ec = e.admin.call("GET", providersBase+"/"+linked.Oauth.ProviderId.String(), nil, nil, nil)
	mustCode(t, "server-bound via admin", code, ec, 404, "provider_not_found")
	code, ec = e.admin.call("POST", providersBase, map[string]any{"slug": "mcp-0123456789ab", "name": "X", "clientId": "c", "clientSecret": "s-12345678",
		"authorizationUrl": "https://a.example/authorize", "tokenUrl": "https://a.example/token"}, nil, nil)
	mustCode(t, "reserved slug", code, ec, 422, "invalid_slug")

	// A resource change during the flow: the callback refuses it.
	var st apitypes.ConnectStarted
	code, ec = e.editor.call("POST", serversBase+"/"+id+"/oauth/authorize-setup", nil, &st, nil)
	mustCode(t, "setup again", code, ec, 200, "")
	back := providerAuthorize(t, e.editor, st.AuthorizeUrl)
	if _, err := e.app.Pool.Exec(ctx, `UPDATE auth_providers SET resource = 'https://moved.example/mcp' WHERE server_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if to := callback(t, e.editor, back); !strings.Contains(to, "result=error") {
		t.Fatalf("resource changed = %s", to)
	}
	if _, err := e.app.Pool.Exec(ctx, `UPDATE auth_providers SET resource = $2 WHERE server_id = $1`, id, e.pm.URL()); err != nil {
		t.Fatal(err)
	}

	// sendResource off: the authorization request has no resource.
	code, ec, _ = e.patch(e.editor, id, map[string]any{"oauth": map[string]any{"sendResource": false}})
	mustCode(t, "sendResource off", code, ec, 200, "")
	code, ec = e.editor.call("POST", serversBase+"/"+id+"/oauth/authorize-setup", nil, &st, nil)
	if mustCode(t, "setup without resource", code, ec, 200, ""); mustParse(t, st.AuthorizeUrl).Query().Has("resource") {
		t.Fatalf("resource sent: %s", st.AuthorizeUrl)
	}

	// Leaving oauth deletes the connections (revoked where possible).
	conns := e.scalar(`SELECT count(*)::text FROM provider_connections pc JOIN auth_providers p ON p.id = pc.provider_id WHERE p.server_id = $1`, id)
	code, ec, sv = e.patch(e.editor, id, map[string]any{"authMode": "none"})
	if mustCode(t, "leave oauth", code, ec, 200, ""); sv.Oauth != nil || *sv.AuthMode != "none" {
		t.Fatalf("left = %+v", sv)
	}
	if v := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'provider_connection.revoke' AND metadata->>'reason' = 'server_auth_changed'`); v != conns {
		t.Fatalf("revoked %s of %s connections", v, conns)
	}
}
