package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Machine OAuth (roadmap #24, decision 73, docs/machine-oauth.md): a server
// that authenticates the portal itself. The portal gets a token with the
// client credentials grant from the fake authorization server
// (testutil.FakeOAuth), keeps it in memory and sends it as the bearer to a fake
// MCP server that requires it (testutil.FakeMCP.Protect), on every request:
// discovery, Test, scheduled health checks, calls from people and from
// service accounts. The client secret goes only to the token endpoint it was
// entered for (F-1), and neither it nor a token is in any response, log, audit
// entry, stored error or captured payload.

const machineSecret = "machine-secret-SENTINEL-0001"

type machineEnv struct {
	*rtEnv
	logs *syncBuffer
	reg  *registry.Service
	as   *testutil.FakeOAuth
	// seen collects every response body the test made (mu: calls run concurrently).
	seen []string
	mu   sync.Mutex
}

func newMachineEnv(t *testing.T) *machineEnv {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var reg *registry.Service
	e := &machineEnv{logs: logs}
	e.rtEnv = newRuntimeEnvHook(t, log, func(d *httpapi.Deps) { reg = d.Registry })
	e.reg = reg
	e.as = testutil.NewFakeOAuth(t)
	e.as.Set(func(f *testutil.FakeOAuth) {
		f.ClientSecret, f.EnforceExpiry, f.MachineScopes = machineSecret, true, []string{"read", "write"}
	})
	e.fake.EnableEchoSecrets()
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	e.protect(e.as)
	return e
}

// protect makes the fake MCP server require bearer tokens that as says are
// active and bound to its own URL.
func (e *machineEnv) protect(as *testutil.FakeOAuth) {
	e.fake.Protect(testutil.Protection{Issuer: as.Issuer(),
		Introspect: func(_ context.Context, tok string) testutil.Introspection { return as.Introspect(tok) }})
}

func (e *machineEnv) path() string { return toolsTeam + "/mcp-servers/" + e.server.Id.String() }

func (e *machineEnv) get(s *session) apitypes.McpServer {
	e.t.Helper()
	var sv apitypes.McpServer
	if code := s.get(e.path(), &sv); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	return sv
}

func (e *machineEnv) patch(s *session, body map[string]any) (int, []byte) {
	e.t.Helper()
	code, raw := s.raw("PATCH", e.path(), body, ifMatch(e.get(s).Revision))
	e.seen = append(e.seen, string(raw))
	return code, raw
}

func (e *machineEnv) mustPatch(s *session, body map[string]any) apitypes.McpServer {
	e.t.Helper()
	code, raw := e.patch(s, body)
	if code != 200 {
		e.t.Fatalf("patch %v = %d %s", body, code, raw)
	}
	var out struct{ Data apitypes.McpServer }
	_ = json.Unmarshal(raw, &out)
	return out.Data
}

// machine is the body that puts the server in machine_oauth mode with the
// fake authorization server's client; extra overrides machineOAuth's fields.
func (e *machineEnv) machine(extra map[string]any) map[string]any {
	m := map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": e.as.ClientID, "clientSecret": machineSecret,
		"scopes": []string{"read"}, "resource": e.fake.URL()}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return map[string]any{"authMode": "machine_oauth", "machineOAuth": m}
}

func (e *machineEnv) refreshRaw(s *session) (int, []byte) {
	e.t.Helper()
	code, raw := s.raw("POST", e.path()+"/refresh", nil, nil)
	e.seen = append(e.seen, string(raw))
	return code, raw
}

func (e *machineEnv) test(s *session) apitypes.McpTestResult {
	e.t.Helper()
	code, raw := s.raw("POST", e.path()+"/test", nil, nil)
	e.seen = append(e.seen, string(raw))
	if code != 200 {
		e.t.Fatalf("test = %d %s", code, raw)
	}
	var out struct{ Data apitypes.McpTestResult }
	_ = json.Unmarshal(raw, &out)
	return out.Data
}

// approve has the platform admin approve the server as it is (a change that
// sends a published server back to review leaves it pending).
func (e *machineEnv) approve() {
	e.t.Helper()
	code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(e.t, e.admin, e.server.Id.String()), nil, nil)
	mustCode(e.t, "approve", code, ec, 200, "")
}

func (e *machineEnv) callTool(key, name string, args map[string]any) (int, map[string]any) {
	e.t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	code, _, out := rawMCP(e.t, e.app, "POST", "support", key, rpc(1, "tools/call", map[string]any{"name": name, "arguments": args}), nil)
	b, _ := json.Marshal(out)
	e.mu.Lock()
	e.seen = append(e.seen, string(b))
	e.mu.Unlock()
	return code, out
}

// recorded waits for the latest call record to be outcome and class.
func (e *machineEnv) recorded(want string) {
	e.t.Helper()
	last := ""
	for range 100 {
		last = e.scalar(`SELECT coalesce((SELECT outcome || ' ' || coalesce(error_class, '') FROM mcp_calls ORDER BY id DESC LIMIT 1), '')`)
		if last == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("recorded %q, want %q", last, want)
}

// wantFailure checks a Test result: it failed with class and, when contains is
// not empty, a message with it; the message never holds what the
// authorization server wrote.
func wantFailure(t *testing.T, what string, res apitypes.McpTestResult, class, contains string) {
	t.Helper()
	msg := ""
	if res.Message != nil {
		msg = *res.Message
	}
	if res.Ok || res.ErrorClass == nil || string(*res.ErrorClass) != class || !strings.Contains(msg, contains) ||
		strings.Contains(msg, "fake provider says no") || strings.Contains(msg, "SENTINEL") {
		t.Fatalf("%s = %+v (%s)", what, res, msg)
	}
}

func (e *machineEnv) token(i int) string { return e.as.Issued()[i] }

func (e *machineEnv) tokenRequests() int { return len(e.as.ClientCredentialsRequests()) }

// forget drops the portal's cached token (as a restart would).
func (e *machineEnv) forget() { e.reg.MachineTokens().Forget(e.server.Id.String()) }

// sentinels are every form of the secret a leak could take, and every token
// the authorization server issued.
func (e *machineEnv) sentinels() []string {
	basic := base64.StdEncoding.EncodeToString([]byte(url.QueryEscape(e.as.ClientID) + ":" + url.QueryEscape(machineSecret)))
	out := []string{machineSecret, url.QueryEscape(machineSecret), basic, "SENTINEL-0001"}
	return append(out, e.as.Issued()...)
}

func (e *machineEnv) assertNoSecrets(what, text string) {
	e.t.Helper()
	for _, s := range e.sentinels() {
		if s != "" && strings.Contains(text, s) {
			e.t.Errorf("%s contains %q", what, s)
		}
	}
}

// bearers are the Authorization headers of the fake MCP server's requests
// after the first n.
func bearersSince(f *testutil.FakeMCP, n int) []string {
	var out []string
	for _, a := range f.RequestAuths()[n:] {
		out = append(out, a.Authorization)
	}
	return out
}

func TestMachineOAuthEndToEnd(t *testing.T) {
	e := newMachineEnv(t)
	ctx := context.Background()
	before := len(e.fake.RequestAuths())

	// Without the machine client the protected server refuses everything.
	if code, raw := e.refreshRaw(e.owner); code == 200 {
		t.Fatalf("refresh of a protected server without credentials = %d %s", code, raw)
	}

	// An editor puts the server in machine_oauth mode. It was published, so
	// the change goes back to review (a new way of authenticating).
	sv := e.mustPatch(e.editor, e.machine(nil))
	if sv.AuthMode == nil || *sv.AuthMode != "machine_oauth" || sv.MachineOAuth == nil || sv.PublishState != "pending" {
		t.Fatalf("server = %+v", sv)
	}
	m := sv.MachineOAuth
	if m.TokenUrl != e.as.URL+"/token" || m.ClientIdHint != "client" || !m.HasClientSecret || m.ClientSecretHint != "0001" ||
		m.TokenAuthMethod != "client_secret_basic" || len(m.Scopes) != 1 || m.Scopes[0] != "read" || m.Resource == nil || *m.Resource != e.fake.URL() || m.Audience != nil {
		t.Fatalf("machineOAuth = %+v", m)
	}
	if sv.HasAuth || sv.Oauth != nil {
		t.Errorf("a machine server has no static credential or sign-in: %+v", sv)
	}
	if e.as.ClientSecret == "" || e.tokenRequests() != 0 {
		t.Fatalf("saving requested a token (%d)", e.tokenRequests())
	}
	if got := e.scalar(`SELECT coalesce(string_agg(after_state::text || metadata::text, '|'), '') FROM audit_log WHERE action = 'mcp_server.auth_update'`); !strings.Contains(got, `"tokenUrl"`) ||
		!strings.Contains(got, `"clientSecretChanged": true`) || strings.Contains(got, `"clientId"`) {
		t.Errorf("audit = %s", got)
	}

	// Refresh and Test read the server with the machine token.
	mark := len(e.fake.RequestAuths())
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	if e.tokenRequests() != 1 {
		t.Fatalf("%d token requests after a refresh", e.tokenRequests())
	}
	tok := e.token(0)
	req := e.as.ClientCredentialsRequests()[0]
	if req.ClientAuth != "basic" || req.ClientID != e.as.ClientID || req.ClientSecret != machineSecret || req.Scope != "read" ||
		req.Resource != e.fake.URL() || req.Audience != "" || !req.Authorized {
		t.Fatalf("token request = %+v", req)
	}
	bs := bearersSince(e.fake, mark)
	if len(bs) == 0 {
		t.Fatal("no request reached the server")
	}
	for _, b := range bs {
		if b != "Bearer "+tok {
			t.Errorf("refresh sent %q", b)
		}
	}
	mark = len(e.fake.RequestAuths())
	if res := e.test(e.editor); !res.Ok {
		t.Fatalf("test = %+v", res)
	}
	for _, a := range e.fake.RequestAuths()[mark:] {
		// Test sends the editor's identity token like a call does: it is in
		// MCP-Gateway-Identity, never in Authorization.
		if a.Authorization != "Bearer "+tok || len(a.Identity) < 50 {
			t.Errorf("test sent %+v", a)
		}
	}
	// Scheduled health checks use the machine token and no identity.
	mark = len(e.fake.RequestAuths())
	if _, err := e.app.Pool.Exec(ctx, `DELETE FROM mcp_health_checks`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RunHealthChecks(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if h := e.get(e.owner).Health; h.Status != "healthy" {
		t.Fatalf("health = %+v", h)
	}
	for _, a := range e.fake.RequestAuths()[mark:] {
		if a.Authorization != "Bearer "+tok || a.Identity != "" {
			t.Errorf("health check sent %+v", a)
		}
	}
	if e.tokenRequests() != 1 {
		t.Fatalf("refresh, test and a health check made %d token requests, want one", e.tokenRequests())
	}

	// The change is reviewed on a digest that covers the client: widening the
	// scopes makes an earlier look stale, and a new secret does not.
	e.approve()
	if sv := e.get(e.owner); sv.PublishState != "published" {
		t.Fatalf("approve: %s", sv.PublishState)
	}
	stale := reviewDigestOf(t, e.admin, e.server.Id.String())
	if sv := e.mustPatch(e.editor, e.machine(map[string]any{"scopes": []string{"read", "write"}, "clientSecret": nil, "tokenUrl": nil,
		"clientId": nil, "resource": nil})); sv.PublishState != "pending" {
		t.Fatalf("a wider scope kept the server published: %s", sv.PublishState)
	}
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review",
		map[string]any{"decision": "approve", "expectedDigest": stale}, nil, nil); code != 409 || ec != "changed_since_review" {
		t.Fatalf("approving on the digest from before the change = %d %s", code, ec)
	}
	e.approve()
	// A new secret alone is not a review trigger (and a narrower scope never is).
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"clientSecret": machineSecret, "scopes": []string{"read"}}})
	if sv := e.get(e.owner); sv.PublishState != "published" {
		t.Fatalf("a new secret and fewer scopes sent the server back to review: %s", sv.PublishState)
	}
	// The scopes changed, so the token the portal had is not used for the new
	// ones: the next request asks again.
	if e.tokenRequests() != 1 {
		t.Fatalf("saving requested a token (%d)", e.tokenRequests())
	}

	// A call from a person: the machine token is the bearer, the person's
	// identity token travels as MCP-Gateway-Identity.
	calls := len(e.fake.ToolCalls())
	code, out := e.callTool(e.key.Secret, "status__whoami", nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("call = %d %v", code, out)
	}
	tok = e.token(len(e.as.Issued()) - 1)
	if e.tokenRequests() != 2 {
		t.Fatalf("%d token requests, want 2 (the scopes changed once)", e.tokenRequests())
	}
	got := e.fake.ToolCalls()
	if len(got) != calls+1 {
		t.Fatalf("tool calls = %d", len(got))
	}
	last := got[len(got)-1]
	if last.Tool != "whoami" || last.Authorization != "Bearer "+tok || len(last.Identity) < 50 {
		t.Fatalf("the call arrived as %+v", last)
	}
	var who testutil.WhoamiResult
	_ = json.Unmarshal([]byte(resultTextOf(out)), &who)
	if !who.Verified || who.Claims["principal_type"] != "user" || who.Claims["email"] != "blair@localhost" {
		t.Fatalf("whoami = %+v", who)
	}

	// A service account can call a tool on such a server: the credential is
	// the portal's, so it applies to every caller; the identity token still
	// says who is calling.
	sa := createSA(t, e.owner, map[string]any{"name": "ci-bot"})
	saKey := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "deploy"})
	res, err := connect(t, e.app, "support", saKey.Secret).CallTool(ctx, &mcp.CallToolParams{Name: "status__whoami"})
	if err != nil || res.IsError {
		t.Fatalf("service account call: %v %+v", err, res)
	}
	got = e.fake.ToolCalls()
	last = got[len(got)-1]
	if last.Authorization != "Bearer "+tok {
		t.Fatalf("the service account's call arrived as %+v", last)
	}
	who = testutil.WhoamiResult{}
	_ = json.Unmarshal([]byte(resultText(t, res)), &who)
	if !who.Verified || who.Claims["principal_type"] != "service_account" || who.Claims["sub"] != sa.Id.String() {
		t.Fatalf("service account whoami = %+v", who)
	}
	if e.tokenRequests() != 2 {
		t.Fatalf("calls from two principals made %d token requests", e.tokenRequests())
	}

	// How the client authenticates at the token endpoint is changed without the
	// secret, and the next token request uses the form.
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"tokenAuthMethod": "client_secret_post"}})
	if code, out := e.callTool(e.key.Secret, "status__whoami", nil); code != 200 || out["error"] != nil {
		t.Fatalf("call after the method change = %d %v", code, out)
	}
	reqs := e.as.ClientCredentialsRequests()
	if len(reqs) != 3 || reqs[2].ClientAuth != "post" || reqs[2].ClientSecret != machineSecret || reqs[2].Scope != "read" {
		t.Fatalf("token requests = %+v", reqs)
	}

	// Leaving the mode removes the client and its secret and the token.
	e.mustPatch(e.editor, map[string]any{"authMode": "none"})
	if e.scalar(`SELECT count(*)::text FROM mcp_server_machine_oauth`) != "0" {
		t.Error("the machine client outlived the mode")
	}
	if sv := e.get(e.owner); sv.MachineOAuth != nil || *sv.AuthMode != "none" {
		t.Errorf("after leaving the mode: %+v", sv)
	}

	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
	e.assertNoSecrets("the audit log", e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`))
	_ = before
}

// Creating a server in the mode reads its capabilities at once, with the token;
// the secret can't be shown again; the audit entry names the endpoint.
func TestMachineOAuthCreate(t *testing.T) {
	e := newMachineEnv(t)
	other := testutil.NewFakeMCP(t)
	other.EnableGatewayTools()
	other.Protect(testutil.Protection{Issuer: e.as.Issuer(), Introspect: func(_ context.Context, tok string) testutil.Introspection { return e.as.Introspect(tok) }})
	body := map[string]any{"slug": "machine", "name": "Machine", "url": other.URL(), "authMode": "machine_oauth",
		"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": e.as.ClientID, "clientSecret": machineSecret,
			"scopes": []string{"read"}, "resource": other.URL(), "audience": "api://machine"}}
	var out apitypes.McpServerCreated
	code, ec := e.editor.call("POST", toolsTeam+"/mcp-servers", body, &out, nil)
	mustCode(t, "create", code, ec, 201, "")
	raw, _ := json.Marshal(out)
	e.seen = append(e.seen, string(raw))
	if out.Refresh == nil || out.RefreshError != nil || out.Server.MachineOAuth == nil || out.Server.MachineOAuth.Audience == nil ||
		*out.Server.MachineOAuth.Audience != "api://machine" || out.Refresh.Added == 0 {
		t.Fatalf("created = %+v", out)
	}
	if reqs := e.as.ClientCredentialsRequests(); len(reqs) != 1 || reqs[0].Audience != "api://machine" || reqs[0].Resource != other.URL() {
		t.Fatalf("token requests = %+v", reqs)
	}
	for _, a := range other.RequestAuths() {
		if a.Authorization != "Bearer "+e.token(0) {
			t.Errorf("discovery sent %+v", a)
		}
	}
	// The same server read through the lists.
	var list apitypes.McpServerPage
	if code := e.owner.get(toolsTeam+"/mcp-servers", &list); code != 200 {
		t.Fatal(code)
	}
	found := false
	for _, s := range list.Items {
		if s.Slug == "machine" {
			found = s.MachineOAuth != nil && s.MachineOAuth.TokenUrl == e.as.URL+"/token"
		}
	}
	if !found {
		t.Errorf("list = %+v", list.Items)
	}
	audit := e.scalar(`SELECT string_agg(after_state::text || metadata::text, '|') FROM audit_log WHERE action = 'mcp_server.auth_update'`)
	if !strings.Contains(audit, e.as.URL+"/token") || !strings.Contains(audit, "api://machine") || !strings.Contains(audit, `"clientSecretChanged": true`) {
		t.Errorf("audit = %s", audit)
	}
	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
	e.assertNoSecrets("the audit log", audit)
	if dump := e.scalar(`SELECT encode(client_secret_cipher, 'escape') FROM mcp_server_machine_oauth`); strings.Contains(dump, "SENTINEL") {
		t.Errorf("the secret is stored in the clear")
	}

	// What can't be saved.
	for name, c := range map[string]struct {
		body  map[string]any
		code  int
		ecode string
	}{
		"no client":                 {map[string]any{"authMode": "machine_oauth"}, 400, "invalid_machine_oauth"},
		"no secret":                 {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c"}}, 422, "client_secret_required"},
		"an input without the mode": {map[string]any{"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s"}}, 400, "invalid_machine_oauth"},
		"http token url":            {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": "http://idp.example.com/token", "clientId": "c", "clientSecret": "s"}}, 422, "url_not_allowed"},
		"a token url with a query":  {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token?x=1", "clientId": "c", "clientSecret": "s"}}, 422, "url_not_allowed"},
		"userinfo in the token url": {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": "https://user:pw@idp.example.com/token", "clientId": "c", "clientSecret": "s"}}, 422, "url_not_allowed"},
		"a bad method":              {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s", "tokenAuthMethod": "none"}}, 400, "invalid_token_auth_method"},
		"a bad resource":            {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s", "resource": "not a uri"}}, 400, "invalid_resource"},
		"a bad scope":               {map[string]any{"authMode": "machine_oauth", "machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s", "scopes": []string{"a b"}}}, 400, "invalid_scope"},
		"a static Authorization header": {map[string]any{"authMode": "machine_oauth", "authHeaderName": "Authorization", "authValue": "Bearer x-1234567890",
			"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s"}}, 422, "auth_conflict"},
		"a bearer part": {map[string]any{"authMode": "machine_oauth", "credentials": []any{map[string]any{"kind": "bearer", "value": "x-1234567890"}},
			"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": "c", "clientSecret": "s"}}, 422, "auth_conflict"},
	} {
		b := map[string]any{"slug": "bad", "name": "Bad", "url": e.fake.URL()}
		for k, v := range c.body {
			b[k] = v
		}
		code, raw := e.editor.raw("POST", toolsTeam+"/mcp-servers", b, nil)
		if code != c.code || errorCode(raw) != c.ecode {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}
	// Another static part (not Authorization) can stay next to the machine token.
	b := map[string]any{"slug": "tenant", "name": "Tenant", "url": other.URL(), "authMode": "machine_oauth", "credentials": []any{map[string]any{"kind": "header", "name": "X-Tenant", "value": "tenant-1234567890"}},
		"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token", "clientId": e.as.ClientID, "clientSecret": machineSecret, "resource": other.URL()}}
	if code, raw := e.editor.raw("POST", toolsTeam+"/mcp-servers", b, nil); code != 201 {
		t.Errorf("a machine server with a tenant header = %d %s", code, raw)
	}
	if reqs := other.HTTPRequests(); reqs[len(reqs)-1].Header.Get("X-Tenant") != "tenant-1234567890" ||
		!strings.HasPrefix(reqs[len(reqs)-1].Header.Get("Authorization"), "Bearer fmt_") {
		t.Errorf("the last request = %v", reqs[len(reqs)-1].Header)
	}
}

// F-1: the client secret goes to the token endpoint it was entered for. Another
// token endpoint, another client or a server URL with another origin needs it
// entered again, in the same request; until then nothing is stored and
// nothing is sent to the new place.
func TestMachineOAuthSecretDoesNotFollowEndpointClientOrOrigin(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	evilAS := testutil.NewFakeOAuth(t)
	evilMCP := testutil.NewFakeMCP(t)
	e.mustPatch(e.editor, map[string]any{}) // a request that changes nothing writes nothing
	cur := e.get(e.owner)
	stored := e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`)
	n := e.tokenRequests()

	refuse := func(what, reason string, body map[string]any) {
		t.Helper()
		code, raw := e.patch(e.editor, body)
		d := errorDetails(raw)
		if code != 422 || errorCode(raw) != "client_secret_required" || d["reason"] != reason || d["field"] != "machineOAuth.clientSecret" {
			t.Errorf("%s = %d %s", what, code, raw)
		}
	}
	refuse("another token endpoint", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token"}})
	refuse("another token path", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token/v2"}})
	refuse("another client", "client_id_changed", map[string]any{"machineOAuth": map[string]any{"clientId": "another-client"}})
	refuse("another origin of the server", "origin_changed", map[string]any{"url": evilMCP.URL()})
	refuse("another origin of the server with other fields", "origin_changed", map[string]any{"url": evilMCP.URL(), "name": "Renamed",
		"machineOAuth": map[string]any{"scopes": []string{"read"}}})
	// Switching the mode off and on again starts from nothing: the secret too.
	e.mustPatch(e.editor, map[string]any{"authMode": "none"})
	code, raw := e.patch(e.editor, map[string]any{"authMode": "machine_oauth"})
	if code != 400 || errorCode(raw) != "invalid_machine_oauth" {
		t.Errorf("back to the mode without a client = %d %s", code, raw)
	}
	e.mustPatch(e.editor, e.machine(nil))
	n = e.tokenRequests()
	cur = e.get(e.owner)
	stored = e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`)
	refuse("another token endpoint again", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token"}})

	if evilAS.TokenRequests() != 0 || evilMCP.Requests() != 0 || len(evilMCP.HTTPRequests()) != 0 || e.tokenRequests() != n {
		t.Fatalf("a refused change reached the new place: token endpoint %d, server %d, own endpoint %d",
			evilAS.TokenRequests(), evilMCP.Requests(), e.tokenRequests()-n)
	}
	if got := e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`); got != stored {
		t.Errorf("a refused change changed the stored client")
	}
	if now := e.get(e.owner); now.Revision != cur.Revision || now.Url != cur.Url {
		t.Errorf("a refused change changed the server: %+v", now)
	}

	// With the secret entered again the endpoint moves, and the new
	// endpoint (and only it) gets the secret and issues the token.
	evilAS.Set(func(f *testutil.FakeOAuth) { f.ClientSecret, f.ClientID = "second-secret-0123456789", "second-client" })
	e.protect(evilAS) // the server now trusts the new authorization server
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token", "clientId": "second-client",
		"clientSecret": "second-secret-0123456789"}})
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh with the new client = %d %s", code, raw)
	}
	reqs := evilAS.ClientCredentialsRequests()
	if len(reqs) != 1 || reqs[0].ClientSecret != "second-secret-0123456789" || !reqs[0].Authorized || e.tokenRequests() != n {
		t.Fatalf("the new endpoint got %+v (the old one %d more)", reqs, e.tokenRequests()-n)
	}
	for _, a := range e.fake.RequestAuths()[len(e.fake.RequestAuths())-1:] {
		if a.Authorization != "Bearer "+evilAS.Issued()[0] {
			t.Errorf("the server was sent %q, not the new token", a.Authorization)
		}
	}
	// The old secret is gone: the audit entry says the endpoint and client changed.
	if got := e.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'mcp_server.auth_update' ORDER BY id DESC LIMIT 1`); !strings.Contains(got, `"tokenUrlChanged": true`) ||
		!strings.Contains(got, `"clientIdChanged": true`) || !strings.Contains(got, `"clientSecretChanged": true`) {
		t.Errorf("audit metadata = %s", got)
	}

	// The same for the origin of the server's URL: with the secret entered
	// again the move works and the new host gets the new token only.
	evilMCP.Protect(testutil.Protection{Issuer: evilAS.Issuer(), Introspect: func(_ context.Context, tok string) testutil.Introspection { return evilAS.Introspect(tok) }})
	e.mustPatch(e.editor, map[string]any{"url": evilMCP.URL(), "machineOAuth": map[string]any{"clientSecret": "second-secret-0123456789",
		"resource": evilMCP.URL()}})
	moved := e.get(e.owner)
	if moved.Url != evilMCP.URL() || moved.RefreshedAt == nil || moved.LastRefreshError != nil {
		t.Fatalf("after the move: %+v", moved)
	}
	for _, a := range evilMCP.RequestAuths() {
		if !strings.HasPrefix(a.Authorization, "Bearer fmt_") || a.Authorization == "Bearer "+e.token(0) {
			t.Errorf("the new host was sent %q", a.Authorization)
		}
	}
	// A path-only change of the URL keeps the secret.
	e.mustPatch(e.editor, map[string]any{"url": evilMCP.URL() + "/"})
	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
}

// Concurrent calls share one token request; a token the server rejects is
// replaced once and the call retried once; a second rejection is class auth.
func TestMachineOAuthConcurrencyAndRenewal(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	e.approve()
	e.as.Set(func(f *testutil.FakeOAuth) { f.TokenDelay = 300 * time.Millisecond })
	before := len(e.fake.ToolCalls())
	var wg sync.WaitGroup
	codes := make([]int, 15)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out := e.callTool(e.key.Secret, "status__whoami", nil)
			if out["error"] != nil {
				code = -1
			}
			codes[i] = code
		}()
	}
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("a concurrent call failed: %v", codes)
		}
	}
	if e.tokenRequests() != 1 || len(e.fake.ToolCalls()) != before+15 {
		t.Fatalf("15 concurrent calls: %d token requests, %d calls ran", e.tokenRequests(), len(e.fake.ToolCalls())-before)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.TokenDelay = 0 })

	// The authorization server ends every token (a revocation the portal
	// doesn't know about): one 401, one new token, one retry; the tool ran once.
	e.as.InvalidateAll(false)
	calls, https := len(e.fake.ToolCalls()), len(e.fake.RequestAuths())
	if code, out := e.callTool(e.key.Secret, "status__whoami", nil); code != 200 || out["error"] != nil {
		t.Fatalf("call after revocation = %d %v", code, out)
	}
	if e.tokenRequests() != 2 || len(e.fake.ToolCalls()) != calls+1 {
		t.Fatalf("after a revocation: %d token requests, %d tool runs", e.tokenRequests(), len(e.fake.ToolCalls())-calls)
	}
	bs := bearersSince(e.fake, https)
	if len(bs) < 2 || bs[0] != "Bearer "+e.token(0) || bs[len(bs)-1] != "Bearer "+e.token(1) {
		t.Fatalf("the retry used %v", bs)
	}
	e.recorded("ok ")

	// Several calls rejected together share one renewal.
	e.as.InvalidateAll(false)
	e.as.Set(func(f *testutil.FakeOAuth) { f.TokenDelay = 200 * time.Millisecond })
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, out := e.callTool(e.key.Secret, "status__whoami", nil)
			if out["error"] != nil {
				code = -1
			}
			codes[i] = code
		}()
	}
	wg.Wait()
	for _, c := range codes {
		if c != 200 {
			t.Fatalf("a call rejected together with others failed: %v", codes)
		}
	}
	if e.tokenRequests() != 3 {
		t.Fatalf("15 rejected calls made %d token requests, want 1 more", e.tokenRequests()-2)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.TokenDelay = 0 })

	// A server that rejects the freshly issued token too: one renewal, one
	// retry, then class auth, and nobody sees a token.
	e.fake.SetProtection(func(p *testutil.Protection) { p.Resource = "https://elsewhere.example/mcp" })
	n, calls := e.tokenRequests(), len(e.fake.ToolCalls())
	code, out := e.callTool(e.key.Secret, "status__whoami", nil)
	if code != 200 || out["error"] == nil || e.tokenRequests() != n+1 || len(e.fake.ToolCalls()) != calls {
		t.Fatalf("a server that rejects every token: %d %v, %d token requests, %d runs", code, out, e.tokenRequests()-n, len(e.fake.ToolCalls())-calls)
	}
	e.recorded("upstream_error auth")
	e.fake.SetProtection(func(p *testutil.Protection) { p.Resource = "" })

	// Discovery does the same: a rejected token is replaced once.
	e.as.InvalidateAll(false)
	n = e.tokenRequests()
	if code, raw := e.refreshRaw(e.owner); code != 200 || e.tokenRequests() != n+1 {
		t.Fatalf("refresh after a revocation = %d %s (%d token requests)", code, raw, e.tokenRequests()-n)
	}
	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
}

// A token endpoint that is down is -32010 machine_auth_unavailable and the
// call never reaches the server; a refused client is class auth; Test and
// health checks say the same; nothing says what the authorization server wrote.
func TestMachineOAuthFailures(t *testing.T) {
	e := newMachineEnv(t)
	ctx := context.Background()
	e.mustPatch(e.editor, e.machine(nil))
	e.approve()
	e.fake.SetProtection(func(p *testutil.Protection) {})
	httpBefore := func() int { return len(e.fake.RequestAuths()) }

	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "unavailable" })
	n := httpBefore()
	code, out := e.callTool(e.key.Secret, "status__whoami", nil)
	rc, msg, data := rpcErr(out)
	if code != 200 || rc != -32010 || data["reason"] != "machine_auth_unavailable" || strings.Contains(msg, "token endpoint says") {
		t.Fatalf("token endpoint down: %d %v", code, out)
	}
	if httpBefore() != n {
		t.Errorf("the call reached the server without a token")
	}
	e.recorded("upstream_error unavailable")
	wantFailure(t, "test with the endpoint down", e.test(e.editor), "unavailable", "unavailable")
	if _, err := e.reg.RunHealthChecks(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if h := e.get(e.owner).Health; h.Status != "failing" || h.ErrorClass == nil || *h.ErrorClass != "unavailable" {
		t.Fatalf("health with the endpoint down = %+v", h)
	}
	if code, raw := e.refreshRaw(e.owner); code != 502 || errorCode(raw) != "discovery_failed" {
		t.Fatalf("refresh with the endpoint down = %d %s", code, raw)
	}

	// A client the authorization server refuses: auth, with the OAuth error code only.
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "invalid_client" })
	code, out = e.callTool(e.key.Secret, "status__whoami", nil)
	rc, msg, _ = rpcErr(out)
	if code != 200 || rc == -32010 || !strings.Contains(msg, "invalid_client") || strings.Contains(msg, "fake provider says no") {
		t.Fatalf("refused client: %d %v", code, out)
	}
	e.recorded("upstream_error auth")
	wantFailure(t, "test with a refused client", e.test(e.editor), "auth", "invalid_client")

	// A wrong secret is refused the same way (the authorization server's own check).
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "" })
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"clientSecret": "wrong-secret-SENTINEL-9999"}})
	wantFailure(t, "test with a wrong secret", e.test(e.editor), "auth", "invalid_client")
	// An invalid scope is refused too.
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"clientSecret": machineSecret, "scopes": []string{"admin"}}})
	wantFailure(t, "test with an invalid scope", e.test(e.editor), "auth", "invalid_scope")
	// Back to working: nothing was cached for the failures.
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"scopes": []string{"read"}}})
	if res := e.test(e.editor); !res.Ok {
		t.Fatalf("test after the fix = %+v", res)
	}
	if code, out := e.callTool(e.key.Secret, "status__whoami", nil); code != 200 || out["error"] != nil {
		t.Fatalf("call after the fix = %d %v", code, out)
	}

	// A token of the wrong type, and an answer without a token, are no token.
	e.forget()
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "wrong_type" })
	wantFailure(t, "test with a DPoP token", e.test(e.editor), "auth", "unsupported_token_type")
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "invalid_response" })
	wantFailure(t, "test with an empty answer", e.test(e.editor), "unavailable", "invalid_response")
	// An authorization server that doesn't offer the grant.
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials, f.NoClientCredentials = "", true })
	wantFailure(t, "test without the grant", e.test(e.editor), "auth", "unsupported_grant_type")

	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
	e.assertNoSecrets("the stored errors", e.scalar(`SELECT coalesce(string_agg(coalesce(last_refresh_error, ''), '|'), '') || (SELECT coalesce(string_agg(message, '|'), '') FROM mcp_health_checks) FROM mcp_servers`))
	e.assertNoSecrets("the call records", e.scalar(`SELECT coalesce(string_agg(to_jsonb(c)::text, E'\n'), '') FROM mcp_calls c`))
	if strings.Contains(e.logs.String(), "fake provider says no") {
		t.Error("the logs hold what the authorization server wrote")
	}
}

// The token endpoint is checked against the address rules when it is saved
// and at every request: a URL that stopped being allowed is not dialled.
func TestMachineOAuthTokenEndpointAddressRules(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	e.approve()
	// Stored with a URL the rules refuse (the allowlist changed, or the row was
	// edited; plain http is only allowed to loopback): the call fails as
	// not_allowed and nothing is dialled. Blocked addresses, DNS answers that
	// change and redirects are covered in internal/upstream's tests, which can
	// turn the development allowance off.
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_server_machine_oauth SET token_url = 'http://idp.example.com/token'`); err != nil {
		t.Fatal(err)
	}
	n := e.as.TokenRequests()
	wantFailure(t, "test with a blocked token endpoint", e.test(e.editor), "not_allowed", "unavailable")
	code, out := e.callTool(e.key.Secret, "status__whoami", nil)
	if _, _, data := rpcErr(out); code != 200 || data["reason"] != "machine_auth_unavailable" {
		t.Fatalf("call with a blocked token endpoint = %d %v", code, out)
	}
	e.recorded("upstream_error not_allowed")
	if e.as.TokenRequests() != n {
		t.Errorf("a blocked token endpoint was requested")
	}
}

// Detection says whether the authorization server offers the grant.
func TestMachineOAuthDetect(t *testing.T) {
	e := newMachineEnv(t)
	var r apitypes.DetectAuthResult
	code, ec := e.editor.call("POST", toolsTeam+"/mcp-servers/detect-auth", map[string]any{"url": e.fake.URL()}, &r, nil)
	mustCode(t, "detect", code, ec, 200, "")
	if r.MachineOAuth == nil || !r.MachineOAuth.ClientCredentials || !r.MachineOAuth.GrantTypesListed || r.MachineOAuth.TokenEndpoint != e.as.URL+"/token" ||
		r.MachineOAuth.Resource != e.fake.URL() || len(r.MachineOAuth.TokenAuthMethods) != 2 {
		t.Fatalf("detect = %+v", r.MachineOAuth)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.NoClientCredentials = true })
	code, ec = e.editor.call("POST", toolsTeam+"/mcp-servers/detect-auth", map[string]any{"url": e.fake.URL()}, &r, nil)
	mustCode(t, "detect without the grant", code, ec, 200, "")
	if r.MachineOAuth == nil || r.MachineOAuth.ClientCredentials || !r.MachineOAuth.GrantTypesListed {
		t.Fatalf("detect without the grant = %+v", r.MachineOAuth)
	}
}

// No token or credential of any kind reaches a response, log, audit entry,
// call record or captured payload, even from a server that echoes its
// credentials and from calls that fail.
func TestMachineOAuthSentinels(t *testing.T) {
	e := newMachineEnv(t)
	ctx := context.Background()
	e.mustPatch(e.editor, e.machine(nil))
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	e.approve()
	// Put the echoing tools (approved with the server) on the gateway and record
	// the contents of calls.
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "echo_secrets"),
		e.capID(e.owner, e.server, "tool", "echo_tokens")))
	g := e.gateway(e.owner, e.supportTeamPath)
	if code, ec := e.owner.call("PATCH", e.supportTeamPath, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision)); code != 200 {
		t.Fatalf("capture: %d %s", code, ec)
	}
	for _, tool := range []string{"status__echo_secrets", "status__echo_tokens"} {
		code, out := e.callTool(e.key.Secret, tool, map[string]any{"note": "a harmless note"})
		if code != 200 || out["error"] != nil {
			t.Fatalf("%s = %d %v", tool, code, out)
		}
		text := resultTextOf(out)
		if strings.Contains(text, e.token(0)) || strings.Contains(text, machineSecret) {
			t.Errorf("%s returned a credential to the client: %s", tool, text)
		}
	}
	// What the server echoed back, as the person saw it and as it was captured.
	callID := ""
	for range 100 {
		if callID = e.scalar(`SELECT coalesce(max(call_id)::text, '') FROM mcp_call_payloads`); callID != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	_, payload := e.admin.raw("GET", "/v1/admin/calls/"+callID+"/payload", nil, nil)
	if !strings.Contains(string(payload), "REDACTED") {
		t.Fatalf("payload = %s", payload)
	}
	e.seen = append(e.seen, string(payload))
	e.assertNoSecrets("a response or payload", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
	e.assertNoSecrets("the audit log", e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`))
	e.assertNoSecrets("the call records", e.scalar(`SELECT coalesce(string_agg(to_jsonb(c)::text, E'\n'), '') FROM mcp_calls c`))
	e.assertNoSecrets("the stored payloads", e.scalar(`SELECT coalesce(string_agg(encode(arguments_cipher, 'escape') || encode(result_cipher, 'escape'), E'\n'), '') FROM mcp_call_payloads`))
	_ = ctx
}

// The secret is bound to its server (AAD): a ciphertext moved to another row
// doesn't open, and a key that can't open it is a config error, not a leak.
func TestMachineOAuthSecretIsBoundToItsServer(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	other := e.createServer(e.owner, "tools", "second", e.otherFake.URL(), nil)
	if _, err := e.app.Pool.Exec(context.Background(), `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher)
		SELECT $1, token_url, client_id, client_secret_cipher FROM mcp_server_machine_oauth`, other.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE id = $1`, other.Id); err != nil {
		t.Fatal(err)
	}
	code, raw := e.owner.raw("POST", toolsTeam+"/mcp-servers/"+other.Id.String()+"/test", nil, nil)
	if code != 200 || !strings.Contains(string(raw), "can't be decrypted") || strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("a ciphertext of another server opened: %d %s", code, raw)
	}
}

// The token request is observable without a token in it: omp_machine_token_requests_total
// counts requests (not cache hits) by result, and the span of a token request
// carries only the allowed attributes and a class, never a token, secret or URL.
func TestMachineOAuthMetricsAndSpans(t *testing.T) {
	e := newMachineEnv(t)
	sr := tracingOn(t)
	count := func(result string) float64 {
		return promtest.ToFloat64(observability.MachineTokenRequests.WithLabelValues(result))
	}
	ok0, refused0, down0 := count("ok"), count("refused"), count("unavailable")
	e.mustPatch(e.editor, e.machine(nil))
	e.approve()
	for range 3 {
		if code, out := e.callTool(e.key.Secret, "status__whoami", nil); code != 200 || out["error"] != nil {
			t.Fatalf("call = %d %v", code, out)
		}
	}
	if count("ok")-ok0 != 1 {
		t.Fatalf("ok token requests = %v, want 1 (the cache serves the rest)", count("ok")-ok0)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "invalid_client" })
	e.forget()
	e.callTool(e.key.Secret, "status__whoami", nil)
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "unavailable" })
	e.forget()
	e.callTool(e.key.Secret, "status__whoami", nil)
	if count("refused")-refused0 != 1 || count("unavailable")-down0 != 1 {
		t.Fatalf("refused %v, unavailable %v", count("refused")-refused0, count("unavailable")-down0)
	}
	allowed := map[string]bool{}
	for _, k := range observability.AllowedAttributeKeys() {
		allowed[k] = true
	}
	var token []string
	for _, sp := range sr.Ended() {
		if sp.Name() != "upstream.machine_token" {
			continue
		}
		token = append(token, sp.Name())
		texts := []string{sp.Name(), sp.Status().Description}
		for _, a := range sp.Attributes() {
			if !allowed[string(a.Key)] {
				t.Errorf("the token span carries %s", a.Key)
			}
			texts = append(texts, a.Value.Emit())
		}
		for _, text := range texts {
			for _, bad := range append(e.sentinels(), "127.0.0.1", "/token", e.as.ClientID) {
				if strings.Contains(text, bad) {
					t.Errorf("a token span holds %q: %q", bad, text)
				}
			}
		}
	}
	if len(token) != 3 {
		t.Fatalf("%d token spans, want 3", len(token))
	}
}

// An automation token can't choose where a client secret goes: it may not
// create a server in machine_oauth mode, send machineOAuth or switch a server
// to it, even on a server without credentials (decision 58, decision 73).
func TestMachineOAuthIsSessionOnlyForTokens(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	machine := map[string]any{"tokenUrl": "https://idp.example.com/token", "clientId": "c", "clientSecret": "token-sentinel-secret"}
	field := func(body []byte) string {
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if env.Error.Code != "token_not_allowed" {
			return env.Error.Code
		}
		return env.Error.Details.Field
	}
	create := func(extra map[string]any) (int, []byte) {
		b := map[string]any{"slug": "from-ci", "name": "From CI", "url": e.fakeURL}
		for k, v := range extra {
			b[k] = v
		}
		code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", b))
		return code, body
	}
	for name, c := range map[string]struct {
		extra map[string]any
		field string
	}{
		"machineOAuth with the mode": {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"machineOAuth alone":         {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"the mode alone":             {map[string]any{"authMode": "machine_oauth"}, "authMode"},
	} {
		if code, body := create(c.extra); code != 403 || field(body) != c.field || strings.Contains(string(body), "token-sentinel-secret") {
			t.Errorf("create with %s = %d %s", name, code, body)
		}
	}
	if n := e.exec(`SELECT count(*)::text FROM mcp_servers WHERE slug = 'from-ci'`); n != "0" {
		t.Errorf("a refused create stored a server")
	}
	// Updates: on a server without credentials too.
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"machineOAuth":        {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"the mode":            {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"the mode alone":      {map[string]any{"authMode": "machine_oauth"}, "authMode"},
		"a null machineOAuth": {map[string]any{"machineOAuth": nil}, "machineOAuth"},
	} {
		if code, _, body := e.bearer(pub.secret, patch(path, c.body).h(rev())); code != 403 || field(body) != c.field {
			t.Errorf("update with %s = %d %s", name, code, body)
		}
	}
	// A server already in the mode is protected as one with credentials: the
	// token can't re-point it, change its client or leave the mode.
	e.run(`UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE id = $1`, srv)
	e.run(`INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) VALUES ($1, 'https://idp.example.com/token', 'c', '\x00')`, srv)
	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"the url":         {map[string]any{"url": "https://attacker.example.com/mcp"}, "url"},
		"the mode":        {map[string]any{"authMode": "none"}, "authMode"},
		"the client":      {map[string]any{"machineOAuth": map[string]any{"scopes": []string{"x"}}}, "machineOAuth"},
		"sendIdentity":    {map[string]any{"sendIdentity": false}, "sendIdentity"},
		"a static header": {map[string]any{"authHeaderName": "X-Key", "authValue": "x-1234567890"}, "authHeaderName"},
	} {
		if code, _, body := e.bearer(pub.secret, patch(path, c.body).h(rev())); code != 403 || field(body) != c.field {
			t.Errorf("update of a machine server: %s = %d %s", name, code, body)
		}
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "still fine"}).h(rev())); code != 200 {
		t.Errorf("a harmless field = %d %s", code, body)
	}
	if got := e.exec(`SELECT token_url || client_id FROM mcp_server_machine_oauth WHERE server_id = $1`, srv); got != "https://idp.example.com/tokenc" {
		t.Errorf("a token changed the client: %s", got)
	}
}
