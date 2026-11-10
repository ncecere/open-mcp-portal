package httpapi_test

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
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
