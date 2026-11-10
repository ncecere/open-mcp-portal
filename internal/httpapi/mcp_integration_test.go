package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The /mcp/{slug} runtime, end to end with the official SDK's client.

// syncBuffer collects log output from several goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// newKey creates an API key for s and returns its secret.
func newKey(t *testing.T, s *session, name string) apitypes.ApiKeyCreated {
	t.Helper()
	var out apitypes.ApiKeyCreated
	code, ec := s.call("POST", "/v1/me/api-keys", map[string]any{"name": name}, &out, nil)
	mustCode(t, "create key", code, ec, 201, "")
	return out
}

type bearer struct {
	token string
	next  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.next.RoundTrip(r)
}

// connect opens an SDK client session to a gateway with an API key, in the
// legacy era (initialize, 2025-11-25): what these tests have always
// exercised. The SDK now tries the 2026-07-28 era first; connectModern
// (mcp_modern_integration_test.go) does that.
func connect(t *testing.T, app *testApp, slug, key string) *mcp.ClientSession {
	t.Helper()
	return connectEra(t, app, slug, key, "2025-11-25", nil)
}

// connectEra opens a session asking for protocolVersion ("": the SDK's
// newest), with optional client options.
func connectEra(t *testing.T, app *testApp, slug, key, protocolVersion string, opts *mcp.ClientOptions) *mcp.ClientSession {
	t.Helper()
	if opts == nil {
		opts = &mcp.ClientOptions{}
	}
	opts.Logger = slog.New(slog.DiscardHandler)
	client := mcp.NewClient(&mcp.Implementation{Name: "gateway-test", Version: "1.0.0"}, opts)
	tr := &mcp.StreamableClientTransport{Endpoint: app.URL + "/mcp/" + slug, MaxRetries: -1, DisableStandaloneSSE: true,
		HTTPClient: &http.Client{Transport: bearer{token: key, next: http.DefaultTransport}, Timeout: 30 * time.Second}}
	cs, err := client.Connect(context.Background(), tr, &mcp.ClientSessionOptions{ProtocolVersion: protocolVersion})
	if err != nil {
		t.Fatalf("connect %s: %v", slug, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	out := []string{}
	for _, tool := range res.Tools {
		out = append(out, tool.Name)
	}
	return out
}

func resultText(t *testing.T, res *mcp.CallToolResult) string {
	t.Helper()
	if len(res.Content) != 1 {
		t.Fatalf("content = %+v", res.Content)
	}
	tc, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content = %T", res.Content[0])
	}
	return tc.Text
}

// rawMCP posts one JSON-RPC message to /mcp/{slug}.
func rawMCP(t *testing.T, app *testApp, method, slug, key string, body any, headers map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, app.URL+"/mcp/"+slug, rdr)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return res.StatusCode, res.Header, out
}

func rpc(id int, method string, params any) map[string]any {
	m := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		m["params"] = params
	}
	return m
}

func rpcErrorCode(out map[string]any) float64 {
	e, _ := out["error"].(map[string]any)
	c, _ := e["code"].(float64)
	return c
}

func (e *gwEnv) userID(email string) string {
	e.t.Helper()
	var id string
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT id::text FROM users WHERE email = $1`, email).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

func (e *gwEnv) scalar(sql string, args ...any) string {
	e.t.Helper()
	var out string
	if err := e.app.Pool.QueryRow(context.Background(), sql, args...).Scan(&out); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

func TestMCPEndToEnd(t *testing.T) {
	logs := &syncBuffer{}
	e := newGwEnv(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	jwks := e.app.URL + "/.well-known/jwks.json"
	e.fake.SetJWKS(jwks, e.fake.URL())

	// A second server whose static header is Authorization: the identity
	// goes in MCP-Gateway-Identity instead (decision 19).
	authFake := testutil.NewFakeMCP(t)
	authFake.EnableGatewayTools()
	authFake.SetJWKS(jwks, authFake.URL())
	authFake.RequireHeader("Authorization", "Bearer static-1234567890")
	authServer := e.createServer(e.owner, "tools", "authed", authFake.URL(),
		map[string]any{"authHeaderName": "Authorization", "authValue": "Bearer static-1234567890"})

	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	gwPath := toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(
		e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "echo"),
		e.capID(e.owner, e.server, "tool", "check_outage")+":admin", e.capID(e.owner, e.server, "prompt", "incident_summary"),
		e.capID(e.owner, authServer, "tool", "whoami")))
	key := newKey(t, e.member, "laptop")
	blairID := e.userID("blair@localhost")

	cs := connect(t, e.app, "support", key.Secret)
	if init := cs.InitializeResult(); init.ProtocolVersion != "2025-11-25" || init.Capabilities.Tools == nil ||
		init.Capabilities.Prompts == nil || init.Capabilities.Resources != nil || init.ServerInfo.Name != "support" {
		t.Fatalf("initialize = %+v", init)
	}
	// Only what blair may use: check_outage needs admin.
	if got := toolNames(t, cs); !slices.Equal(got, []string{"authed__whoami", "status__echo", "status__whoami"}) {
		t.Fatalf("tools = %v", got)
	}
	tools, _ := cs.ListTools(context.Background(), nil)
	for _, tool := range tools.Tools {
		if tool.Name == "status__echo" && (tool.Description != "Returns its text." || tool.InputSchema == nil) {
			t.Errorf("echo definition = %+v", tool)
		}
	}
	prompts, err := cs.ListPrompts(context.Background(), nil)
	if err != nil || len(prompts.Prompts) != 1 || prompts.Prompts[0].Name != "status__incident_summary" {
		t.Fatalf("prompts = %+v %v", prompts, err)
	}

	// whoami: the server received a JWT that verifies against our JWKS, for
	// its own URL, valid for at most five minutes, and never the API key.
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
	if err != nil || res.IsError {
		t.Fatalf("whoami: %v %+v", err, res)
	}
	var who testutil.WhoamiResult
	if err := json.Unmarshal([]byte(resultText(t, res)), &who); err != nil {
		t.Fatal(err)
	}
	c := who.Claims
	if !who.Verified || who.Header != "Authorization" || c["aud"] != e.fake.URL() || c["sub"] != blairID || c["iss"] != e.app.URL ||
		c["gateway"] != "support" || c["tool"] != "status__whoami" || c["email"] != "blair@localhost" || c["client"] != "laptop" {
		t.Fatalf("whoami = %+v", who)
	}
	if exp, iat := c["exp"].(float64), c["iat"].(float64); exp-iat > 300 || exp-iat <= 0 {
		t.Fatalf("lifetime = %v", exp-iat)
	}
	if teams, _ := c["teams"].([]any); len(teams) != 1 || teams[0] != "tools" {
		t.Fatalf("teams = %v", c["teams"])
	}
	seen := e.fake.ToolCalls()
	if len(seen) != 1 || !strings.HasPrefix(seen[0].Authorization, "Bearer ey") {
		t.Fatalf("fake saw %+v", seen)
	}
	var claims struct {
		Gateway string `json:"gateway"`
	}
	if err := testutil.VerifyIdentity(context.Background(), strings.TrimPrefix(seen[0].Authorization, "Bearer "), jwks, e.fake.URL(), &claims); err != nil ||
		claims.Gateway != "support" {
		t.Fatalf("verify: %v %+v", err, claims)
	}
	if testutil.VerifyIdentity(context.Background(), strings.TrimPrefix(seen[0].Authorization, "Bearer "), jwks, "https://elsewhere.example/mcp", nil) == nil {
		t.Fatal("a token for another server verified")
	}
	for name, values := range seen[0].Header {
		for _, v := range values {
			if strings.Contains(v, key.Secret) || strings.Contains(v, "omp_") {
				t.Fatalf("the client's key reached the server in %s", name)
			}
		}
	}

	// The static Authorization header stays; the identity moves aside.
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "authed__whoami"})
	if err != nil || res.IsError {
		t.Fatalf("authed whoami: %v %+v", err, res)
	}
	who = testutil.WhoamiResult{}
	_ = json.Unmarshal([]byte(resultText(t, res)), &who)
	if !who.Verified || who.Header != "MCP-Gateway-Identity" || who.Claims["aud"] != authFake.URL() {
		t.Fatalf("authed whoami = %+v", who)
	}
	if got := authFake.ToolCalls(); len(got) != 1 || got[0].Authorization != "Bearer static-1234567890" || got[0].Identity == "" {
		t.Fatalf("authed fake saw %+v", got)
	}

	// A capability above the caller's role is an unknown tool, and the
	// server never hears of it.
	before := e.fake.Requests()
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__check_outage", Arguments: map[string]any{"service": "x"}}); err == nil ||
		!strings.Contains(err.Error(), "Unknown tool") {
		t.Fatalf("check_outage = %v", err)
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__nope"}); err == nil {
		t.Fatal("unknown tool answered")
	}
	if e.fake.Requests() != before {
		t.Fatal("a refused call reached the server")
	}

	// Prompts are forwarded too.
	pr, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "status__incident_summary", Arguments: map[string]string{"service": "email"}})
	if err != nil || len(pr.Messages) != 1 || !strings.Contains(pr.Messages[0].Content.(*mcp.TextContent).Text, "email") {
		t.Fatalf("prompt = %+v %v", pr, err)
	}

	// Arguments and results pass through but are never recorded or logged.
	const sentinel = "SENTINEL-7c1e-secret-argument"
	res, err = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__echo", Arguments: map[string]any{"text": sentinel}})
	if err != nil || resultText(t, res) != sentinel {
		t.Fatalf("echo = %+v %v", res, err)
	}

	// The transport's edges.
	code, hdr, out := rawMCP(t, e.app, "POST", "support", "", rpc(1, "tools/list", nil), nil)
	if code != 401 || hdr.Get("WWW-Authenticate") != `Bearer resource_metadata="`+e.app.URL+`/.well-known/oauth-protected-resource/mcp/support"` {
		t.Fatalf("no key = %d %q %v", code, hdr.Get("WWW-Authenticate"), out)
	}
	code, hdr, _ = rawMCP(t, e.app, "POST", "support", "omp_"+strings.Repeat("x", 43), rpc(1, "tools/list", nil), nil)
	if code != 401 || !strings.Contains(hdr.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Fatalf("bad key = %d %q", code, hdr.Get("WWW-Authenticate"))
	}
	for _, m := range []string{"GET", "DELETE"} {
		if code, hdr, _ := rawMCP(t, e.app, m, "support", key.Secret, nil, nil); code != 405 || hdr.Get("Allow") != "POST" {
			t.Errorf("%s = %d", m, code)
		}
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "nope", key.Secret, rpc(1, "tools/list", nil), nil); code != 404 {
		t.Errorf("unknown gateway = %d", code)
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", key.Secret, []any{rpc(1, "ping", nil)}, nil); code != 400 {
		t.Errorf("batch = %d", code)
	}
	if code, _, out := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(2, "resources/list", nil), nil); code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("resources/list = %d %v", code, out)
	}
	if code, _, out := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(3, "server/discover", nil), nil); code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("server/discover = %d %v", code, out)
	}
	if code, _, out := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(4, "ping", nil), nil); code != 200 || out["result"] == nil {
		t.Errorf("ping = %d %v", code, out)
	}
	for asked, want := range map[string]string{"2025-06-18": "2025-06-18", "2024-11-05": "2024-11-05", "1999-01-01": "2025-11-25"} {
		_, _, out := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(5, "initialize", map[string]any{"protocolVersion": asked,
			"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "raw", "version": "1"}}), nil)
		if r, _ := out["result"].(map[string]any); r["protocolVersion"] != want {
			t.Errorf("initialize %s = %v", asked, out)
		}
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(6, "tools/list", nil), map[string]string{"MCP-Protocol-Version": "2023-01-01"}); code != 400 {
		t.Errorf("unsupported protocol header = %d", code)
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", key.Secret, rpc(7, "tools/list", nil), map[string]string{"Origin": "https://evil.example"}); code != 403 {
		t.Errorf("foreign origin = %d", code)
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", key.Secret, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil); code != 202 {
		t.Errorf("notification = %d", code)
	}
	// clientInfo in a 2026-07-28 request's _meta is recorded.
	rawMCP(t, e.app, "POST", "support", key.Secret, rpc(8, "tools/list", map[string]any{
		"_meta": map[string]any{"io.modelcontextprotocol/clientInfo": map[string]any{"name": "raw-client", "version": "1"}}}), nil)
	if got := e.scalar(`SELECT coalesce(client_name, '') FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "raw-client" {
		t.Errorf("client name = %q", got)
	}

	// Records: metadata for every list and call; never the payloads.
	outcomes := e.scalar(`SELECT string_agg(method || ' ' || outcome || ' ' || coalesce(error_class, '-'), ', ' ORDER BY id) FROM mcp_calls`)
	for _, want := range []string{"tools/call ok -", "tools/call denied role", "tools/call denied unknown", "prompts/get ok -", "tools/list ok -", "prompts/list ok -"} {
		if !strings.Contains(outcomes, want) {
			t.Errorf("calls %q lack %q", outcomes, want)
		}
	}
	for what, text := range map[string]string{
		"mcp_calls": e.scalar(`SELECT string_agg(row_to_json(c)::text, '') FROM mcp_calls c`),
		"audit_log": e.scalar(`SELECT string_agg(row_to_json(a)::text, '') FROM audit_log a`),
		"api_keys":  e.scalar(`SELECT string_agg(row_to_json(k)::text, '') FROM api_keys k`),
		"logs":      logs.String(),
	} {
		if strings.Contains(text, sentinel) {
			t.Errorf("%s contains the call's arguments or result", what)
		}
		if strings.Contains(text, key.Secret) {
			t.Errorf("%s contains the API key", what)
		}
	}
	if e.scalar(`SELECT (last_used_at IS NOT NULL)::text FROM api_keys WHERE id = $1`, key.Key.Id) != "true" {
		t.Error("last_used_at not recorded")
	}
	if code := mustGet(t, e.app, "/.well-known/jwks.json"); code != 200 {
		t.Errorf("jwks = %d", code)
	}

	// The call log: the team's owners and admins and platform staff.
	var page apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls?outcome=denied", &page); code != 200 || len(page.Items) < 2 {
		t.Fatalf("denied calls = %d %+v", code, page)
	}
	for _, it := range page.Items {
		if it.Outcome != "denied" || it.Principal.Email == nil || *it.Principal.Email != "blair@localhost" || it.Principal.Kind != "api_key" || it.Principal.ApiKeyName == nil ||
			*it.Principal.ApiKeyName != "laptop" || it.Gateway.Slug != "support" || !it.Gateway.Exists {
			t.Errorf("call %+v", it)
		}
	}
	page = apitypes.McpCallPage{}
	e.owner.get(toolsTeam+"/calls?limit=2", &page)
	if len(page.Items) != 2 || page.NextCursor == nil {
		t.Fatalf("page 1 = %+v", page)
	}
	var page2 apitypes.McpCallPage
	e.owner.get(toolsTeam+"/calls?limit=2&cursor="+*page.NextCursor, &page2)
	if len(page2.Items) == 0 || page2.Items[0].Id >= page.Items[1].Id {
		t.Fatalf("page 2 = %+v", page2)
	}
	if code := e.member.get(toolsTeam+"/calls", nil); code != 403 {
		t.Errorf("member calls = %d", code)
	}
	if code := e.outsider.get(toolsTeam+"/calls", nil); code != 404 {
		t.Errorf("outsider calls = %d", code)
	}
	if code := e.owner.get(toolsTeam+"/calls?outcome=bogus", nil); code != 400 {
		t.Errorf("bad outcome = %d", code)
	}
	page = apitypes.McpCallPage{}
	if code := e.auditor.get("/v1/admin/calls?team=tools&gateway="+gw.Id.String()+"&server="+e.server.Id.String(), &page); code != 200 || len(page.Items) == 0 {
		t.Fatalf("admin calls = %d %+v", code, page)
	}
	for _, it := range page.Items {
		if it.Server == nil || it.Server.Slug != "status" {
			t.Errorf("filtered call %+v", it)
		}
	}
	page = apitypes.McpCallPage{}
	if e.auditor.get("/v1/admin/calls?team=nope", &page); len(page.Items) != 0 {
		t.Errorf("unknown team calls = %+v", page)
	}
	// Deleting the gateway keeps its records.
	code, ec := e.owner.call("DELETE", gwPath, nil, nil, nil)
	mustCode(t, "delete gateway", code, ec, 200, "")
	page = apitypes.McpCallPage{}
	e.auditor.get("/v1/admin/calls?limit=1", &page)
	if len(page.Items) != 1 || page.Items[0].Gateway.Exists || page.Items[0].Gateway.Slug != "support" {
		t.Fatalf("after delete = %+v", page)
	}
}

func mustGet(t *testing.T, app *testApp, path string) int {
	t.Helper()
	res, err := http.Get(app.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if !strings.Contains(res.Header.Get("Cache-Control"), "max-age") {
		t.Errorf("%s has no cache lifetime", path)
	}
	return res.StatusCode
}

// rtEnv is a published server, a team gateway "support" and a platform
// gateway "shared" (granted to blair only) both selecting whoami, and
// blair's key.
type rtEnv struct {
	*gwEnv
	support, shared string // admin paths
	supportTeamPath string
	grant           string
	key             apitypes.ApiKeyCreated
}

func newRuntimeEnv(t *testing.T) *rtEnv { return newRuntimeEnvHook(t, nil, nil) }

// newRuntimeEnvHook is newRuntimeEnv logging to log, with a hook that
// adjusts the services before the handler is built (nil: none).
func newRuntimeEnvHook(t *testing.T, log *slog.Logger, hook func(*httpapi.Deps)) *rtEnv {
	e := &rtEnv{gwEnv: newGwEnvHook(t, log, hook)}
	e.publish(e.owner, e.server)
	whoami := e.capID(e.owner, e.server, "tool", "whoami")
	support := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.supportTeamPath = toolsTeam + "/gateways/" + support.Id.String()
	e.support = "/v1/admin/gateways/" + support.Id.String()
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(whoami))
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	e.shared = "/v1/admin/gateways/" + shared.Id.String()
	e.mustSetCaps(e.admin, e.shared, sel(whoami))
	var g apitypes.GatewayGrant
	code, ec := e.admin.call("POST", e.shared+"/grants", map[string]any{"subjectKind": "user", "userEmail": "blair@localhost"}, &g, nil)
	mustCode(t, "grant", code, ec, 201, "")
	e.grant = g.Id.String()
	e.key = newKey(t, e.member, "laptop")
	return e
}

// Between tools/list and tools/call, any of these changes refuses the
// call without contacting the server, in both protocol eras.
func TestMCPRechecksBeforeEveryCall(t *testing.T) { testRechecksBeforeEveryCall(t, legacyVersion) }

func TestMCPRechecksBeforeEveryCallModern(t *testing.T) { testRechecksBeforeEveryCall(t, "") }

// testRechecksBeforeEveryCall runs the cases with an SDK client asking for
// protocolVersion ("": the SDK's newest, which is the modern era).
func testRechecksBeforeEveryCall(t *testing.T, protocolVersion string) {
	modern := protocolVersion == ""
	cases := []struct {
		name, gateway string
		unauthorized  bool
		mutate        func(e *rtEnv)
	}{
		{"remove grant", "shared", false, func(e *rtEnv) {
			code, ec := e.admin.call("DELETE", e.shared+"/grants/"+e.grant, nil, nil, nil)
			mustCode(e.t, "remove grant", code, ec, 200, "")
		}},
		{"remove from selection", "support", false, func(e *rtEnv) { e.mustSetCaps(e.owner, e.supportTeamPath, sel()) }},
		{"unpublish server", "shared", false, func(e *rtEnv) {
			code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers/"+e.server.Id.String()+"/unpublish", nil, nil, nil)
			mustCode(e.t, "unpublish", code, ec, 200, "")
		}},
		{"change fingerprint", "shared", false, func(e *rtEnv) {
			e.fake.SetDescription("whoami", "Now also does something else.")
			e.refresh(e.owner, e.server)
		}},
		{"disable gateway", "support", false, func(e *rtEnv) {
			code, ec := e.owner.call("PATCH", e.supportTeamPath, map[string]any{"enabled": false}, nil, ifMatch(e.gateway(e.owner, e.supportTeamPath).Revision))
			mustCode(e.t, "disable gateway", code, ec, 200, "")
		}},
		{"disable server", "support", false, func(e *rtEnv) { e.patchServer(e.owner, e.server, map[string]any{"enabled": false}) }},
		// The team gateway's own team: the gateway stops serving (404).
		{"archive gateway's team", "support", false, func(e *rtEnv) { e.setTeamStatus("tools", "archived") }},
		// The server's team: a platform gateway's capability is unavailable.
		{"archive server's team", "shared", false, func(e *rtEnv) { e.setTeamStatus("tools", "archived") }},
		{"suspend user", "support", true, func(e *rtEnv) {
			id := e.userID("blair@localhost")
			var u apitypes.UserDetail
			e.admin.get("/v1/admin/users/"+id, &u)
			code, ec := e.admin.call("PATCH", "/v1/admin/users/"+id, map[string]any{"status": "suspended"}, nil, ifMatch(u.User.Revision))
			mustCode(e.t, "suspend", code, ec, 200, "")
		}},
		{"revoke key", "support", true, func(e *rtEnv) {
			code, ec := e.member.call("DELETE", "/v1/me/api-keys/"+e.key.Key.Id.String(), nil, nil, nil)
			mustCode(e.t, "revoke", code, ec, 200, "")
		}},
		{"expire key", "support", true, func(e *rtEnv) {
			e.app.Pool.Exec(context.Background(), `UPDATE api_keys SET created_at = now() - interval '2 days', expires_at = now() - interval '1 day'`)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newRuntimeEnv(t)
			cs := connectEra(t, e.app, tc.gateway, e.key.Secret, protocolVersion, nil)
			if got := toolNames(t, cs); !slices.Equal(got, []string{"status__whoami"}) {
				t.Fatalf("tools = %v", got)
			}
			tc.mutate(e)
			requests, calls := e.fake.Requests(), len(e.fake.ToolCalls())
			_, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
			if err == nil {
				t.Fatal("the call went through")
			}
			if e.fake.Requests() != requests || len(e.fake.ToolCalls()) != calls {
				t.Fatal("the refused call reached the server")
			}
			code, _, _ := rawMCP(t, e.app, "POST", tc.gateway, e.key.Secret, rpc(1, "tools/call", map[string]any{"name": "status__whoami"}), nil)
			if modern {
				code, _, _ = rawModern(t, e.app, tc.gateway, e.key.Secret, "tools/call", map[string]any{"name": "status__whoami"}, nil, nil)
			}
			switch {
			case tc.unauthorized && code != 401:
				t.Fatalf("raw call = %d, want 401", code)
			case !tc.unauthorized && code != 200 && code != 404:
				t.Fatalf("raw call = %d, want not found", code)
			}
			if !tc.unauthorized {
				if got := e.scalar(`SELECT outcome FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "denied" {
					t.Fatalf("recorded %s", got)
				}
			}
			if strings.HasPrefix(tc.name, "archive") {
				if got := e.scalar(`SELECT coalesce(error_class, '') FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "team_archived" {
					t.Fatalf("recorded error class %q", got)
				}
				// Unarchiving restores it: nothing was changed.
				e.setTeamStatus("tools", "active")
				res, err := connectEra(t, e.app, tc.gateway, e.key.Secret, protocolVersion, nil).CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami"})
				if err != nil || res.IsError {
					t.Fatalf("after unarchiving: %+v %v", res, err)
				}
			}
		})
	}
}

func TestAPIKeys(t *testing.T) {
	e := newGwEnv(t, nil)
	k := newKey(t, e.member, "Claude Code on my laptop")
	if !strings.HasPrefix(k.Secret, "omp_") || len(k.Secret) != len("omp_")+43 || k.Key.Prefix != k.Secret[:len("omp_")+8] || k.Key.Status != "active" ||
		k.Key.ExpiresAt == nil || time.Until(*k.Key.ExpiresAt) < 89*24*time.Hour {
		t.Fatalf("key = %+v", k)
	}
	if n := e.scalar(`SELECT count(*)::text FROM api_keys WHERE position($1 in row_to_json(api_keys)::text) > 0`, k.Secret); n != "0" {
		t.Fatal("the secret is stored")
	}
	for _, body := range []map[string]any{{"name": ""}, {"name": "x", "expiresInDays": 0}, {"name": "x", "expiresInDays": 366}} {
		code, ec := e.member.call("POST", "/v1/me/api-keys", body, nil, nil)
		mustCode(t, "invalid key", code, ec, 400, "")
	}
	var short apitypes.ApiKeyCreated
	code, ec := e.member.call("POST", "/v1/me/api-keys", map[string]any{"name": "ci", "expiresInDays": 1}, &short, nil)
	mustCode(t, "1-day key", code, ec, 201, "")
	if d := time.Until(*short.Key.ExpiresAt); d > 25*time.Hour || d < 23*time.Hour {
		t.Fatalf("expiry = %v", d)
	}
	for i := 2; i < 20; i++ {
		newKey(t, e.member, "bulk")
	}
	code, ec = e.member.call("POST", "/v1/me/api-keys", map[string]any{"name": "one too many"}, nil, nil)
	mustCode(t, "21st key", code, ec, 409, "too_many_keys")
	code, ec = e.owner.call("DELETE", "/v1/me/api-keys/"+k.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke someone else's key", code, ec, 404, "api_key_not_found")
	code, ec = e.member.call("DELETE", "/v1/me/api-keys/"+k.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke", code, ec, 200, "")
	code, ec = e.member.call("DELETE", "/v1/me/api-keys/"+k.Key.Id.String(), nil, nil, nil)
	mustCode(t, "revoke again", code, ec, 200, "")
	newKey(t, e.member, "replacement")
	var list []apitypes.ApiKey
	e.member.get("/v1/me/api-keys", &list)
	statuses := map[string]int{}
	for _, it := range list {
		statuses[string(it.Status)]++
	}
	if len(list) != 21 || statuses["revoked"] != 1 || statuses["active"] != 20 || list[0].Name != "replacement" {
		t.Fatalf("list = %v (%d)", statuses, len(list))
	}
	if e.owner.get("/v1/me/api-keys", &list); len(list) != 0 {
		t.Fatalf("owner sees %d keys", len(list))
	}
	// Keys are not accepted by the management API.
	if code, _ := e.app.do("GET", "/v1/me", nil, map[string]string{"Authorization": "Bearer " + short.Secret}); code != 401 {
		t.Fatalf("key on /v1/me = %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'api_key.create' AND target_type = 'api_key'`); n != "21" {
		t.Fatalf("create audits = %s", n)
	}
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'api_key.revoke'`); n != "1" {
		t.Fatalf("revoke audits = %s", n)
	}
	var page apitypes.AuditPage
	e.admin.get("/v1/admin/audit?action=api_key.revoke", &page)
	if len(page.Items) != 1 || page.Items[0].TargetLabel == nil || *page.Items[0].TargetLabel != "Claude Code on my laptop" {
		t.Fatalf("revoke entry = %+v", page.Items)
	}
}
