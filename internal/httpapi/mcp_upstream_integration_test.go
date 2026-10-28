package httpapi_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The portal as an MCP client of your servers (docs/mcp-protocol.md, "The
// portal as a client"): era negotiation, relaying a server's elicitation,
// streaming, trace context.

// relayEnv is the gateway "support" for blair over the server "status", whose
// fake has every tool of the new revision's behaviours.
type relayEnv struct {
	*gwEnv
	gw   apitypes.Gateway
	path string
	key  string
}

func newRelayEnv(t *testing.T, hook func(*httpapi.Deps)) *relayEnv {
	t.Helper()
	e := &relayEnv{gwEnv: newGwEnvHook(t, nil, hook)}
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	e.fake.EnableMRTRTools()
	e.fake.EnableStreamTools()
	e.refresh(e.owner, e.server)
	e.gw = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.path = toolsTeam + "/gateways/" + e.gw.Id.String()
	var ids []string
	for _, c := range [][2]string{{"tool", "ask_form"}, {"tool", "ask_url"}, {"tool", "ask_sampling"}, {"tool", "echo"}, {"tool", "whoami"},
		{"tool", "progress"}, {"tool", "block"}, {"prompt", "ask_prompt"}, {"prompt", "incident_summary"}, {"resource", "status://ask"}} {
		ids = append(ids, e.capID(e.owner, e.server, c[0], c[1]))
	}
	e.mustSetCaps(e.owner, e.path, sel(ids...))
	e.key = newKey(t, e.member, "laptop").Secret
	return e
}

// call posts a modern request with extra _meta entries and returns the
// decoded JSON answer.
func (e *relayEnv) call(method string, params, caps, meta map[string]any) (int, map[string]any) {
	e.t.Helper()
	code, _, out := rawMCP(e.t, e.app, "POST", "support", e.key, rpc(1, method, modernMeta(params, caps, meta)), modernHeaders(method, params, nil))
	return code, out
}

// modernMeta is modernParams with more _meta entries.
func modernMeta(params, caps, meta map[string]any) map[string]any {
	p := modernParams(params, caps)
	m := p["_meta"].(map[string]any)
	for k, v := range meta {
		m[k] = v
	}
	return p
}

func argsCall(name string, args map[string]any, extra map[string]any) map[string]any {
	p := map[string]any{"name": name, "arguments": args}
	for k, v := range extra {
		p[k] = v
	}
	return p
}

// textOf is the first text content of a tool result.
func textOf(t *testing.T, out map[string]any) string {
	t.Helper()
	r := resultOf(t, out)
	content, _ := r["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no content in %v", r)
	}
	s, _ := content[0].(map[string]any)["text"].(string)
	return s
}

// lastRecord waits for the latest call record to read want ("outcome class").
// An optional exposed name avoids matching a preceding call's same outcome.
func (e *relayEnv) lastRecord(want string, names ...string) {
	e.t.Helper()
	name := ""
	if len(names) > 0 {
		name = names[0]
	}
	last := ""
	for range 150 {
		last = e.scalar(`SELECT coalesce((SELECT outcome || ' ' || coalesce(error_class, '') FROM mcp_calls WHERE ($1='' OR exposed_name=$1) ORDER BY id DESC LIMIT 1), '')`, name)
		if last == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("recorded %q, want %q", last, want)
}

func (e *relayEnv) protocolOf(sv apitypes.McpServer) *apitypes.McpServerProtocol {
	e.t.Helper()
	var cur apitypes.McpServer
	if code := e.owner.get("/v1/teams/"+sv.TeamSlug+"/mcp-servers/"+sv.Id.String(), &cur); code != 200 {
		e.t.Fatalf("get server = %d", code)
	}
	return cur.Protocol
}

// ---------------------------------------------------------------------------
// Era negotiation

func TestUpstreamEraMatrix(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, tc := range []struct {
		protocol testutil.Protocol
		era      apitypes.McpServerProtocolEra
		version  string
	}{
		{testutil.ProtocolModern, apitypes.Modern, "2026-07-28"},
		{testutil.ProtocolLegacy, apitypes.Legacy, "2025-11-25"},
		{testutil.ProtocolBoth, apitypes.Modern, "2026-07-28"},
	} {
		t.Run(string(tc.protocol), func(t *testing.T) {
			f := testutil.NewFakeMCP(t)
			f.SetProtocol(tc.protocol)
			f.EnableGatewayTools()
			slug := "up-" + string(tc.protocol)
			base := "/v1/teams/tools/mcp-servers/"

			// Nothing is known before the first exchange.
			var sv apitypes.McpServerCreated
			code, ec := e.owner.call("POST", "/v1/teams/tools/mcp-servers", map[string]any{"slug": slug, "name": slug, "url": f.URL()}, &sv, nil)
			mustCode(t, "create", code, ec, 201, "")
			if sv.RefreshError != nil {
				t.Fatalf("discovery failed: %+v", sv.RefreshError)
			}
			check := func(when string) {
				t.Helper()
				p := e.protocolOf(sv.Server)
				if p == nil || p.Era != tc.era || p.Version != tc.version || time.Since(p.NegotiatedAt) > time.Minute {
					t.Fatalf("%s: protocol = %+v, want %s %s", when, p, tc.era, tc.version)
				}
			}
			check("after creating it")

			// Test and refresh say it too. Move the clock of the record back
			// to see each one set it.
			for _, step := range []string{"test", "refresh"} {
				if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_servers SET protocol_era = NULL, protocol_version = NULL,
					protocol_negotiated_at = NULL WHERE id = $1`, sv.Server.Id); err != nil {
					t.Fatal(err)
				}
				if p := e.protocolOf(sv.Server); p != nil {
					t.Fatalf("protocol = %+v after clearing", p)
				}
				var res apitypes.McpTestResult
				code, ec := e.owner.call("POST", base+sv.Server.Id.String()+"/"+step, nil, &res, nil)
				mustCode(t, step, code, ec, 200, "")
				check("after " + step)
				if step == "test" && (!res.Ok || res.ProtocolVersion == nil || *res.ProtocolVersion != tc.version) {
					t.Fatalf("test result = %+v", res)
				}
			}

			// Forwarded calls: a tool, a prompt and a resource, in the era the
			// server speaks.
			g := e.createGateway(e.owner, toolsTeam+"/gateways", slug)
			e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, sv.Server, "tool", "echo"),
				e.capID(e.owner, sv.Server, "prompt", "incident_summary"), e.capID(e.owner, sv.Server, "resource", "status://services")))
			seen := len(f.SeenRequests())
			cs := connectModern(t, e.app, slug, e.key)
			if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: slug + "__echo", Arguments: map[string]any{"text": "hi"}}); err != nil ||
				resultText(t, res) != "hi" {
				t.Fatalf("echo = %v, %v", res, err)
			}
			if _, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: slug + "__incident_summary", Arguments: map[string]string{"service": "vpn"}}); err != nil {
				t.Fatalf("prompt: %v", err)
			}
			if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "omp://" + slug + "/status://services"}); err != nil {
				t.Fatalf("read: %v", err)
			}
			var methods []string
			initialized := false
			for _, r := range f.SeenRequests()[seen:] {
				if r.Method == "initialize" {
					initialized = true
				}
				if r.Method == "tools/call" || r.Method == "prompts/get" || r.Method == "resources/read" {
					methods = append(methods, r.Method)
					if modern := r.Version == "2026-07-28" && r.McpMethod == r.Method; modern != (tc.era == apitypes.Modern) {
						t.Errorf("%s reached the server as %+v", r.Method, r)
					}
				}
				if r.Refused && tc.era == apitypes.Modern {
					t.Errorf("a request was refused: %+v", r)
				}
			}
			if !slices.Equal(methods, []string{"tools/call", "prompts/get", "resources/read"}) {
				t.Errorf("the server saw %v", methods)
			}
			if initialized != (tc.era == apitypes.Legacy) {
				t.Errorf("initialize seen = %v for a %s server", initialized, tc.era)
			}
			// The era is remembered: later calls don't probe again.
			for _, r := range f.SeenRequests()[seen:] {
				if r.Method == "server/discover" {
					t.Errorf("a forwarded call probed again: %+v", r)
				}
			}
		})
	}
}

// A server that changes era is picked up by the next refresh, and a
// modern server that is mistaken for legacy (or the reverse) never fails a
// call for it.
func TestUpstreamEraChange(t *testing.T) {
	e := newRelayEnv(t, nil)
	p := e.protocolOf(e.server)
	if p == nil || p.Era != apitypes.Modern {
		t.Fatalf("protocol = %+v", p)
	}
	e.fake.SetProtocol(testutil.ProtocolLegacy)
	// A call with the era remembered as modern still works.
	code, out := e.call("tools/call", argsCall("status__echo", map[string]any{"text": "still"}, nil), nil, nil)
	if code != 200 || textOf(t, out) != "still" {
		t.Fatalf("call after the server became legacy = %d %v", code, out)
	}
	e.refresh(e.owner, e.server)
	if p := e.protocolOf(e.server); p == nil || p.Era != apitypes.Legacy || p.Version != "2025-11-25" {
		t.Fatalf("protocol after a refresh = %+v", p)
	}
	e.fake.SetProtocol(testutil.ProtocolModern)
	code, out = e.call("tools/call", argsCall("status__echo", map[string]any{"text": "back"}, nil), nil, nil)
	if code != 200 || textOf(t, out) != "back" {
		t.Fatalf("call after the server became modern = %d %v", code, out)
	}
	e.refresh(e.owner, e.server)
	if p := e.protocolOf(e.server); p == nil || p.Era != apitypes.Modern {
		t.Fatalf("protocol = %+v", p)
	}
}

// The specification's rule: a 400 whose body is a recognized modern error
// does not send the portal to initialize.
func TestUpstreamModernErrorDoesNotFallBack(t *testing.T) {
	e := newRelayEnv(t, nil)
	var initializes, requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		body, _ := io.ReadAll(r.Body)
		if bytes.Contains(body, []byte(`"initialize"`)) {
			initializes.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"HeaderMismatch: this server is picky"}}`))
	}))
	defer srv.Close()
	var created apitypes.McpServerCreated
	code, ec := e.owner.call("POST", "/v1/teams/tools/mcp-servers", map[string]any{"slug": "picky", "name": "Picky", "url": srv.URL}, &created, nil)
	mustCode(t, "create", code, ec, 201, "")
	if created.RefreshError == nil || created.RefreshError.ErrorClass == nil {
		t.Fatalf("discovery of a picky modern server succeeded: %+v", created.RefreshError)
	}
	if initializes.Load() != 0 || requests.Load() != 1 {
		t.Fatalf("%d requests, %d initialize: a modern error must not fall back", requests.Load(), initializes.Load())
	}
	if p := e.protocolOf(created.Server); p != nil {
		t.Fatalf("protocol = %+v for a server that was never read", p)
	}
}

// ---------------------------------------------------------------------------
// Elicitation relay

// formCaps and urlCaps declare form mode (an empty elicitation object) and
// URL mode.
var (
	emptyCaps = map[string]any{"elicitation": map[string]any{}}
	bothCaps  = map[string]any{"elicitation": map[string]any{"form": map[string]any{}, "url": map[string]any{}}}
)

func (e *relayEnv) elicitor(handler func(*mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	e.t.Helper()
	return connectEra(e.t, e.app, "support", e.key, "", &mcp.ClientOptions{
		ElicitationHandler: func(_ context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) { return handler(r) },
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{Form: &mcp.FormElicitationCapabilities{},
			URL: &mcp.URLElicitationCapabilities{}}},
	})
}

func TestRelayElicitationWithSDKClient(t *testing.T) {
	e := newRelayEnv(t, nil)
	ctx := context.Background()
	var mu sync.Mutex
	var asked []*mcp.ElicitParams
	cs := e.elicitor(func(r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		mu.Lock()
		asked = append(asked, r.Params)
		mu.Unlock()
		if r.Params.Mode == "url" {
			return &mcp.ElicitResult{Action: "accept"}, nil
		}
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"region": "eu-1"}}, nil
	})

	// A form: the client answers, the SDK retries, the server completes with
	// its own state and the answer.
	res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__ask_form"})
	if err != nil || res.IsError || resultText(t, res) != "ask_form: region=eu-1 upstream-state=form-state-1" {
		t.Fatalf("ask_form = %+v, %v", res, err)
	}
	e.lastRecord("ok ")
	// The URL: relayed as given, accepted, and the server finishes.
	res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__ask_url"})
	if err != nil || res.IsError || resultText(t, res) != "ask_url: accept upstream-state=url-state-1" {
		t.Fatalf("ask_url = %+v, %v", res, err)
	}
	mu.Lock()
	if len(asked) != 2 || asked[0].Mode != "form" || asked[0].Message != "Which region?" || asked[1].Mode != "url" ||
		asked[1].URL != "https://auth.example.com/approve?id=abc" || asked[1].Message != "Approve this in your browser." {
		t.Fatalf("what the client was asked = %+v %+v", asked[0], asked[1])
	}
	mu.Unlock()

	// What the server received: the portal's declared capabilities as wide as
	// the client's, the original arguments both times, the responses and its
	// own state on the retry only.
	var forms []testutil.ToolCall
	for _, c := range e.fake.ToolCalls() {
		if c.Tool == "ask_form" {
			forms = append(forms, c)
		}
	}
	if len(forms) != 2 || forms[0].RequestState != "" || forms[1].RequestState != "form-state-1" || forms[0].InputResponses != nil {
		t.Fatalf("ask_form calls = %+v", forms)
	}
	if got, _ := json.Marshal(forms[1].InputResponses); string(got) != `{"region":{"action":"accept","content":{"region":"eu-1"}}}` {
		t.Fatalf("input responses = %s", got)
	}
	for _, c := range forms {
		if got, _ := json.Marshal(c.Meta["io.modelcontextprotocol/clientCapabilities"]); string(got) != `{"elicitation":{"form":{},"url":{}}}` {
			t.Errorf("the server was told %s", got)
		}
		if c.Header.Get("Mcp-Name") != "ask_form" || c.Header.Get("MCP-Protocol-Version") != "2026-07-28" {
			t.Errorf("headers = %v", c.Header)
		}
	}

	// Prompts and reads relay too.
	pr, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "status__ask_prompt"})
	if err != nil || len(pr.Messages) != 1 || pr.Messages[0].Content.(*mcp.TextContent).Text != "for <nil> upstream-state=prompt-state-1" {
		// The form answer carries region only; "who" is absent.
		t.Fatalf("ask_prompt = %+v, %v", pr, err)
	}
	rd, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "omp://status/status://ask"})
	if err != nil || len(rd.Contents) != 1 || rd.Contents[0].Text != "accept upstream-state=read-state-1" || rd.Contents[0].URI != "omp://status/status://ask" {
		t.Fatalf("read = %+v, %v", rd, err)
	}
}

func (e *relayEnv) askForm(caps map[string]any, extraMeta map[string]any) (map[string]any, string) {
	e.t.Helper()
	code, out := e.call("tools/call", argsCall("status__ask_form", map[string]any{}, nil), caps, extraMeta)
	if code != 200 {
		e.t.Fatalf("ask_form = %d %v", code, out)
	}
	r, _ := out["result"].(map[string]any)
	state, _ := r["requestState"].(string)
	return out, state
}

func lastForm(e *relayEnv) testutil.ToolCall {
	calls := e.fake.ToolCalls()
	for i := len(calls) - 1; i >= 0; i-- {
		if calls[i].Tool == "ask_form" || calls[i].Tool == "ask_url" || calls[i].Tool == "ask_sampling" {
			return calls[i]
		}
	}
	return testutil.ToolCall{}
}

// The portal declares to the server exactly the elicitation the client
// declared, per request, and none when the client declared none.
func TestRelayDeclaredCapabilityNarrowing(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, tc := range []struct {
		name string
		caps map[string]any
		want string // what the server was told (clientCapabilities), "" never relays
	}{
		{"form only, empty object", emptyCaps, `{"elicitation":{}}`},
		{"form only, explicit", map[string]any{"elicitation": map[string]any{"form": map[string]any{}}}, `{"elicitation":{"form":{}}}`},
		{"url only", map[string]any{"elicitation": map[string]any{"url": map[string]any{}}}, `{"elicitation":{"url":{}}}`},
		{"both", bothCaps, `{"elicitation":{"form":{},"url":{}}}`},
		{"extras are not passed on", map[string]any{"elicitation": map[string]any{"form": map[string]any{"x": 1}}, "sampling": map[string]any{}, "roots": map[string]any{}},
			`{"elicitation":{"form":{}}}`},
		{"none", map[string]any{}, `{}`},
		{"elicitation is not an object", map[string]any{"elicitation": true}, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := e.askForm(tc.caps, nil)
			// The server is told what the client declared, whether or not the
			// answer can be relayed.
			got, _ := json.Marshal(lastForm(e).Meta["io.modelcontextprotocol/clientCapabilities"])
			if string(got) != tc.want {
				t.Fatalf("the server was told %s, want %s (answer %v)", got, tc.want, out)
			}
		})
	}
	// A form request to a client that declared none is refused, not relayed.
	out, _ := e.askForm(map[string]any{}, nil)
	r := resultOf(t, out)
	if r["isError"] != true || !strings.Contains(textOf(t, out), "can't give") || r["inputRequests"] != nil || r["requestState"] != nil {
		t.Fatalf("no declared elicitation: %v", r)
	}
	// ask_url to a client that declared form only: the server asked for a
	// mode it wasn't offered.
	code, out := e.call("tools/call", argsCall("status__ask_url", map[string]any{}, nil), emptyCaps, nil)
	if code != 200 || rpcErrorCode(out) != -32603 || !strings.Contains(fmt.Sprint(out["error"]), "URL") {
		t.Fatalf("url to a form-only client = %d %v", code, out)
	}
	e.lastRecord("upstream_error input_required")
}

func TestRelayShape(t *testing.T) {
	e := newRelayEnv(t, nil)
	out, state := e.askForm(bothCaps, nil)
	r := resultOf(t, out)
	if r["resultType"] != "input_required" || state == "" || !slices.Equal(keysOf(r), []string{"_meta", "inputRequests", "requestState", "resultType"}) {
		t.Fatalf("result = %v", r)
	}
	if serverInfoOf(t, r)["name"] != "support" {
		t.Fatalf("serverInfo = %v", r["_meta"])
	}
	reqs := r["inputRequests"].(map[string]any)
	if got, _ := json.Marshal(reqs); string(got) != `{"region":{"method":"elicitation/create","params":{"message":"Which region?","mode":"form",`+
		`"requestedSchema":{"properties":{"region":{"title":"Region","type":"string"}},"required":["region"],"type":"object"}}}}` {
		t.Fatalf("inputRequests = %s", got)
	}
	// The server's own state is not what the client got.
	if strings.Contains(state, "form-state-1") {
		t.Fatalf("requestState = %q", state)
	}
	e.lastRecord("ok input_required")
}

func TestRelayRefusals(t *testing.T) {
	e := newRelayEnv(t, nil)
	toolError := func(name string, args map[string]any, caps map[string]any, want string) {
		t.Helper()
		code, out := e.call("tools/call", argsCall(name, args, nil), caps, nil)
		r, _ := out["result"].(map[string]any)
		if code != 200 || r == nil || r["isError"] != true || !strings.Contains(textOf(t, out), want) || r["inputRequests"] != nil || r["requestState"] != nil {
			t.Fatalf("%s = %d %v, want a tool error saying %q", name, code, out, want)
		}
	}
	// Sampling (and roots) are not relayed, alone or next to a form.
	toolError("status__ask_sampling", map[string]any{}, bothCaps, "this server asked for something the portal can't provide (sampling/roots)")
	e.lastRecord("tool_error input_required")
	toolError("status__ask_sampling", map[string]any{"mixed": true}, bothCaps, "sampling/roots")

	// URLs: https only (plain http only for loopback in development, which
	// these tests run in); no user info, no other schemes.
	for _, tc := range []struct {
		url string
		ok  bool
	}{
		{"https://auth.example.com/approve", true},
		{"http://127.0.0.1:9/approve", true},
		{"http://localhost:9/approve", true},
		{"http://evil.example.com/approve", false},
		{"javascript:alert(1)", false},
		{"file:///etc/passwd", false},
		{"https://user:pw@example.com/", false},
		{"https:///nohost", false},
		{"//example.com/x", false},
		{"https://example.com/a b", false},
		{"https://example.com/" + strings.Repeat("a", 3000), false},
	} {
		code, out := e.call("tools/call", argsCall("status__ask_url", map[string]any{"url": tc.url}, nil), bothCaps, nil)
		r, _ := out["result"].(map[string]any)
		relayed := code == 200 && r != nil && r["resultType"] == "input_required"
		if relayed != tc.ok {
			t.Errorf("url %.60q: relayed = %v (%v)", tc.url, relayed, out)
		}
		if !tc.ok && (code != 200 || rpcErrorCode(out) != -32603) {
			t.Errorf("url %.60q: want a refusal, got %d %v", tc.url, code, out)
		}
	}

	// A legacy client can't be relayed to: the server was told so, and the
	// call fails clearly.
	legacy := connect(t, e.app, "support", e.key)
	res, err := legacy.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__ask_form"})
	if err != nil || !res.IsError || !strings.Contains(resultText(t, res), "can't give") {
		t.Fatalf("legacy client: %+v, %v", res, err)
	}
	if got, _ := json.Marshal(lastForm(e).Meta["io.modelcontextprotocol/clientCapabilities"]); string(got) != `{}` {
		t.Fatalf("the server was told %s about a legacy client", got)
	}
	e.lastRecord("tool_error input_required")
}

// Bounds and shape of what is relayed, checked on the validation itself.
// (internal/mcpgw/relay_test.go)

// What a requestState binds, and what a client can't do with it.
func TestRelayStateBinding(t *testing.T) {
	var mu sync.Mutex
	var offset time.Duration
	e := newRelayEnv(t, func(d *httpapi.Deps) {
		d.MCP.(interface{ SetClock(func() time.Time) }).SetClock(func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return time.Now().Add(offset)
		})
	})
	_, state := e.askForm(bothCaps, nil)
	retry := func(key, tool string, args map[string]any, st string, responses map[string]any) (int, map[string]any) {
		extra := map[string]any{"requestState": st}
		if responses != nil {
			extra["inputResponses"] = responses
		}
		p := argsCall(tool, args, extra)
		c, _, o := rawMCP(t, e.app, "POST", "support", key, rpc(2, "tools/call", modernParams(p, bothCaps)), modernHeaders("tools/call", p, nil))
		return c, o
	}
	answer := map[string]any{"region": map[string]any{"action": "accept", "content": map[string]any{"region": "us-2"}}}
	rejected := func(what, class, part string, code int, out map[string]any) {
		t.Helper()
		if code != 200 || rpcErrorCode(out) != -32602 {
			t.Fatalf("%s = %d %v", what, code, out)
		}
		if msg := fmt.Sprint(out["error"]); !strings.Contains(msg, part) {
			t.Fatalf("%s: %s, want it to say %q", what, msg, part)
		}
		e.lastRecord("bad_request " + class)
	}
	before := len(e.fake.ToolCalls())

	// Altered, cut short, made up.
	b := []byte(state)
	if b[len(b)/2] == 'A' {
		b[len(b)/2] = 'B'
	} else {
		b[len(b)/2] = 'A'
	}
	c, o := retry(e.key, "status__ask_form", map[string]any{}, string(b), answer)
	rejected("altered", "request_state_invalid", "not valid", c, o)
	c, o = retry(e.key, "status__ask_form", map[string]any{}, state[:len(state)-6], answer)
	rejected("cut short", "request_state_invalid", "not valid", c, o)
	c, o = retry(e.key, "status__ask_form", map[string]any{}, "form-state-1", answer)
	rejected("the server's own state", "request_state_invalid", "not valid", c, o)

	// Another person's key (the team owner may use the gateway too): "not
	// valid", nothing said about whose it was.
	ownerKey := newKey(t, e.owner, "owner").Secret
	c, o = retry(ownerKey, "status__ask_form", map[string]any{}, state, answer)
	rejected("another person", "request_state_invalid", "not valid", c, o)

	// Another call: another tool, other arguments.
	c, o = retry(e.key, "status__ask_url", map[string]any{}, state, answer)
	rejected("another tool", "request_state_mismatch", "different request", c, o)
	c, o = retry(e.key, "status__ask_form", map[string]any{"x": 1}, state, answer)
	rejected("other arguments", "request_state_mismatch", "different request", c, o)
	// A state of one method on another.
	p := map[string]any{"name": "status__ask_prompt", "requestState": state}
	c2, _, o2 := rawMCP(t, e.app, "POST", "support", e.key, rpc(3, "prompts/get", modernParams(p, bothCaps)), modernHeaders("prompts/get", p, nil))
	rejected("another method", "request_state_mismatch", "different request", c2, o2)
	if n := len(e.fake.ToolCalls()); n != before {
		t.Fatalf("a refused retry reached the server (%d calls, had %d)", n, before)
	}

	// Answers that aren't elicitation results are refused; answers to keys
	// that weren't asked are ignored.
	c, o = retry(e.key, "status__ask_form", map[string]any{}, state, map[string]any{"region": map[string]any{"action": "maybe"}})
	if c != 200 || rpcErrorCode(o) != -32602 {
		t.Fatalf("a bad answer = %d %v", c, o)
	}
	e.lastRecord("bad_request invalid_params")
	c, o = retry(e.key, "status__ask_form", map[string]any{}, state, map[string]any{
		"region": map[string]any{"action": "accept", "content": map[string]any{"region": "us-2"}},
		"other":  map[string]any{"action": "accept"}, "connect_github": map[string]any{"action": "accept"}})
	if c != 200 || textOf(t, o) != "ask_form: region=us-2 upstream-state=form-state-1" {
		t.Fatalf("the retry = %d %v", c, o)
	}
	last := lastForm(e)
	if got, _ := json.Marshal(last.InputResponses); string(got) != `{"region":{"action":"accept","content":{"region":"us-2"}}}` {
		t.Fatalf("the server received answers %s", got)
	}
	// A state can be replayed within its life (it only re-runs the call).
	c, o = retry(e.key, "status__ask_form", map[string]any{}, state, answer)
	if c != 200 || textOf(t, o) != "ask_form: region=us-2 upstream-state=form-state-1" {
		t.Fatalf("a replay = %d %v", c, o)
	}
	e.lastRecord("ok ")

	// Expired.
	mu.Lock()
	offset = 11 * time.Minute
	mu.Unlock()
	c, o = retry(e.key, "status__ask_form", map[string]any{}, state, answer)
	rejected("expired", "request_state_expired", "expired", c, o)
}

// The sealed state holds the person, gateway, call and the server's own
// state, never a credential: neither the identity token the server saw, nor
// the person's key.
func TestRelayStateHoldsNoCredentials(t *testing.T) {
	e := newRelayEnv(t, nil)
	out, state := e.askForm(bothCaps, nil)
	body, _ := json.Marshal(out)
	_, identity := testutil.IdentityToken(lastForm(e).Header)
	if identity == "" {
		t.Fatal("the server saw no identity token")
	}
	plain := openState(t, state)
	for what, secret := range map[string]string{"identity token": identity, "API key": e.key, "bearer header": "Bearer " + e.key} {
		if strings.Contains(plain, secret) || strings.Contains(string(body), secret) || strings.Contains(state, secret) {
			t.Errorf("the %s is in the state or the response", what)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal([]byte(plain), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["us"] != "form-state-1" || claims["u"] != "relay" || claims["m"] != "tools/call" || claims["n"] != "status__ask_form" {
		t.Fatalf("claims = %v", claims)
	}
	for k := range claims {
		switch k {
		case "u", "p", "g", "m", "n", "d", "iat", "exp", "s", "k", "us":
		default:
			t.Errorf("unexpected claim %q", k)
		}
	}
	if iat, exp := claims["iat"].(float64), claims["exp"].(float64); exp-iat != 600 {
		t.Errorf("lifetime = %v s, want 600", exp-iat)
	}
}

// openState decrypts a requestState with the test deployment's key, as the
// handler does (HKDF info string of internal/mcpgw/requeststate.go).
func openState(t *testing.T, token string) string {
	t.Helper()
	key, _ := secrets.ParseKey(testEncryptionKey)
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := box.Derive("open-mcp-portal/mcp-request-state/v1")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(keys[0])
	aead, _ := cipher.NewGCM(block)
	n := aead.NonceSize()
	plain, err := aead.Open(nil, raw[1:1+n], raw[1+n:], []byte("open-mcp-portal/mcp-request-state/v1"))
	if err != nil {
		t.Fatal(err)
	}
	return string(plain)
}

// ---------------------------------------------------------------------------
// Streaming

type sseEvent struct {
	comment bool
	event   string
	data    string
	at      time.Time
}

// readSSE reads events until the stream ends.
func readSSE(r io.Reader) []sseEvent {
	var out []sseEvent
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 8<<20)
	cur := sseEvent{}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if cur.data != "" || cur.event != "" {
				cur.at = time.Now()
				out = append(out, cur)
			}
			cur = sseEvent{}
		case strings.HasPrefix(line, ":"):
			out = append(out, sseEvent{comment: true, data: line, at: time.Now()})
		case strings.HasPrefix(line, "event: "):
			cur.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			cur.data += strings.TrimPrefix(line, "data: ")
		}
	}
	return out
}

func (e *relayEnv) post(ctx context.Context, body any, headers map[string]string) *http.Response {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", e.app.URL+"/mcp/support", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+e.key)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

// toolRequest is a tools/call as a modern or legacy client sends it, with a
// progress token.
func toolRequest(modern bool, name string, args map[string]any, meta map[string]any) (body map[string]any, headers map[string]string) {
	p := argsCall(name, args, nil)
	if modern {
		p = modernMeta(p, nil, meta)
		return rpc(1, "tools/call", p), modernHeaders("tools/call", p, nil)
	}
	p["_meta"] = meta
	return rpc(1, "tools/call", p), nil
}

func TestStreamProgress(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, upstreamEra := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		f := testutil.NewFakeMCP(t)
		f.SetProtocol(upstreamEra)
		f.EnableStreamTools()
		sv := e.createServer(e.owner, "tools", "s-"+string(upstreamEra), f.URL(), nil)
		g := e.createGateway(e.owner, toolsTeam+"/gateways", "s-"+string(upstreamEra))
		e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, sv, "tool", "progress")))
		for _, downstreamModern := range []bool{true, false} {
			t.Run(fmt.Sprintf("upstream %s, downstream modern=%v", upstreamEra, downstreamModern), func(t *testing.T) {
				for _, token := range []any{"tok-1", 42} {
					body, headers := toolRequest(downstreamModern, "s-"+string(upstreamEra)+"__progress", map[string]any{"count": 3, "delay_ms": 20},
						map[string]any{"progressToken": token})
					b, _ := json.Marshal(body)
					req, _ := http.NewRequest("POST", e.app.URL+"/mcp/s-"+string(upstreamEra), bytes.NewReader(b))
					req.Header.Set("Content-Type", "application/json")
					req.Header.Set("Accept", "application/json, text/event-stream")
					req.Header.Set("Authorization", "Bearer "+e.key)
					for k, v := range headers {
						req.Header.Set(k, v)
					}
					res, err := http.DefaultClient.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					if res.StatusCode != 200 || res.Header.Get("Content-Type") != "text/event-stream" || res.Header.Get("X-Accel-Buffering") != "no" {
						t.Fatalf("response = %d %v", res.StatusCode, res.Header)
					}
					events := readSSE(res.Body)
					res.Body.Close()
					if len(events) != 4 {
						t.Fatalf("%d events: %+v", len(events), events)
					}
					for i, ev := range events[:3] {
						var n struct {
							Method string
							Params struct {
								ProgressToken   any
								Progress, Total float64
								Message         string
							}
						}
						if err := json.Unmarshal([]byte(ev.data), &n); err != nil || ev.event != "message" || n.Method != "notifications/progress" ||
							fmt.Sprint(n.Params.ProgressToken) != fmt.Sprint(token) || n.Params.Progress != float64(i+1) || n.Params.Total != 3 ||
							n.Params.Message != fmt.Sprintf("step %d", i+1) {
							t.Fatalf("event %d = %+v (%v)", i, ev, err)
						}
					}
					var final map[string]any
					if err := json.Unmarshal([]byte(events[3].data), &final); err != nil || final["id"] != float64(1) || textOf(t, final) != "progress: 3 steps" {
						t.Fatalf("final = %s (%v)", events[3].data, err)
					}
					// Events arrive while the call runs, not all at the end.
					if events[2].at.Sub(events[0].at) < 20*time.Millisecond {
						t.Errorf("progress events %v apart: they were buffered", events[2].at.Sub(events[0].at))
					}
				}
			})
		}
	}
	// One record per call: the sizes include the stream.
	var n, minBytes int
	if _, err := fmt.Sscan(e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE exposed_name LIKE '%progress'`), &n); err != nil || n != 8 {
		t.Errorf("%d records for 8 streamed calls (%v)", n, err)
	}
	// Three progress events and the response: well over the response alone.
	if _, err := fmt.Sscan(e.scalar(`SELECT coalesce(min(response_bytes), 0)::text FROM mcp_calls WHERE exposed_name LIKE '%progress'`), &minBytes); err != nil || minBytes < 500 {
		t.Errorf("response_bytes = %d: the stream should count (%v)", minBytes, err)
	}
}

func TestStreamOnlyWhenAskedFor(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, tc := range []struct {
		name    string
		modern  bool
		accept  string
		meta    map[string]any
		wantSSE bool
	}{
		{"modern with token and SSE", true, "application/json, text/event-stream", map[string]any{"progressToken": "p"}, true},
		{"legacy with token and SSE", false, "application/json, text/event-stream", map[string]any{"progressToken": "p"}, true},
		{"no token", true, "application/json, text/event-stream", nil, false},
		{"JSON only", true, "application/json", map[string]any{"progressToken": "p"}, false},
		{"token of a bad type", true, "application/json, text/event-stream", map[string]any{"progressToken": true}, false},
		{"empty token", true, "application/json, text/event-stream", map[string]any{"progressToken": ""}, false},
		{"float token", true, "application/json, text/event-stream", map[string]any{"progressToken": 1.5}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body, headers := toolRequest(tc.modern, "status__echo", map[string]any{"text": "plain"}, tc.meta)
			headers2 := map[string]string{"Accept": tc.accept}
			for k, v := range headers {
				headers2[k] = v
			}
			res := e.post(context.Background(), body, headers2)
			defer res.Body.Close()
			raw, _ := io.ReadAll(res.Body)
			sse := strings.HasPrefix(res.Header.Get("Content-Type"), "text/event-stream")
			if sse != tc.wantSSE {
				t.Fatalf("content type %q for %s", res.Header.Get("Content-Type"), tc.name)
			}
			if res.StatusCode != 200 {
				t.Fatalf("status %d: %s", res.StatusCode, raw)
			}
			if !sse {
				var out map[string]any
				if err := json.Unmarshal(raw, &out); err != nil || textOf(t, out) != "plain" {
					t.Fatalf("answer = %s", raw)
				}
				return
			}
			events := readSSE(bytes.NewReader(raw))
			if len(events) != 1 {
				t.Fatalf("events = %+v", events)
			}
		})
	}
	// Refusals before the call reaches the server are the JSON answers they
	// always were, even with a token.
	body, headers := toolRequest(true, "status__nope", nil, map[string]any{"progressToken": "p"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	if res.Header.Get("Content-Type") != "application/json" || !strings.Contains(string(raw), "Unknown tool") {
		t.Fatalf("an unknown tool = %s %s", res.Header.Get("Content-Type"), raw)
	}
}

func TestStreamKeepAlive(t *testing.T) {
	e := newRelayEnv(t, func(d *httpapi.Deps) {
		d.MCP.(interface{ SetStreamKeepAlive(time.Duration) }).SetStreamKeepAlive(40 * time.Millisecond)
	})
	body, headers := toolRequest(true, "status__progress", map[string]any{"count": 1, "delay_ms": 400}, map[string]any{"progressToken": "k"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	events := readSSE(res.Body)
	comments := 0
	for _, ev := range events {
		if ev.comment {
			comments++
		}
	}
	if comments < 3 || events[len(events)-1].comment || len(events) != comments+2 {
		t.Fatalf("%d comments in %+v", comments, events)
	}
}

// Closing the downstream connection cancels the call to the server.
func TestStreamCancelsUpstream(t *testing.T) {
	e := newRelayEnv(t, nil)
	for _, p := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		t.Run(string(p), func(t *testing.T) {
			f := testutil.NewFakeMCP(t)
			f.SetProtocol(p)
			f.EnableStreamTools()
			slug := "c-" + string(p)
			sv := e.createServer(e.owner, "tools", slug, f.URL(), nil)
			g := e.createGateway(e.owner, toolsTeam+"/gateways", slug)
			e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, sv, "tool", "block")))

			ctx, cancel := context.WithCancel(context.Background())
			body, headers := toolRequest(true, slug+"__block", nil, map[string]any{"progressToken": "b"})
			b, _ := json.Marshal(body)
			req, _ := http.NewRequestWithContext(ctx, "POST", e.app.URL+"/mcp/"+slug, bytes.NewReader(b))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("Authorization", "Bearer "+e.key)
			for k, v := range headers {
				req.Header.Set(k, v)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if res.Header.Get("Content-Type") != "text/event-stream" {
				t.Fatalf("content type = %q", res.Header.Get("Content-Type"))
			}
			f.WaitBlocked(t)
			if f.Cancellations() != 0 {
				t.Fatal("cancelled before the client left")
			}
			cancel()
			res.Body.Close()
			deadline := time.Now().Add(10 * time.Second)
			for f.Cancellations() == 0 && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if f.Cancellations() != 1 {
				t.Fatalf("the server saw %d cancellations after the client closed the stream", f.Cancellations())
			}
			// Recorded once, as a call that ended because the client left.
			e.lastRecord("upstream_error client_cancelled", slug+"__block")
			if n := e.scalar(`SELECT count(*)::text FROM mcp_calls WHERE exposed_name = $1`, slug+"__block"); n != "1" {
				t.Errorf("%s records", n)
			}
		})
	}
}

// At most 64 progress events are relayed per call; the call still completes.
func TestStreamProgressCap(t *testing.T) {
	e := newRelayEnv(t, nil)
	body, headers := toolRequest(true, "status__progress", map[string]any{"count": 100, "delay_ms": 0}, map[string]any{"progressToken": "many"})
	res := e.post(context.Background(), body, headers)
	defer res.Body.Close()
	events := readSSE(res.Body)
	progress := 0
	for _, ev := range events {
		if strings.Contains(ev.data, "notifications/progress") {
			progress++
		}
	}
	if progress != 64 || len(events) != 65 || !strings.Contains(events[len(events)-1].data, `"result"`) {
		t.Fatalf("%d progress events, %d in all", progress, len(events))
	}
}

// ---------------------------------------------------------------------------
// Trace context

func TestTraceContextPassthrough(t *testing.T) {
	e := newRelayEnv(t, nil)
	const tp = "00-0af7651916cd43dd8448eb211c80319c-00f067aa0ba902b7-01"
	const ts = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"
	const bg = "userId=alice,serverNode=DF%2028,isProduction=false"
	lastEcho := func() testutil.ToolCall {
		calls := e.fake.ToolCalls()
		for i := len(calls) - 1; i >= 0; i-- {
			if calls[i].Tool == "echo" {
				return calls[i]
			}
		}
		t.Fatal("no echo call")
		return testutil.ToolCall{}
	}
	trace := func(c testutil.ToolCall) [3]any {
		return [3]any{c.Meta["traceparent"], c.Meta["tracestate"], c.Meta["baggage"]}
	}
	for _, upstreamEra := range []testutil.Protocol{testutil.ProtocolModern, testutil.ProtocolLegacy} {
		e.fake.SetProtocol(upstreamEra)
		e.refresh(e.owner, e.server)
		for _, modern := range []bool{true, false} {
			name := fmt.Sprintf("upstream %s downstream modern=%v", upstreamEra, modern)
			send := func(meta map[string]any) testutil.ToolCall {
				t.Helper()
				body, headers := toolRequest(modern, "status__echo", map[string]any{"text": "x"}, meta)
				code, _, out := rawMCP(t, e.app, "POST", "support", e.key, body, headers)
				if code != 200 || out["error"] != nil {
					t.Fatalf("%s: %d %v", name, code, out)
				}
				return lastEcho()
			}
			// Valid values reach the server's _meta as they were.
			if got := trace(send(map[string]any{"traceparent": tp, "tracestate": ts, "baggage": bg})); got != [3]any{tp, ts, bg} {
				t.Errorf("%s: trace context = %v", name, got)
			}
			// None sent: none passed on.
			if got := trace(send(nil)); got != [3]any{nil, nil, nil} {
				t.Errorf("%s: trace context without any = %v", name, got)
			}
			// Malformed or oversized values are dropped, the valid ones stay.
			for what, meta := range map[string]map[string]any{
				"bad traceparent":        {"traceparent": "nonsense", "tracestate": ts, "baggage": bg},
				"all-zero trace id":      {"traceparent": "00-00000000000000000000000000000000-00f067aa0ba902b7-01"},
				"uppercase traceparent":  {"traceparent": strings.ToUpper(tp)},
				"traceparent not string": {"traceparent": 7},
			} {
				got := trace(send(meta))
				if got[0] != nil || got[1] != nil {
					t.Errorf("%s: %s: traceparent/tracestate = %v", name, what, got)
				}
			}
			if got := trace(send(map[string]any{"traceparent": tp, "tracestate": "BAD KEY=x", "baggage": strings.Repeat("a=b,", 600)})); got != [3]any{tp, nil, nil} {
				t.Errorf("%s: invalid tracestate and oversized baggage = %v", name, got)
			}
		}
	}
	// A client's other _meta (and its credentials) are not passed on.
	body, headers := toolRequest(true, "status__echo", map[string]any{"text": "x"}, map[string]any{"x-secret": "nope", "traceparent": tp})
	if code, _, _ := rawMCP(t, e.app, "POST", "support", e.key, body, headers); code != 200 {
		t.Fatal(code)
	}
	if _, ok := lastEcho().Meta["x-secret"]; ok {
		t.Error("an unknown _meta entry was passed on")
	}
}
