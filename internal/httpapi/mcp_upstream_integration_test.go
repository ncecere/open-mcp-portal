package httpapi_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
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

// Bounds and shape of what is relayed, checked on the validation itself.
// (internal/mcpgw/relay_test.go)

// ---------------------------------------------------------------------------
// Streaming

// ---------------------------------------------------------------------------
// Trace context
