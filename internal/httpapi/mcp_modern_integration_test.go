package httpapi_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// MCP 2026-07-28 at /mcp/{slug}, next to the earlier revisions (docs/mcp-protocol.md):
// every row of the roadmap's table (v0.2 A) in both eras, and the official
// SDK's client in both.

const (
	legacyVersion = "2025-11-25"
	modernVersion = "2026-07-28"
)

func connectModern(t *testing.T, app *testApp, slug, key string) *mcp.ClientSession {
	t.Helper()
	return connectEra(t, app, slug, key, "", nil)
}

func modernParams(params, caps map[string]any) map[string]any {
	p := map[string]any{}
	for k, v := range params {
		p[k] = v
	}
	if caps == nil {
		caps = map[string]any{}
	}
	p["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion":    modernVersion,
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": "modern-test", "version": "1"},
		"io.modelcontextprotocol/clientCapabilities": caps,
	}
	return p
}

// modernHeaders are the headers a conforming client sends for a request;
// extra adds to them or, with an empty value, takes one away.
func modernHeaders(method string, params map[string]any, extra map[string]string) map[string]string {
	h := map[string]string{"MCP-Protocol-Version": modernVersion, "Mcp-Method": method}
	switch method {
	case "tools/call", "prompts/get":
		if n, ok := params["name"].(string); ok {
			h["Mcp-Name"] = n
		}
	case "resources/read":
		if u, ok := params["uri"].(string); ok {
			h["Mcp-Name"] = u
		}
	}
	for k, v := range extra {
		h[k] = v
	}
	return h
}

// rawModern posts a modern request. Headers with an empty value in extra
// are sent empty (the server sees them as missing).
func rawModern(t *testing.T, app *testApp, slug, key, method string, params, caps map[string]any, extra map[string]string) (int, http.Header, map[string]any) {
	t.Helper()
	return rawMCP(t, app, "POST", slug, key, rpc(1, method, modernParams(params, caps)), modernHeaders(method, params, extra))
}

func resultOf(t *testing.T, out map[string]any) map[string]any {
	t.Helper()
	r, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result in %v", out)
	}
	return r
}

func keysOf(m map[string]any) []string {
	out := []string{}
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func serverInfoOf(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	meta, _ := result["_meta"].(map[string]any)
	info, _ := meta["io.modelcontextprotocol/serverInfo"].(map[string]any)
	if info == nil {
		t.Fatalf("no serverInfo in %v", result)
	}
	return info
}

func namesOf(t *testing.T, result map[string]any, list, field string) []string {
	t.Helper()
	items, _ := result[list].([]any)
	out := []string{}
	for _, it := range items {
		out = append(out, it.(map[string]any)[field].(string))
	}
	return out
}

// eraEnv is a team gateway "support" for blair with every kind of
// capability: the tools whoami, echo and lookup (schema features of the new
// revision), the prompt incident_summary, a resource and a template.
type eraEnv struct {
	*gwEnv
	gw   apitypes.Gateway
	path string
	key  apitypes.ApiKeyCreated
}

func newEraEnv(t *testing.T) *eraEnv {
	t.Helper()
	// These tests pin the era behaviour of a portal WITHOUT the Tasks extension
	// (not advertised, task methods unknown); mcp_tasks_integration_test.go
	// covers the same surface with tasks enabled.
	e := &eraEnv{gwEnv: newGwEnvHook(t, nil, disableTasks)}
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	e.fake.EnableSchemaTools()
	e.refresh(e.owner, e.server)
	e.gw = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.path = toolsTeam + "/gateways/" + e.gw.Id.String()
	// Selected out of order: lists must come out sorted by exposed name.
	e.mustSetCaps(e.owner, e.path, sel(
		e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "lookup"), e.capID(e.owner, e.server, "tool", "echo"),
		e.capID(e.owner, e.server, "prompt", "incident_summary"),
		e.capID(e.owner, e.server, "resource_template", "status://services/{service}"), e.capID(e.owner, e.server, "resource", "status://services")))
	e.key = newKey(t, e.member, "laptop")
	return e
}

func (e *eraEnv) modern(method string, params, caps map[string]any, extra map[string]string) (int, http.Header, map[string]any) {
	e.t.Helper()
	return rawModern(e.t, e.app, "support", e.key.Secret, method, params, caps, extra)
}

func (e *eraEnv) legacy(method string, params any) (int, http.Header, map[string]any) {
	e.t.Helper()
	return rawMCP(e.t, e.app, "POST", "support", e.key.Secret, rpc(1, method, params), nil)
}

func TestMCPDiscover(t *testing.T) {
	e := newEraEnv(t)
	code, hdr, out := e.modern("server/discover", nil, nil, nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("discover = %d %v", code, out)
	}
	r := resultOf(t, out)
	if r["resultType"] != "complete" || r["ttlMs"] != float64(30000) || r["cacheScope"] != "private" {
		t.Fatalf("discover result = %v", r)
	}
	if got, _ := json.Marshal(r["supportedVersions"]); string(got) != `["2026-07-28","2025-11-25","2025-06-18","2025-03-26","2024-11-05"]` {
		t.Fatalf("supportedVersions = %s", got)
	}
	caps := r["capabilities"].(map[string]any)
	if got, _ := json.Marshal(caps); string(got) != `{"prompts":{"listChanged":false},"resources":{"listChanged":false,"subscribe":false},"tools":{"listChanged":false}}` {
		t.Fatalf("capabilities = %s", got)
	}
	if info := serverInfoOf(t, r); info["name"] != "support" || info["title"] != "SUPPORT" || info["version"] == "" || info["version"] == nil {
		t.Fatalf("serverInfo = %v", info)
	}
	if _, ok := r["instructions"]; ok {
		t.Fatalf("instructions = %v", r["instructions"])
	}
	if hdr.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", hdr.Get("Cache-Control"))
	}
	// It agrees with the legacy initialize.
	_, _, init := e.legacy("initialize", map[string]any{"protocolVersion": legacyVersion, "capabilities": map[string]any{},
		"clientInfo": map[string]any{"name": "raw", "version": "1"}})
	ir := resultOf(t, init)
	if !equalJSON(ir["capabilities"], caps) || !equalJSON(ir["serverInfo"], serverInfoOf(t, r)) {
		t.Fatalf("initialize %v vs discover %v", ir, r)
	}

	// Without resources, no resources capability.
	e.mustSetCaps(e.owner, e.path, sel(e.capID(e.owner, e.server, "tool", "echo")))
	_, _, out = e.modern("server/discover", nil, nil, nil)
	if got := resultOf(t, out)["capabilities"].(map[string]any); got["resources"] != nil || got["tools"] == nil {
		t.Fatalf("capabilities without resources = %v", got)
	}

	// Without the modern signs, discover is what it was: unknown.
	if code, _, out := e.legacy("server/discover", nil); code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("legacy discover = %d %v", code, out)
	}
	// Needs the same sign-in as everything else.
	if code, hdr, _ := rawModern(t, e.app, "support", "", "server/discover", nil, nil, nil); code != 401 || hdr.Get("WWW-Authenticate") == "" {
		t.Errorf("discover without a key = %d", code)
	}
	if code, _, _ := rawModern(t, e.app, "nope", e.key.Secret, "server/discover", nil, nil, nil); code != 404 {
		t.Errorf("discover of an unknown gateway = %d", code)
	}
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Request validation (the roadmap's "Request validation" row): refused
// modern requests, and the same requests as legacy ones.
func TestMCPRequestValidation(t *testing.T) {
	e := newEraEnv(t)
	enc := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	call := map[string]any{"name": "status__echo", "arguments": map[string]any{"text": "hi"}}
	cases := []struct {
		name    string
		method  string
		params  map[string]any
		caps    map[string]any
		headers map[string]string
		// mutate edits the whole message (meta changes).
		mutate func(m map[string]any)
		status int
		code   float64
		text   string
	}{
		{name: "valid call", method: "tools/call", params: call, status: 200},
		{name: "valid call, base64 name", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": enc("status__echo")}, status: 200},
		{name: "header version mismatch", method: "tools/list", headers: map[string]string{"MCP-Protocol-Version": "2025-11-25"}, status: 400, code: -32020, text: "MCP-Protocol-Version"},
		{name: "no version header", method: "tools/list", headers: map[string]string{"MCP-Protocol-Version": ""}, status: 400, code: -32020, text: "MCP-Protocol-Version"},
		{name: "no method header", method: "tools/list", headers: map[string]string{"Mcp-Method": ""}, status: 400, code: -32020, text: "Mcp-Method"},
		{name: "method mismatch", method: "tools/list", headers: map[string]string{"Mcp-Method": "prompts/list"}, status: 400, code: -32020, text: "Mcp-Method"},
		{name: "no name header", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": ""}, status: 400, code: -32020, text: "Mcp-Name"},
		{name: "name mismatch", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": "status__whoami"}, status: 400, code: -32020, text: "Mcp-Name"},
		// Mcp-Name is the exposed name; the server's own name is not it.
		{name: "name is the original, not exposed", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": "echo"}, status: 400, code: -32020, text: "Mcp-Name"},
		{name: "base64 name of another tool", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": enc("status__whoami")}, status: 400, code: -32020},
		{name: "invalid base64 name", method: "tools/call", params: call, headers: map[string]string{"Mcp-Name": "=?base64?***?="}, status: 400, code: -32020},
		{name: "prompt name mismatch", method: "prompts/get", params: map[string]any{"name": "status__incident_summary"},
			headers: map[string]string{"Mcp-Name": "x"}, status: 400, code: -32020, text: "Mcp-Name"},
		{name: "resource uri mismatch", method: "resources/read", params: map[string]any{"uri": "omp://status/status://services"},
			headers: map[string]string{"Mcp-Name": "omp://status/status://other"}, status: 400, code: -32020, text: "Mcp-Name"},
		{name: "resource uri", method: "resources/read", params: map[string]any{"uri": "omp://status/status://services"}, status: 200},
		{name: "no protocol version in _meta", method: "tools/list", status: 400, code: -32602, text: "protocolVersion",
			mutate: func(m map[string]any) {
				delete(m["params"].(map[string]any)["_meta"].(map[string]any), "io.modelcontextprotocol/protocolVersion")
			}},
		{name: "no capabilities in _meta", method: "tools/list", status: 400, code: -32602, text: "clientCapabilities",
			mutate: func(m map[string]any) {
				delete(m["params"].(map[string]any)["_meta"].(map[string]any), "io.modelcontextprotocol/clientCapabilities")
			}},
		{name: "no _meta at all, modern header", method: "tools/list", status: 400, code: -32602, text: "protocolVersion",
			mutate: func(m map[string]any) { delete(m["params"].(map[string]any), "_meta") }},
		{name: "unsupported version", method: "tools/list", status: 400, code: -32022,
			headers: map[string]string{"MCP-Protocol-Version": "1900-01-01"},
			mutate: func(m map[string]any) {
				m["params"].(map[string]any)["_meta"].(map[string]any)["io.modelcontextprotocol/protocolVersion"] = "1900-01-01"
			}},
		{name: "future version", method: "tools/list", status: 400, code: -32022,
			headers: map[string]string{"MCP-Protocol-Version": "2027-06-01"},
			mutate: func(m map[string]any) {
				m["params"].(map[string]any)["_meta"].(map[string]any)["io.modelcontextprotocol/protocolVersion"] = "2027-06-01"
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			params := modernParams(c.params, c.caps)
			msg := rpc(1, c.method, params)
			if c.mutate != nil {
				c.mutate(msg)
			}
			code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, msg, modernHeaders(c.method, c.params, c.headers))
			if code != c.status {
				t.Fatalf("status = %d, want %d: %v", code, c.status, out)
			}
			if c.status == 200 {
				if out["error"] != nil {
					t.Fatalf("error = %v", out)
				}
				return
			}
			if rpcErrorCode(out) != c.code || out["id"] != float64(1) {
				t.Fatalf("error = %v", out)
			}
			if _, msg, data := rpcErr(out); !strings.Contains(msg, c.text) {
				t.Fatalf("message = %q, want it to mention %q", msg, c.text)
			} else if c.code == -32022 {
				if got, _ := json.Marshal(data["supported"]); string(got) != `["2026-07-28","2025-11-25","2025-06-18","2025-03-26","2024-11-05"]` || data["requested"] == "" {
					t.Fatalf("data = %v", data)
				}
			}
		})
	}

	// Refused requests never reach a server or the call log as calls.
	before, rows := e.fake.Requests(), e.scalar(`SELECT count(*)::text FROM mcp_calls`)
	rawModern(t, e.app, "support", e.key.Secret, "tools/call", call, nil, map[string]string{"Mcp-Name": "echo"})
	if e.fake.Requests() != before || e.scalar(`SELECT count(*)::text FROM mcp_calls`) != rows {
		t.Error("a refused request had effects")
	}

	// The same requests without the modern signs are served as before: no
	// headers required, none validated.
	for _, h := range []map[string]string{nil, {"Mcp-Method": "wrong", "Mcp-Name": "wrong"}, {"MCP-Protocol-Version": "2025-06-18"}} {
		if code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", call), h); code != 200 || out["error"] != nil {
			t.Errorf("legacy call with headers %v = %d %v", h, code, out)
		}
	}
	// An old but unknown version in the header alone is still the old refusal.
	if code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/list", nil), map[string]string{"MCP-Protocol-Version": "2023-01-01"}); code != 400 || rpcErrorCode(out) != -32001 {
		t.Errorf("legacy unsupported version = %d %v", code, out)
	}
	// initialize is legacy whatever it carries.
	code, hdr, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "initialize", modernParams(map[string]any{
		"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "x", "version": "1"}}, nil)),
		map[string]string{"MCP-Protocol-Version": modernVersion})
	if r := resultOf(t, out); code != 200 || r["protocolVersion"] != legacyVersion || r["resultType"] != nil || hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("initialize with modern fields = %d %v", code, out)
	}
}

// Parameter headers: tools whose definition marks arguments x-mcp-header.
func TestMCPParamHeaders(t *testing.T) {
	e := newEraEnv(t)
	enc := func(s string) string { return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(s)) + "?=" }
	lookup := func(args map[string]any, extra map[string]string) (int, map[string]any) {
		code, _, out := e.modern("tools/call", map[string]any{"name": "status__lookup", "arguments": args}, nil, extra)
		return code, out
	}
	// The listed definition carries the annotations.
	_, _, out := e.modern("tools/list", nil, nil, nil)
	var found bool
	for _, tool := range resultOf(t, out)["tools"].([]any) {
		if tool.(map[string]any)["name"] == "status__lookup" {
			props := tool.(map[string]any)["inputSchema"].(map[string]any)["properties"].(map[string]any)
			found = props["region"].(map[string]any)["x-mcp-header"] == "Region"
		}
	}
	if !found {
		t.Fatalf("x-mcp-header missing from the listed lookup: %v", out)
	}

	good := map[string]string{"Mcp-Param-Region": "us-west1", "Mcp-Param-Limit": "10"}
	if code, out := lookup(map[string]any{"region": "us-west1", "limit": 10, "note": "n"}, good); code != 200 || out["error"] != nil {
		t.Fatalf("matching headers = %d %v", code, out)
	}
	// Upstream gets the original tool name and its parameter headers.
	calls := e.fake.ToolCalls()
	last := calls[len(calls)-1]
	if last.Tool != "lookup" || last.Header.Get("Mcp-Param-Region") != "us-west1" || last.Header.Get("Mcp-Param-Limit") != "10" || last.Header.Get("Mcp-Name") != "lookup" {
		t.Fatalf("upstream saw %s %v", last.Tool, last.Header)
	}
	for what, c := range map[string]struct {
		args  map[string]any
		extra map[string]string
		ok    bool
	}{
		"base64 value":            {map[string]any{"region": "Hello, 世界", "limit": 1}, map[string]string{"Mcp-Param-Region": enc("Hello, 世界"), "Mcp-Param-Limit": "1"}, true},
		"integer as decimal":      {map[string]any{"limit": 7}, map[string]string{"Mcp-Param-Limit": "7.0"}, true},
		"absent arguments":        {map[string]any{"note": "x"}, nil, true},
		"null argument":           {map[string]any{"region": nil}, nil, true},
		"missing header":          {map[string]any{"region": "us", "limit": 1}, map[string]string{"Mcp-Param-Limit": "1"}, false},
		"mismatch":                {map[string]any{"region": "us", "limit": 1}, map[string]string{"Mcp-Param-Region": "eu", "Mcp-Param-Limit": "1"}, false},
		"integer mismatch":        {map[string]any{"limit": 1}, map[string]string{"Mcp-Param-Limit": "2"}, false},
		"header for absent value": {map[string]any{"note": "x"}, map[string]string{"Mcp-Param-Region": "us"}, false},
		"header for a null value": {map[string]any{"region": nil}, map[string]string{"Mcp-Param-Region": "us"}, false},
		"invalid base64":          {map[string]any{"region": "us"}, map[string]string{"Mcp-Param-Region": "=?base64?%%?="}, false},
		"base64 of another value": {map[string]any{"region": "us"}, map[string]string{"Mcp-Param-Region": enc("eu")}, false},
	} {
		code, out := lookup(c.args, c.extra)
		switch {
		case c.ok && (code != 200 || out["error"] != nil):
			t.Errorf("%s = %d %v", what, code, out)
		case !c.ok && (code != 400 || rpcErrorCode(out) != -32020):
			t.Errorf("%s = %d %v, want 400 -32020", what, code, out)
		}
	}
	// The refusal is recorded without reaching the server.
	before := len(e.fake.ToolCalls())
	lookup(map[string]any{"region": "us"}, nil)
	if len(e.fake.ToolCalls()) != before {
		t.Error("a refused call reached the server")
	}
	if got := e.scalar(`SELECT outcome || ' ' || error_class FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "bad_request header_mismatch" {
		t.Errorf("recorded %q", got)
	}
	// An unknown tool is unknown, not a header problem; a tool that isn't
	// selected can't be probed through its headers.
	if code, _, out := e.modern("tools/call", map[string]any{"name": "status__nope", "arguments": map[string]any{"a": 1}}, nil, map[string]string{"Mcp-Param-A": "zzz"}); code != 200 || rpcErrorCode(out) != -32602 {
		t.Errorf("unknown tool = %d %v", code, out)
	}
	// Legacy: no headers needed.
	if code, _, out := e.legacy("tools/call", map[string]any{"name": "status__lookup", "arguments": map[string]any{"region": "us", "limit": 1}}); code != 200 || out["error"] != nil {
		t.Errorf("legacy lookup = %d %v", code, out)
	}
}

// Result shape, caching, order (the "Result shape" row).
func TestMCPResultShape(t *testing.T) {
	e := newEraEnv(t)
	lists := []struct {
		method, key, field string
		want               []string
	}{
		{"tools/list", "tools", "name", []string{"status__echo", "status__lookup", "status__whoami"}},
		{"prompts/list", "prompts", "name", []string{"status__incident_summary"}},
		{"resources/list", "resources", "uri", []string{"omp://status/status://services"}},
		{"resources/templates/list", "resourceTemplates", "uriTemplate", []string{"omp://status/status://services/{service}"}},
	}
	for _, l := range lists {
		t.Run(l.method, func(t *testing.T) {
			// Modern: resultType, serverInfo, private cache hints, sorted.
			code, hdr, out := e.modern(l.method, nil, nil, nil)
			if code != 200 {
				t.Fatalf("modern = %d %v", code, out)
			}
			r := resultOf(t, out)
			if got := namesOf(t, r, l.key, l.field); !slices.Equal(got, l.want) {
				t.Fatalf("modern %s = %v, want %v", l.key, got, l.want)
			}
			if r["resultType"] != "complete" || r["ttlMs"] != float64(30000) || r["cacheScope"] != "private" {
				t.Fatalf("modern result = %v", keysOf(r))
			}
			if serverInfoOf(t, r)["name"] != "support" {
				t.Fatalf("serverInfo = %v", r["_meta"])
			}
			if hdr.Get("Cache-Control") != "no-store" || strings.Contains(hdr.Get("Cache-Control"), "public") {
				t.Errorf("Cache-Control = %q", hdr.Get("Cache-Control"))
			}
			// Legacy: exactly the list, as before.
			code, _, out = e.legacy(l.method, nil)
			r = resultOf(t, out)
			if code != 200 || !slices.Equal(keysOf(r), []string{l.key}) {
				t.Fatalf("legacy result keys = %v", keysOf(r))
			}
			if got := namesOf(t, r, l.key, l.field); !slices.Equal(got, l.want) {
				t.Fatalf("legacy %s = %v", l.key, got)
			}
		})
	}

	// Lists differ per person: never public, and a person without access
	// to a capability doesn't see it.
	e.mustSetCaps(e.owner, e.path, sel(e.capID(e.owner, e.server, "tool", "echo"), e.capID(e.owner, e.server, "tool", "whoami")+":admin"))
	ownerKey := newKey(t, e.owner, "owner")
	for who, c := range map[string]struct {
		key  string
		want []string
	}{"member": {e.key.Secret, []string{"status__echo"}}, "owner": {ownerKey.Secret, []string{"status__echo", "status__whoami"}}} {
		_, _, out := rawModern(t, e.app, "support", c.key, "tools/list", nil, nil, nil)
		r := resultOf(t, out)
		if got := namesOf(t, r, "tools", "name"); !slices.Equal(got, c.want) || r["cacheScope"] != "private" {
			t.Errorf("%s: tools = %v scope %v", who, got, r["cacheScope"])
		}
	}
	e.mustSetCaps(e.owner, e.path, sel(
		e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "lookup"), e.capID(e.owner, e.server, "tool", "echo"),
		e.capID(e.owner, e.server, "prompt", "incident_summary"),
		e.capID(e.owner, e.server, "resource_template", "status://services/{service}"), e.capID(e.owner, e.server, "resource", "status://services")))

	// A call: complete, our identity, no cache hints.
	code, _, out := e.modern("tools/call", map[string]any{"name": "status__echo", "arguments": map[string]any{"text": "hi"}}, nil, nil)
	r := resultOf(t, out)
	if code != 200 || r["resultType"] != "complete" || r["ttlMs"] != nil || r["cacheScope"] != nil || serverInfoOf(t, r)["name"] != "support" {
		t.Fatalf("modern call = %d %v", code, out)
	}
	if content := r["content"].([]any); content[0].(map[string]any)["text"] != "hi" {
		t.Fatalf("content = %v", content)
	}
	_, _, out = e.legacy("tools/call", map[string]any{"name": "status__echo", "arguments": map[string]any{"text": "hi"}})
	// (A relayed result is the upstream SDK's, whose own fields pass as
	// they always did; what the gateway adds in the modern era it doesn't.)
	if r := resultOf(t, out); r["_meta"] != nil || r["structuredContent"] != nil {
		t.Errorf("legacy call result = %v", r)
	}
	// A prompt.
	_, _, out = e.modern("prompts/get", map[string]any{"name": "status__incident_summary", "arguments": map[string]any{"service": "vpn"}}, nil, nil)
	if r := resultOf(t, out); r["resultType"] != "complete" || r["ttlMs"] != nil || len(r["messages"].([]any)) != 1 {
		t.Errorf("modern prompt = %v", out)
	}
	_, _, out = e.legacy("prompts/get", map[string]any{"name": "status__incident_summary", "arguments": map[string]any{"service": "vpn"}})
	if r := resultOf(t, out); r["_meta"] != nil || r["messages"] == nil {
		t.Errorf("legacy prompt result = %v", r)
	}
	// A read: complete, private, fresh every time.
	uri := map[string]any{"uri": "omp://status/status://services/email"}
	_, _, out = e.modern("resources/read", uri, nil, nil)
	if r := resultOf(t, out); r["resultType"] != "complete" || r["ttlMs"] != float64(0) || r["cacheScope"] != "private" ||
		r["contents"].([]any)[0].(map[string]any)["uri"] != "omp://status/status://services/email" || serverInfoOf(t, r)["name"] != "support" {
		t.Errorf("modern read = %v", out)
	}
	_, _, out = e.legacy("resources/read", uri)
	if r := resultOf(t, out); r["_meta"] != nil || r["contents"] == nil {
		t.Errorf("legacy read result = %v", r)
	}
}

// However the selection was made, the list comes out sorted.
func TestMCPListOrderIsDeterministic(t *testing.T) {
	e := newEraEnv(t)
	for i := 0; i < 3; i++ {
		e.fake.AddTool(strings.Repeat("a", i+1) + "_bulk")
	}
	e.refresh(e.owner, e.server)
	var ids []string
	for _, n := range []string{"whoami", "lookup", "echo", "a_bulk", "aa_bulk", "aaa_bulk"} {
		ids = append(ids, e.capID(e.owner, e.server, "tool", n))
	}
	slices.Reverse(ids)
	e.mustSetCaps(e.owner, e.path, sel(ids...))
	var names []string
	cursor := ""
	for page := 0; page < 20; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		_, _, out := e.modern("tools/list", params, nil, nil)
		r := resultOf(t, out)
		if r["cacheScope"] != "private" || r["ttlMs"] != float64(30000) {
			t.Fatalf("page %d = %v", page, keysOf(r))
		}
		names = append(names, namesOf(t, r, "tools", "name")...)
		if cursor, _ = r["nextCursor"].(string); cursor == "" {
			break
		}
	}
	want := slices.Clone(names)
	slices.Sort(want)
	if len(names) != 6 || !slices.Equal(names, want) {
		t.Fatalf("tools = %v", names)
	}
}

// Era-aware schemas: any JSON Schema outputSchema and any JSON
// structuredContent for modern clients; objects only for legacy ones.
func TestMCPSchemasByEra(t *testing.T) {
	e := newEraEnv(t)
	toolOf := func(out map[string]any, name string) map[string]any {
		for _, tool := range resultOf(t, out)["tools"].([]any) {
			if tool.(map[string]any)["name"] == name {
				return tool.(map[string]any)
			}
		}
		t.Fatalf("no tool %s in %v", name, out)
		return nil
	}
	_, _, out := e.modern("tools/list", nil, nil, nil)
	if got := toolOf(out, "status__lookup")["outputSchema"]; !equalJSON(got, map[string]any{"type": []any{"null", "array"}}) {
		t.Errorf("modern outputSchema = %v", got)
	}
	_, _, out = e.legacy("tools/list", nil)
	if _, ok := toolOf(out, "status__lookup")["outputSchema"]; ok {
		t.Error("legacy outputSchema was not dropped")
	}
	args := map[string]any{"name": "status__lookup", "arguments": map[string]any{"region": "us", "limit": 3}}
	_, _, out = e.modern("tools/call", args, nil, map[string]string{"Mcp-Param-Region": "us", "Mcp-Param-Limit": "3"})
	if got := resultOf(t, out)["structuredContent"]; !equalJSON(got, []any{map[string]any{"region": "us", "limit": 3}}) {
		t.Errorf("modern structuredContent = %v (%v)", got, out)
	}
	_, _, out = e.legacy("tools/call", args)
	if r := resultOf(t, out); r["structuredContent"] != nil || len(r["content"].([]any)) != 1 {
		t.Errorf("legacy structuredContent = %v", r)
	}
}

// Error codes by era and the methods the new era dropped.
func TestMCPErrorsAndRemovedMethods(t *testing.T) {
	e := newEraEnv(t)
	uri := map[string]any{"uri": "omp://status/status://other"}
	code, _, out := e.modern("resources/read", uri, nil, nil)
	if code != 200 || rpcErrorCode(out) != -32602 {
		t.Errorf("modern resource not found = %d %v", code, out)
	}
	code, _, out = e.legacy("resources/read", uri)
	if code != 200 || rpcErrorCode(out) != -32002 {
		t.Errorf("legacy resource not found = %d %v", code, out)
	}
	// An unknown tool is invalid params in both.
	for _, call := range []func() (int, http.Header, map[string]any){
		func() (int, http.Header, map[string]any) {
			return e.modern("tools/call", map[string]any{"name": "status__nope"}, nil, nil)
		},
		func() (int, http.Header, map[string]any) {
			return e.legacy("tools/call", map[string]any{"name": "status__nope"})
		},
	} {
		if code, _, out := call(); code != 200 || rpcErrorCode(out) != -32602 {
			t.Errorf("unknown tool = %d %v", code, out)
		}
	}

	// ping and logging/setLevel are gone: 404 and method not found. Legacy
	// keeps ping and has never had setLevel.
	for _, m := range []string{"ping", "logging/setLevel", "subscriptions/listen", "resources/subscribe", "completion/complete", "tasks/get"} {
		if code, _, out := e.modern(m, map[string]any{"level": "info", "uri": "x"}, nil, nil); code != 404 || rpcErrorCode(out) != -32601 {
			t.Errorf("modern %s = %d %v", m, code, out)
		}
	}
	if code, _, out := e.legacy("ping", nil); code != 200 || out["result"] == nil {
		t.Errorf("legacy ping = %d %v", code, out)
	}
	if code, _, out := e.legacy("logging/setLevel", map[string]any{"level": "info"}); code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("legacy logging/setLevel = %d %v", code, out)
	}
	// resources/* without any resource selected: not found in both eras.
	e.mustSetCaps(e.owner, e.path, sel(e.capID(e.owner, e.server, "tool", "echo")))
	if code, _, out := e.modern("resources/list", nil, nil, nil); code != 404 || rpcErrorCode(out) != -32601 {
		t.Errorf("modern resources/list without resources = %d %v", code, out)
	}
	if code, _, out := e.legacy("resources/list", nil); code != 200 || rpcErrorCode(out) != -32601 {
		t.Errorf("legacy resources/list without resources = %d %v", code, out)
	}
}

// Transport edges that did not change: 405, session ids and Last-Event-ID
// ignored, batches refused, Origin checked.
func TestMCPTransportEdges(t *testing.T) {
	e := newEraEnv(t)
	for _, m := range []string{"GET", "DELETE"} {
		if code, hdr, _ := rawMCP(t, e.app, m, "support", e.key.Secret, nil, modernHeaders("tools/list", nil, nil)); code != 405 || hdr.Get("Allow") != "POST" {
			t.Errorf("%s = %d", m, code)
		}
	}
	extra := map[string]string{"Mcp-Session-Id": "abc-123", "Last-Event-ID": "42"}
	code, hdr, out := e.modern("tools/list", nil, nil, extra)
	if code != 200 || out["error"] != nil || hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("modern with a session id = %d %v %q", code, out, hdr.Get("Mcp-Session-Id"))
	}
	code, hdr, out = rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/list", nil), extra)
	if code != 200 || out["error"] != nil || hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("legacy with a session id = %d %v", code, out)
	}
	_, hdr, _ = e.legacy("initialize", map[string]any{"protocolVersion": legacyVersion, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "x", "version": "1"}})
	if hdr.Get("Mcp-Session-Id") != "" {
		t.Errorf("initialize minted a session id: %q", hdr.Get("Mcp-Session-Id"))
	}
	batch := []any{rpc(1, "tools/list", modernParams(nil, nil)), rpc(2, "tools/list", modernParams(nil, nil))}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", e.key.Secret, batch, modernHeaders("tools/list", nil, nil)); code != 400 {
		t.Errorf("modern batch = %d", code)
	}
	if code, _, _ := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/list", modernParams(nil, nil)),
		modernHeaders("tools/list", nil, map[string]string{"Origin": "https://evil.example"})); code != 403 {
		t.Errorf("modern foreign origin = %d", code)
	}
	// A notification is accepted without headers in either era.
	if code, _, _ := rawMCP(t, e.app, "POST", "support", e.key.Secret, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, nil); code != 202 {
		t.Errorf("notification = %d", code)
	}
	// The client's name from _meta is recorded.
	e.modern("tools/list", nil, nil, nil)
	if got := e.scalar(`SELECT coalesce(client_name, '') FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "modern-test" {
		t.Errorf("client name = %q", got)
	}
}

// The official SDK's client in both eras against one gateway.
func TestMCPSDKClientBothEras(t *testing.T) {
	for _, era := range []struct{ name, version, want string }{{"legacy", legacyVersion, legacyVersion}, {"modern", "", modernVersion}} {
		t.Run(era.name, func(t *testing.T) {
			e := newEraEnv(t)
			ctx := context.Background()
			cs := connectEra(t, e.app, "support", e.key.Secret, era.version, nil)
			init := cs.InitializeResult()
			if init.ProtocolVersion != era.want || init.ServerInfo == nil || init.ServerInfo.Name != "support" || init.Capabilities.Tools == nil ||
				init.Capabilities.Prompts == nil || init.Capabilities.Resources == nil {
				t.Fatalf("session = %+v %+v", init, init.ServerInfo)
			}
			if got := toolNames(t, cs); !slices.Equal(got, []string{"status__echo", "status__lookup", "status__whoami"}) {
				t.Fatalf("tools = %v", got)
			}
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__echo", Arguments: map[string]any{"text": "hello"}})
			if err != nil || resultText(t, res) != "hello" {
				t.Fatalf("echo = %+v %v", res, err)
			}
			// whoami: the identity token reached the server in both eras.
			res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__whoami"})
			if err != nil || res.IsError || !strings.Contains(resultText(t, res), `"verified":true`) {
				t.Fatalf("whoami = %+v %v", res, err)
			}
			// x-mcp-header: the SDK adds the headers itself in the modern era.
			res, err = cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__lookup", Arguments: map[string]any{"region": "eu-1", "limit": 5}})
			if err != nil || res.IsError {
				t.Fatalf("lookup = %+v %v", res, err)
			}
			if era.name == "modern" {
				if sc, _ := json.Marshal(res.StructuredContent); string(sc) != `[{"limit":5,"region":"eu-1"}]` {
					t.Errorf("structuredContent = %s", sc)
				}
			}
			calls := e.fake.ToolCalls()
			if last := calls[len(calls)-1]; last.Tool != "lookup" || last.Header.Get("Mcp-Param-Region") != "eu-1" {
				t.Errorf("upstream saw %v", last.Header)
			}
			pr, err := cs.GetPrompt(ctx, &mcp.GetPromptParams{Name: "status__incident_summary", Arguments: map[string]string{"service": "vpn"}})
			if err != nil || len(pr.Messages) != 1 {
				t.Fatalf("prompt = %+v %v", pr, err)
			}
			prompts, err := cs.ListPrompts(ctx, nil)
			if err != nil || len(prompts.Prompts) != 1 || prompts.Prompts[0].Name != "status__incident_summary" {
				t.Fatalf("prompts = %+v %v", prompts, err)
			}
			rs, err := cs.ListResources(ctx, nil)
			if err != nil || len(rs.Resources) != 1 || rs.Resources[0].URI != "omp://status/status://services" {
				t.Fatalf("resources = %+v %v", rs, err)
			}
			rt, err := cs.ListResourceTemplates(ctx, nil)
			if err != nil || len(rt.ResourceTemplates) != 1 {
				t.Fatalf("templates = %+v %v", rt, err)
			}
			read, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "omp://status/status://services/email"})
			if err != nil || len(read.Contents) != 1 || read.Contents[0].Text != "operating normally" {
				t.Fatalf("read = %+v %v", read, err)
			}
			if _, err := cs.ReadResource(ctx, &mcp.ReadResourceParams{URI: "omp://status/status://nope"}); err == nil {
				t.Fatal("an unselected resource was read")
			}
			if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "status__nope"}); err == nil || !strings.Contains(err.Error(), "Unknown tool") {
				t.Fatalf("unknown tool = %v", err)
			}
		})
	}
}

// Over a rate limit a modern request is 429 with code 429 (-32029 is in the
// range 2026-07-28 reserves for itself); legacy requests keep -32029.
func TestMCPRateLimitCodeByEra(t *testing.T) {
	e := newRuntimeEnv(t)
	code, ec := e.putLimits(limit("credential_per_minute", 2, nil), limit("person_per_minute", 1000, nil))
	mustCode(t, "limits", code, ec, 200, "")
	freshWindow(t, e.app.Pool)
	for i := 0; i < 2; i++ {
		if code, _, out := rawModern(t, e.app, "support", e.key.Secret, "tools/list", nil, nil, nil); code != 200 || out["error"] != nil {
			t.Fatalf("request %d = %d %v", i+1, code, out)
		}
	}
	code, hdr, out := rawModern(t, e.app, "support", e.key.Secret, "tools/call", map[string]any{"name": "status__whoami"}, nil, nil)
	_, _, data := rpcErr(out)
	if code != 429 || rpcErrorCode(out) != 429 || hdr.Get("Retry-After") == "" || data["reason"] != "rate_limited" || data["limit"] != "credential_per_minute" {
		t.Fatalf("modern over the limit = %d %v", code, out)
	}
	code, _, out = rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/list", nil), nil)
	if code != 429 || rpcErrorCode(out) != -32029 {
		t.Fatalf("legacy over the limit = %d %v", code, out)
	}
}
