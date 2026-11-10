package httpapi_test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

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
