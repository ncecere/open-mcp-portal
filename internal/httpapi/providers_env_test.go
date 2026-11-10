package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

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
