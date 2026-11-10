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

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

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
