package httpapi_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Per-person secrets as an upstream auth mode (roadmap #22, decision 72,
// docs/person-secrets.md): each person pastes their own key for a server, it
// is sealed per person, server and origin, sent in the placement the team
// chose, never shown again, and used for an agent's call only when the person
// allowed it.

const (
	ownerKey    = "owner-key-sentinel-0001"
	blairKey    = "blair-key-sentinel-0002"
	querySecret = "q sentinel&0003/+"
	secretsRPC  = "keyed__echo_secrets"
)

type secEnv struct {
	*gwEnv
	logs *syncBuffer
	reg  *registry.Service
	kf   *testutil.FakeMCP
	srv  apitypes.McpServer
	gw   apitypes.Gateway
	// ownerMCP and blairMCP are their personal API keys for /mcp.
	ownerMCP, blairMCP string
	// seen collects every response body, for the sentinel scan.
	seen []string
}

func (e *secEnv) path() string { return toolsTeam + "/mcp-servers/" + e.srv.Id.String() }

func secretConfig(placement, name, prefix string) map[string]any {
	c := map[string]any{"placement": placement, "label": "Acme API key", "help": "Account settings, API keys."}
	if name != "" {
		c["name"] = name
	}
	if prefix != "" {
		c["prefix"] = prefix
	}
	return c
}

// newSecEnvRaw is the team, a fake server in person_secret mode (header
// X-Api-Key) and nothing else: nobody has entered a key.
func newSecEnvRaw(t *testing.T) *secEnv {
	t.Helper()
	logs := &syncBuffer{}
	e := &secEnv{logs: logs}
	e.gwEnv = newGwEnvHook(t, slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})), func(d *httpapi.Deps) { e.reg = d.Registry })
	e.kf = testutil.NewFakeMCP(t)
	e.kf.EnableGatewayTools()
	e.kf.EnableEchoSecrets()
	e.srv = e.createServer(e.owner, "tools", "keyed", e.kf.URL(), map[string]any{
		"authMode": "person_secret", "personSecret": secretConfig("header", "X-Api-Key", ""),
	})
	return e
}

// newSecEnv also has the owner's key as the setup key (capabilities read with
// it), a gateway "support" offering echo_secrets and whoami, and both people's
// MCP keys. Blair has entered no key.
func newSecEnv(t *testing.T) *secEnv {
	t.Helper()
	e := newSecEnvRaw(t)
	e.putKey(e.owner, ownerKey, map[string]any{"useForSetup": true}, 200)
	e.gw = e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gw.Id.String(), sel(
		e.capID(e.owner, e.srv, "tool", "echo_secrets"), e.capID(e.owner, e.srv, "tool", "whoami")))
	e.ownerMCP, e.blairMCP = newKey(t, e.owner, "laptop").Secret, newKey(t, e.member, "laptop").Secret
	return e
}

func (e *secEnv) origin() string { return registry.OriginOf(e.kf.URL()) }

// putKey enters (or changes) a person's key and returns the body.
func (e *secEnv) putKey(s *session, value string, extra map[string]any, want int) []byte {
	e.t.Helper()
	body := map[string]any{"origin": e.origin()}
	if value != "" {
		body["value"] = value
	}
	for k, v := range extra {
		body[k] = v
	}
	code, raw := s.raw("PUT", "/v1/me/server-secrets/"+e.srv.Id.String(), body, nil)
	e.seen = append(e.seen, string(raw))
	if code != want {
		e.t.Fatalf("PUT the key = %d %s, want %d", code, raw, want)
	}
	return raw
}

func (e *secEnv) mine(s *session) apitypes.ServerSecret {
	e.t.Helper()
	var list []apitypes.ServerSecret
	code, _ := s.call("GET", "/v1/me/server-secrets", nil, &list, nil)
	if code != 200 {
		e.t.Fatalf("list = %d", code)
	}
	b, _ := json.Marshal(list)
	e.seen = append(e.seen, string(b))
	for _, m := range list {
		if m.Server.Id == e.srv.Id {
			return m
		}
	}
	e.t.Fatalf("the server is not listed: %s", b)
	return apitypes.ServerSecret{}
}

// call makes a tools/call as an MCP key (legacy era) and records the answer.
func (e *secEnv) call(key, tool string) (int, map[string]any) {
	e.t.Helper()
	code, _, out := rawMCP(e.t, e.app, "POST", "support", key, rpc(1, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{"note": "hi"}}), nil)
	b, _ := json.Marshal(out)
	e.seen = append(e.seen, string(b))
	return code, out
}

// lastCall waits for the newest call record and returns "outcome class".
func (e *secEnv) lastCall(want string) {
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

// echoed is the text of a successful call's answer. A server that echoes the
// key back (the fake's echo_secrets does) gets it redacted on the way out.
func echoed(t *testing.T, out map[string]any) string {
	t.Helper()
	text, isErr := toolText(t, out)
	if isErr {
		t.Fatalf("the call failed: %s", text)
	}
	return text
}

// lastSent is the X-Api-Key the server received on its newest request.
func (e *secEnv) lastSent() string {
	reqs := e.kf.HTTPRequests()
	return reqs[len(reqs)-1].Header.Get("X-Api-Key")
}

// sentOK checks that a call went through and the server got key in X-Api-Key.
func (e *secEnv) sentOK(out map[string]any, key string) {
	e.t.Helper()
	echoed(e.t, out)
	if got := e.lastSent(); got != key {
		e.t.Fatalf("the server got X-Api-Key %q, want %q", got, key)
	}
}

func TestPersonSecretSetupReadsCapabilitiesWithTheSetupKey(t *testing.T) {
	e := newSecEnvRaw(t)
	sv := e.srv
	if sv.AuthMode == nil || *sv.AuthMode != "person_secret" || sv.PersonSecret == nil || sv.PersonSecret.Placement != "header" ||
		*sv.PersonSecret.Name != "X-Api-Key" || sv.PersonSecret.Setup.Status != "missing" || sv.PersonSecret.People != 0 || sv.HasAuth {
		t.Fatalf("server = %+v %+v", sv, sv.PersonSecret)
	}
	// Nobody's key reads the capabilities yet: nothing was sent, and Refresh says why.
	if n := e.kf.Requests(); n != 0 {
		t.Fatalf("the server was contacted %d times before any key", n)
	}
	code, raw := e.owner.raw("POST", e.path()+"/refresh", nil, nil)
	if code != 409 || errorCode(raw) != "setup_secret_required" {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	// A member can't read it with theirs; an editor can, and it is read with it.
	e.putKey(e.member, blairKey, map[string]any{"useForSetup": true}, 404) // not reachable and not an editor
	e.kf.RequireHeader("X-Api-Key", ownerKey)
	e.putKey(e.owner, ownerKey, map[string]any{"useForSetup": true}, 200)
	reqs := e.kf.HTTPRequests()
	if len(reqs) == 0 {
		t.Fatal("capabilities were not read")
	}
	for _, r := range reqs {
		if r.Header.Get("X-Api-Key") != ownerKey {
			t.Errorf("a discovery request lacks the setup key: %v", r.Header)
		}
	}
	var got apitypes.McpServer
	e.owner.get(e.path(), &got)
	if got.Counts.Tools == 0 || got.PersonSecret.Setup.Status != "active" || got.PersonSecret.People != 1 || *got.PersonSecret.Setup.PersonName == "" {
		t.Fatalf("after setup: %+v %+v", got.Counts, got.PersonSecret)
	}

	// Scheduled checks send nobody's key; the server's 401 is healthy ("requires a personal key").
	before := len(e.kf.HTTPRequests())
	if _, err := e.app.Pool.Exec(context.Background(), `DELETE FROM mcp_health_checks`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RunHealthChecks(context.Background(), time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, r := range e.kf.HTTPRequests()[before:] {
		if r.Header.Get("X-Api-Key") != "" || strings.Contains(r.RawQuery, ownerKey) {
			t.Errorf("a scheduled check carried a key: %v", r.Header)
		}
	}
	e.owner.get(e.path(), &got)
	if got.Health.Status != "healthy" || got.Health.SignInRequired == nil || !*got.Health.SignInRequired {
		t.Fatalf("health = %+v", got.Health)
	}
	// A manual Test reads with the setup key.
	before = len(e.kf.HTTPRequests())
	code, raw = e.owner.raw("POST", e.path()+"/test", nil, nil)
	if code != 200 || !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("test = %d %s", code, raw)
	}
	for _, r := range e.kf.HTTPRequests()[before:] {
		if r.Header.Get("X-Api-Key") != ownerKey {
			t.Errorf("the test lacks the setup key: %v", r.Header)
		}
	}
}

func TestPersonSecretEachPersonSendsTheirOwn(t *testing.T) {
	for _, tc := range []struct {
		name, placement, field, prefix string
		sent                           func(owner, blair string) (string, string)
	}{
		{"header", "header", "X-Api-Key", "Token ", nil},
		{"bearer", "bearer", "", "", nil},
		{"query", "query", "api_key", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newSecEnv(t)
			if tc.placement != "header" || tc.prefix != "" {
				// Another placement forgets every key (the setup key too): enter again.
				e.patchServer(e.owner, e.srv, map[string]any{"personSecret": secretConfig(tc.placement, tc.field, tc.prefix)})
				if tc.placement != "header" && e.mine(e.owner).HasSecret {
					t.Fatal("a new placement kept the key")
				}
			}
			e.putKey(e.owner, ownerKey, nil, 200)
			e.putKey(e.member, blairKey, nil, 200)
			for who, want := range map[string]string{e.ownerMCP: ownerKey, e.blairMCP: blairKey} {
				before := len(e.kf.HTTPRequests())
				code, out := e.call(who, secretsRPC)
				if code != 200 {
					t.Fatalf("call = %d %v", code, out)
				}
				text := echoed(t, out)
				reqs := e.kf.HTTPRequests()[before:]
				if len(reqs) == 0 {
					t.Fatal("nothing reached the server")
				}
				for _, r := range reqs {
					switch tc.placement {
					case "header":
						if r.Header.Get("X-Api-Key") != tc.prefix+want {
							t.Errorf("X-Api-Key = %q, want %q", r.Header.Get("X-Api-Key"), tc.prefix+want)
						}
					case "bearer":
						if r.Header.Get("Authorization") != "Bearer "+want || len(r.Header.Get("MCP-Gateway-Identity")) < 50 {
							t.Errorf("bearer: Authorization %q, identity %d chars: the identity token must move to MCP-Gateway-Identity",
								r.Header.Get("Authorization"), len(r.Header.Get("MCP-Gateway-Identity")))
						}
					case "query":
						q, _ := url.ParseQuery(r.RawQuery)
						if q.Get("api_key") != want {
							t.Errorf("api_key = %q, want %q", q.Get("api_key"), want)
						}
					}
				}
				// The other person's key never went along; nor did the answer
				// give either key back (the server echoed its own).
				other := blairKey
				if want == blairKey {
					other = ownerKey
				}
				for _, r := range reqs {
					if strings.Contains(r.RawQuery, other) || strings.Contains(strings.Join(r.Header.Values("X-Api-Key"), ""), other) ||
						strings.Contains(r.Header.Get("Authorization"), other) {
						t.Errorf("another person's key was sent: %v", r.Header)
					}
				}
				if strings.Contains(text, want) {
					t.Errorf("the key came back to the client: %s", text)
				}
			}
			// Used, and shown only as a hint.
			if m := e.mine(e.member); !m.HasSecret || *m.Hint != "0002" || m.LastUsedAt == nil || m.Status == nil || *m.Status != "active" {
				t.Errorf("entry = %+v", m)
			}
		})
	}
}

// consentFor checks the answer of a call with no key, in the three client eras,
// and that nothing reached the server.
func TestPersonSecretMissingKeyIsAskedInEveryEra(t *testing.T) {
	e := newSecEnv(t)
	before := e.kf.Requests()
	// Legacy: -32042 with the link.
	code, out := e.call(e.blairMCP, secretsRPC)
	c, msg, data := rpcErr(out)
	els, _ := data["elicitations"].([]any)
	if code != 200 || c != -32042 || len(els) != 1 {
		t.Fatalf("legacy = %d %v", code, out)
	}
	el := els[0].(map[string]any)
	link, _ := el["url"].(string)
	if !strings.HasPrefix(link, e.app.URL+"/connect/secret/") || el["mode"] != "url" || !strings.Contains(msg, link) ||
		!strings.Contains(msg, "KEYED (tools)") || !strings.Contains(msg, "Acme API key") {
		t.Fatalf("legacy answer = %v", out)
	}
	e.lastCall("needs_authorization secret_missing")
	// Modern, declared URL elicitation: an input request with the same link.
	_, _, mo := rawModern(t, e.app, "support", e.blairMCP, "tools/call", map[string]any{"name": secretsRPC, "arguments": map[string]any{}}, urlCaps, nil)
	r := resultOf(t, mo)
	reqs, _ := r["inputRequests"].(map[string]any)
	if r["resultType"] != "input_required" || len(reqs) != 1 || r["requestState"] == "" {
		t.Fatalf("modern with elicitation = %v", mo)
	}
	for _, ir := range reqs {
		params := ir.(map[string]any)["params"].(map[string]any)
		if params["url"] != link || params["mode"] != "url" {
			t.Fatalf("input request = %v, want the same link %s", ir, link)
		}
	}
	// Modern without it: a tool error with the link, never -32042.
	_, _, mo = rawModern(t, e.app, "support", e.blairMCP, "tools/call", map[string]any{"name": secretsRPC, "arguments": map[string]any{}}, nil, nil)
	text, isErr := toolText(t, mo)
	if !isErr || !strings.Contains(text, link) || mo["error"] != nil {
		t.Fatalf("modern without elicitation = %v", mo)
	}
	if e.kf.Requests() != before {
		t.Fatal("a call without a key reached the server")
	}
	// The link: only Blair's, names the server, team and address; used up by entering the key.
	var sr apitypes.SecretRequest
	if code2, ec := e.member.call("GET", "/v1/connect/secret-requests/"+secretRequestID(link), nil, &sr, nil); code2 != 200 {
		t.Fatalf("get request = %d %s", code2, ec)
	}
	if sr.Server.Name != "KEYED" || sr.Server.TeamName == "" || sr.Origin != e.origin() || sr.Reason != "secret_missing" ||
		sr.Config.Placement != "header" || sr.Secret.HasSecret || sr.Capability.ExposedName != secretsRPC {
		t.Fatalf("request = %+v", sr)
	}
	if code, _ := e.owner.raw("GET", "/v1/connect/secret-requests/"+secretRequestID(link), nil, nil); code != 404 {
		t.Fatalf("another person's link = %d, want 404", code)
	}
	e.putKey(e.member, blairKey, nil, 200)
	if code, _ := e.member.raw("GET", "/v1/connect/secret-requests/"+secretRequestID(link), nil, nil); code != 410 {
		t.Fatalf("a used link = %d, want 410", code)
	}
	code3, out3 := e.call(e.blairMCP, secretsRPC)
	if code3 != 200 {
		t.Fatalf("after entering the key: %v", out3)
	}
	e.sentOK(out3, blairKey)
}

// secretRequestID is the ID at the end of a link.
func secretRequestID(link string) string { return link[strings.LastIndex(link, "/")+1:] }

func TestPersonSecretRejectedKeyIsNotSentAgain(t *testing.T) {
	e := newSecEnv(t)
	e.kf.RequireHeader("X-Api-Key", ownerKey) // only the owner's key is good
	e.putKey(e.member, blairKey, nil, 200)
	before := e.kf.Requests()
	code, out := e.call(e.blairMCP, secretsRPC)
	if c, _, data := rpcErr(out); code != 200 || c != -32042 || data["elicitations"] == nil {
		t.Fatalf("a refused key = %d %v", code, out)
	}
	if e.kf.Requests() != before+1 {
		t.Fatalf("the refused call made %d requests, want exactly one (no retry)", e.kf.Requests()-before)
	}
	e.lastCall("needs_authorization secret_rejected")
	if m := e.mine(e.member); m.Status == nil || *m.Status != "rejected" || m.RejectedAt == nil {
		t.Fatalf("entry = %+v", m)
	}
	// The next call asks without sending anything.
	before = e.kf.Requests()
	if _, out := e.call(e.blairMCP, secretsRPC); out["error"] == nil {
		t.Fatalf("a rejected key was used: %v", out)
	}
	if e.kf.Requests() != before {
		t.Fatal("a rejected key was sent again")
	}
	// Entering it again (the good one) works; another person's key is theirs alone.
	e.putKey(e.member, ownerKey, nil, 200)
	c, out := e.call(e.blairMCP, secretsRPC)
	if c != 200 {
		t.Fatalf("after entering again: %v", out)
	}
	e.sentOK(out, ownerKey)
	if m := e.mine(e.owner); m.Status == nil || *m.Status != "active" {
		t.Fatalf("the owner's key: %+v", m)
	}
	// Entering a key is audited by what it was, never its value.
	for action, want := range map[string]string{"person_secret.create": "2", "person_secret.rotate": "1"} {
		if got := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = $1`, action); got != want {
			t.Errorf("%s audited %s times, want %s", action, got, want)
		}
	}
}

// A 403 from the server marks the key rejected too.
func TestPersonSecretForbiddenMarksRejected(t *testing.T) {
	e := newSecEnv(t)
	e.patchServer(e.owner, e.srv, map[string]any{"personSecret": secretConfig("bearer", "", "")})
	e.putKey(e.member, blairKey, nil, 200)
	e.kf.RejectAuthorization(403) // any request with an Authorization header
	_, out := e.call(e.blairMCP, secretsRPC)
	if c, _, _ := rpcErr(out); c != -32042 {
		t.Fatalf("answer = %v", out)
	}
	if m := e.mine(e.member); *m.Status != "rejected" {
		t.Fatalf("entry = %+v", m)
	}
}

func TestPersonSecretOriginBinding(t *testing.T) {
	e := newSecEnv(t)
	e.putKey(e.member, blairKey, nil, 200)
	// A path-only edit keeps every key.
	e.patchServer(e.owner, e.srv, map[string]any{"url": strings.TrimSuffix(e.kf.URL(), "/mcp") + "/mcp/"})
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets`); n != "2" {
		t.Fatalf("a path edit left %s keys, want 2", n)
	}
	// A key is used only at the origin it was entered for, even if a row
	// somehow says another (checked on every call).
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE person_secrets SET origin = 'https://elsewhere.example.com'`); err != nil {
		t.Fatal(err)
	}
	before := e.kf.Requests()
	if _, out := e.call(e.blairMCP, secretsRPC); out["error"] == nil {
		t.Fatalf("a key for another origin was used: %v", out)
	}
	if e.kf.Requests() != before {
		t.Fatal("a key for another origin was sent")
	}
	e.lastCall("needs_authorization secret_missing")
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE person_secrets SET origin = $1`, e.origin()); err != nil {
		t.Fatal(err)
	}
	// The entry page names the origin it was shown; another one is refused.
	code, raw := e.member.raw("PUT", "/v1/me/server-secrets/"+e.srv.Id.String(), map[string]any{"origin": "https://elsewhere.example.com", "value": blairKey}, nil)
	if code != 409 || errorCode(raw) != "server_changed" {
		t.Fatalf("a stale origin = %d %s", code, raw)
	}

	// A new origin deletes everyone's keys (and the setup person), audited with a count.
	other := testutil.NewFakeMCP(t)
	other.EnableGatewayTools()
	e.patchServer(e.owner, e.srv, map[string]any{"url": other.URL()})
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets`); n != "0" {
		t.Fatalf("a new origin left %s keys", n)
	}
	if e.scalar(`SELECT (secret_setup_user_id IS NULL)::text FROM mcp_servers WHERE id = $1`, e.srv.Id) != "true" {
		t.Error("the setup person survived a new origin")
	}
	meta := e.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'mcp_server.person_secrets_reset' ORDER BY id DESC LIMIT 1`)
	if !strings.Contains(meta, `"secretsDeleted": 2`) || !strings.Contains(meta, "origin_changed") || !strings.Contains(meta, "oldOrigin") {
		t.Fatalf("audit = %s", meta)
	}
	if got := e.scalar(`SELECT count(*)::text FROM person_secrets`); got != "0" {
		t.Fatal(got)
	}
}

func TestPersonSecretModeAndPlacementChangesResetKeys(t *testing.T) {
	e := newSecEnv(t)
	e.putKey(e.member, blairKey, nil, 200)
	// A new prefix, label and help keep the keys; a new placement does not.
	e.patchServer(e.owner, e.srv, map[string]any{"personSecret": secretConfig("header", "X-Api-Key", "Key ")})
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets`); n != "2" {
		t.Fatalf("a new prefix left %s keys", n)
	}
	e.patchServer(e.owner, e.srv, map[string]any{"personSecret": secretConfig("query", "k", "")})
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets`); n != "0" {
		t.Fatalf("a new placement left %s keys", n)
	}
	e.putKey(e.member, blairKey, nil, 200)
	e.patchServer(e.owner, e.srv, map[string]any{"authMode": "none"})
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets`); n != "0" {
		t.Fatalf("leaving the mode left %s keys", n)
	}
	var sv apitypes.McpServer
	e.owner.get(e.path(), &sv)
	if sv.PersonSecret != nil || *sv.AuthMode != "none" {
		t.Fatalf("server = %+v", sv)
	}
	if e.scalar(`SELECT (secret_placement IS NULL AND secret_name IS NULL)::text FROM mcp_servers WHERE id = $1`, e.srv.Id) != "true" {
		t.Error("the settings stayed after leaving the mode")
	}
}

func TestPersonSecretValidation(t *testing.T) {
	e := newSecEnv(t)
	create := func(extra map[string]any) (int, []byte) {
		body := map[string]any{"slug": "other-keyed", "name": "Other", "url": e.kf.URL()}
		for k, v := range extra {
			body[k] = v
		}
		return e.owner.raw("POST", toolsTeam+"/mcp-servers", body, nil)
	}
	for name, tc := range map[string]struct {
		extra map[string]any
		code  string
	}{
		"no settings":         {map[string]any{"authMode": "person_secret"}, "invalid_person_secret"},
		"unknown placement":   {map[string]any{"authMode": "person_secret", "personSecret": map[string]any{"placement": "cookie", "name": "x"}}, "invalid_person_secret"},
		"bearer with a name":  {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("bearer", "X-Key", "")}, "invalid_person_secret"},
		"bearer with prefix":  {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("bearer", "", "Key ")}, "invalid_person_secret"},
		"header without name": {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("header", "", "")}, "invalid_person_secret"},
		"reserved header":     {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("header", "Cookie", "")}, "invalid_person_secret"},
		"mcp- query name":     {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("query", "mcp-key", "")}, "invalid_person_secret"},
		"newline in prefix":   {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("header", "X-K", "a\nb")}, "invalid_person_secret"},
		"static Authorization with bearer": {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("bearer", "", ""),
			"authHeaderName": "Authorization", "authValue": "static-value-12345"}, "auth_conflict"},
		"static header with the same name": {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("header", "X-Api-Key", ""),
			"authHeaderName": "x-api-key", "authValue": "static-value-12345"}, "auth_conflict"},
		"static query with the same name": {map[string]any{"authMode": "person_secret", "personSecret": secretConfig("query", "k", ""),
			"credentials": []any{map[string]any{"kind": "query", "name": "K", "value": "static-value-12345"}}}, "auth_conflict"},
	} {
		if code, raw := create(tc.extra); code < 400 || code >= 500 || errorCode(raw) != tc.code {
			t.Errorf("%s: %d %s, want %s", name, code, raw, tc.code)
		}
	}
	// A static part that doesn't clash may stay next to the person's key.
	if code, raw := create(map[string]any{"authMode": "person_secret", "personSecret": secretConfig("bearer", "", ""),
		"credentials": []any{map[string]any{"kind": "header", "name": "X-Tenant", "value": "tenant-value-1"}}}); code != 201 {
		t.Errorf("a static header next to a bearer key: %d %s", code, raw)
	}
	// The mode excludes a requirement.
	p := (&provEnv{gwEnv: e.gwEnv}).createProvider("github", testutil.NewFakeOAuth(t), nil)
	if code, raw := e.owner.raw("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "third", "name": "Third", "url": e.kf.URL(), "authMode": "person_secret",
		"personSecret": secretConfig("header", "X-K", ""), "requirement": map[string]any{"providerId": p.Id, "scopes": []string{"repo"}}}, nil); code != 422 || errorCode(raw) != "auth_conflict" {
		t.Errorf("a requirement: %d %s", code, raw)
	}
	// Entering a key. (The owner already has one, so a change with no value is fine.)
	for name, tc := range map[string]struct {
		body map[string]any
		code int
	}{
		"no origin": {map[string]any{"value": "a-valid-key-0123"}, 400},
		"too short": {map[string]any{"origin": e.origin(), "value": "short"}, 400},
		"two lines": {map[string]any{"origin": e.origin(), "value": "line-one-0123\nline-two-4567"}, 400},
	} {
		if code, raw := e.owner.raw("PUT", "/v1/me/server-secrets/"+e.srv.Id.String(), tc.body, nil); code != tc.code {
			t.Errorf("%s: %d %s, want %d", name, code, raw, tc.code)
		}
	}
	// A person with no way to use the server can't enter a key for it, and can't tell it exists.
	casey := e.outsider
	code, raw := casey.raw("PUT", "/v1/me/server-secrets/"+e.srv.Id.String(), map[string]any{"origin": e.origin(), "value": "a-valid-key-0123"}, nil)
	if code != 404 || errorCode(raw) != "server_not_found" {
		t.Errorf("an outsider = %d %s", code, raw)
	}
	if code, raw := casey.raw("DELETE", "/v1/me/server-secrets/"+e.srv.Id.String(), nil, nil); code != 404 {
		t.Errorf("an outsider's revoke = %d %s", code, raw)
	}
}

func TestPersonSecretServiceAccountIsRefused(t *testing.T) {
	e := newSecEnv(t)
	sa := createSA(t, e.owner, map[string]any{"name": "robot", "role": "editor"})
	key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "k", "expiresInDays": 30}).Secret
	before := e.kf.Requests()
	code, _, out := rawMCP(t, e.app, "POST", "support", key, rpc(1, "tools/call", map[string]any{"name": secretsRPC, "arguments": map[string]any{}}), nil)
	c, _, data := rpcErr(out)
	if code != 200 || c != -32010 || data["reason"] != "service_account" {
		t.Fatalf("service account = %d %v", code, out)
	}
	if e.kf.Requests() != before {
		t.Fatal("a service account's call reached the server")
	}
	e.lastCall("denied service_account")
}

func TestPersonSecretSuspensionBlocksAndKeepsTheKey(t *testing.T) {
	e := newSecEnv(t)
	e.putKey(e.member, blairKey, nil, 200)
	id := e.userID("blair@localhost")
	setStatus := func(status string) {
		var u apitypes.UserDetail
		e.admin.get("/v1/admin/users/"+id, &u)
		code, ec := e.admin.call("PATCH", "/v1/admin/users/"+id, map[string]any{"status": status}, nil, ifMatch(u.User.Revision))
		mustCode(t, status, code, ec, 200, "")
	}
	setStatus("suspended")
	before := e.kf.Requests()
	if code, _ := e.call(e.blairMCP, secretsRPC); code != 401 {
		t.Fatalf("a suspended person's call = %d, want 401", code)
	}
	if e.kf.Requests() != before {
		t.Fatal("a suspended person's key was sent")
	}
	// Suspension doesn't delete or disconnect it (decision 53).
	if n := e.scalar(`SELECT count(*)::text FROM person_secrets WHERE user_id = $1`, id); n != "1" {
		t.Fatalf("suspension left %s keys, want 1", n)
	}
	setStatus("active")
	e.member = e.app.signIn("blair") // suspending ended the session
	c, out := e.call(e.blairMCP, secretsRPC)
	if c != 200 {
		t.Fatalf("after reactivation: %v", out)
	}
	e.sentOK(out, blairKey)
	// Deleting a person (cascade) and an admin's revoke both end it.
	if code, raw := e.auditor.raw("DELETE", "/v1/admin/users/"+id+"/server-secrets/"+e.srv.Id.String(), nil, nil); code != 403 {
		t.Fatalf("an auditor's revoke = %d %s", code, raw)
	}
	var list []apitypes.ServerSecret
	if code := e.auditor.get("/v1/admin/users/"+id+"/server-secrets", &list); code != 200 || len(list) != 1 || !list[0].HasSecret {
		t.Fatalf("admin list = %d %+v", code, list)
	}
	if code, raw := e.admin.raw("DELETE", "/v1/admin/users/"+id+"/server-secrets/"+e.srv.Id.String(), nil, nil); code != 200 {
		t.Fatalf("admin revoke = %d %s", code, raw)
	}
	if _, out := e.call(e.blairMCP, secretsRPC); out["error"] == nil {
		t.Fatalf("a revoked key was used: %v", out)
	}
	meta := e.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'person_secret.revoke' ORDER BY id DESC LIMIT 1`)
	if !strings.Contains(meta, `"reason": "admin"`) || !strings.Contains(meta, "blair") {
		t.Fatalf("audit = %s", meta)
	}
	// People revoke their own.
	e.putKey(e.member, blairKey, nil, 200)
	if code, raw := e.member.raw("DELETE", "/v1/me/server-secrets/"+e.srv.Id.String(), nil, nil); code != 200 {
		t.Fatalf("revoke = %d %s", code, raw)
	}
	if code, _ := e.member.raw("DELETE", "/v1/me/server-secrets/"+e.srv.Id.String(), nil, nil); code != 404 {
		t.Fatalf("a second revoke = %d, want 404", code)
	}
}

func TestPersonSecretRelayedCalls(t *testing.T) {
	e := newSecEnv(t)
	fx := setupRelay(t, e.gwEnv)
	before := e.kf.Requests()
	agent := agentSpec{Email: "blair@localhost"}

	// No key: a tool error naming where to enter it, no link, nothing stored, nothing sent.
	_, out := fx.callTool(agent, secretsRPC, nil)
	text, isErr := toolText(t, out)
	if !isErr || !strings.Contains(text, "My connections") || strings.Contains(text, "http") || out["error"] != nil {
		t.Fatalf("relayed, no key = %v", out)
	}
	if n := e.scalar(`SELECT count(*)::text FROM secret_requests`); n != "0" {
		t.Fatalf("an agent's call stored %s links", n)
	}
	rec := fx.recordAfter(0)
	if rec.Outcome != "needs_authorization" || rec.Class != "secret_missing" || rec.User == "" || rec.Agent == "" {
		t.Fatalf("record = %+v", rec)
	}
	// A key entered but agents not allowed: a different error, still no link.
	e.putKey(e.member, blairKey, nil, 200)
	_, out = fx.callTool(agent, secretsRPC, nil)
	text, isErr = toolText(t, out)
	if !isErr || !strings.Contains(text, "allowed agents") && !strings.Contains(text, "haven't allowed agents") || strings.Contains(text, "http") {
		t.Fatalf("relayed, agents not allowed = %v", out)
	}
	if e.kf.Requests() != before {
		t.Fatal("an agent's call used a key its person hadn't allowed agents to use")
	}
	// Allowed: the call carries Blair's key (and never the owner's, who has one too).
	body := string(e.putKey(e.member, "", map[string]any{"allowAgents": true}, 200))
	if !strings.Contains(body, `"allowAgents":true`) {
		t.Fatalf("entry = %s", body)
	}
	_, out = fx.callTool(agent, secretsRPC, nil)
	e.sentOK(out, blairKey)
	// The relay account without a person is a service account's call: refused.
	_, out = fx.callTool("", secretsRPC, nil)
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "service_account" {
		t.Fatalf("relay account alone = %v", out)
	}
	// Another person's agent has their own switch: the owner has a key but hasn't
	// allowed agents, and never gets Blair's.
	before = e.kf.Requests()
	_, out = fx.callTool(agentSpec{Email: "user@localhost"}, secretsRPC, nil)
	if text, isErr := toolText(t, out); !isErr || !strings.Contains(text, "allowed agents") || e.kf.Requests() != before {
		t.Fatalf("the owner's agent call = %v", out)
	}
	e.putKey(e.owner, "", map[string]any{"allowAgents": true}, 200)
	_, out = fx.callTool(agentSpec{Email: "user@localhost"}, secretsRPC, nil)
	e.sentOK(out, ownerKey)
	// Turning it off stops it at once, and the person's own calls are unaffected.
	e.putKey(e.member, "", map[string]any{"allowAgents": false}, 200)
	before = e.kf.Requests()
	if _, out = fx.callTool(agent, secretsRPC, nil); e.kf.Requests() != before {
		t.Fatalf("an agent used a key after the person turned it off: %v", out)
	}
	if c, out := e.call(e.blairMCP, secretsRPC); c != 200 {
		t.Fatalf("the person's own call = %v", out)
	} else {
		e.sentOK(out, blairKey)
	}
	fx.noSecrets(e.logs, blairKey, ownerKey)
}

func TestPersonSecretNeverLeaks(t *testing.T) {
	e := newSecEnv(t)
	// Query placement with a key full of characters that encode, the server's
	// error page repeating the request line, and capture on.
	e.patchServer(e.owner, e.srv, map[string]any{"personSecret": secretConfig("query", "api_key", "")})
	g := e.gateway(e.owner, toolsTeam+"/gateways/"+e.gw.Id.String())
	if code, ec := e.owner.call("PATCH", toolsTeam+"/gateways/"+e.gw.Id.String(), map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision)); code != 200 {
		t.Fatalf("capture: %d %s", code, ec)
	}
	e.putKey(e.owner, ownerKey, map[string]any{"useForSetup": true}, 200)
	e.putKey(e.member, querySecret, map[string]any{"allowAgents": true}, 200)
	sentinels := []string{ownerKey, querySecret, url.QueryEscape(querySecret), url.PathEscape(querySecret), "sentinel&0003", "sentinel%260003"}

	// A good call whose server echoes what it got, with the key in the arguments too.
	if code, _, out := rawMCP(t, e.app, "POST", "support", e.blairMCP, rpc(1, "tools/call", map[string]any{"name": secretsRPC,
		"arguments": map[string]any{"note": "my key is " + querySecret}}), nil); code != 200 {
		t.Fatalf("call = %d %v", code, out)
	} else {
		b, _ := json.Marshal(out)
		e.seen = append(e.seen, string(b))
	}
	// The server refuses it with a page that repeats the URL (the key in it).
	e.kf.RequireQuery("api_key", "something-else")
	_, out := e.call(e.blairMCP, secretsRPC)
	b, _ := json.Marshal(out)
	e.seen = append(e.seen, string(b))
	// A test and a refresh with the setup key, refused the same way: the stored
	// message must hold no key.
	_, raw := e.owner.raw("POST", e.path()+"/test", nil, nil)
	e.seen = append(e.seen, string(raw))
	_, raw = e.owner.raw("POST", e.path()+"/refresh", nil, nil)
	e.seen = append(e.seen, string(raw))
	for _, p := range []string{e.path(), toolsTeam + "/mcp-servers", "/v1/admin/mcp-servers", "/v1/me/server-secrets", toolsTeam + "/calls?limit=100",
		"/v1/admin/audit?limit=500", e.path() + "/health", "/v1/admin/users/" + e.userID("blair@localhost") + "/server-secrets"} {
		_, raw := e.admin.raw("GET", p, nil, nil)
		e.seen = append(e.seen, string(raw))
	}
	time.Sleep(200 * time.Millisecond) // calls are recorded after the answer
	dump := strings.Join(e.seen, " ") + e.logs.String() +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(p)::text, ' '), '') FROM mcp_call_payloads p`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(h)::text, ' '), '') FROM mcp_health_checks h`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(s)::text, ' '), '') FROM mcp_servers s`) +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(r)::text, ' '), '') FROM secret_requests r`) +
		e.scalar(`SELECT coalesce(string_agg(encode(secret_cipher, 'escape') || hint, ' '), '') FROM person_secrets`)
	for _, s := range sentinels {
		if strings.Contains(dump, s) {
			t.Errorf("the key leaked as %q", s)
		}
	}
	if !strings.Contains(dump, "[REDACTED]") && !strings.Contains(dump, "[redacted]") {
		t.Error("nothing was redacted, so the check proves little")
	}
	// The captured payload exists (it was recorded) and is redacted.
	if n := e.scalar(`SELECT count(*)::text FROM mcp_call_payloads`); n == "0" {
		t.Error("no payload was captured, so the check proves nothing")
	}
}

func TestPersonSecretTokenFieldRule(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	field := func(change map[string]any) string {
		code, _, body := e.bearer(pub.secret, patch(path, change).h(rev()))
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if code == 200 {
			return "ok"
		}
		if code != 403 || env.Error.Code != "token_not_allowed" {
			t.Errorf("%v: %d %s", change, code, body)
		}
		return env.Error.Details.Field
	}
	// Even a server with nothing to steal can't be switched to the mode by a token.
	if got := field(map[string]any{"authMode": "person_secret", "personSecret": secretConfig("header", "X-K", "")}); got != "authMode" {
		t.Errorf("switching to the mode: field %q", got)
	}
	e.run(`UPDATE mcp_servers SET auth_mode = 'person_secret', secret_placement = 'header', secret_name = 'X-K' WHERE id = $1`, srv)
	for want, change := range map[string]map[string]any{
		"personSecret": {"personSecret": secretConfig("query", "k", "")},
		"url":          {"url": "https://attacker.example.com/mcp"},
		"authMode":     {"authMode": "none"},
	} {
		if got := field(change); got != want {
			t.Errorf("%v: field %q, want %q", change, got, want)
		}
	}
	if got := field(map[string]any{"description": "fine"}); got != "ok" {
		t.Errorf("a harmless field: %q", got)
	}
}

// The tracing allow-list (decision 71) holds with a person's key on a call:
// no span name, attribute, status or resource carries it, a key refused by
// the server included, and no attribute outside the list appears.
func TestPersonSecretSpansCarryNoKey(t *testing.T) {
	sr := tracingOn(t)
	e := newSecEnv(t)
	e.putKey(e.member, blairKey, nil, 200)
	if c, out := e.call(e.blairMCP, secretsRPC); c != 200 {
		t.Fatalf("call = %v", out)
	}
	e.kf.RequireHeader("X-Api-Key", "another-key-0123")
	e.call(e.blairMCP, secretsRPC) // refused: the key is marked rejected
	e.call(e.blairMCP, secretsRPC) // asks again without sending
	allowed := map[string]bool{}
	for _, k := range observability.AllowedAttributeKeys() {
		allowed[k] = true
	}
	var sawSecretSpan bool
	for _, sp := range sr.Ended() {
		if sp.Name() == "mcp.person_secret" {
			sawSecretSpan = true
		}
		texts := []string{sp.Name(), sp.Status().Description}
		for _, a := range sp.Attributes() {
			if !allowed[string(a.Key)] {
				t.Errorf("%s carries the attribute %s", sp.Name(), a.Key)
			}
			texts = append(texts, a.Value.Emit())
		}
		if len(sp.Events()) != 0 || len(sp.Links()) != 0 {
			t.Errorf("%s has events or links", sp.Name())
		}
		for _, text := range texts {
			for _, bad := range []string{blairKey, ownerKey, "X-Api-Key", "another-key"} {
				if strings.Contains(text, bad) {
					t.Errorf("span %q: %q contains %q", sp.Name(), text, bad)
				}
			}
		}
	}
	if !sawSecretSpan {
		t.Error("no span for the person secret step")
	}
}
