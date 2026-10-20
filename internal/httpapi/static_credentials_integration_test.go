package httpapi_test

import (
	"context"
	"encoding/base64"
	"log/slog"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// A server's own credential as parts (roadmap #23, decision 70): header,
// bearer, basic and query values, sealed per part, sent on every request to
// the server (discovery, test, health, forwarded calls), kept out of every
// response, log, audit entry and captured payload, and never carried to
// another origin (F-1).

const (
	partTenant = "tenant-sentinel-0001"
	partQuery  = "q sentinel&0002/+"
	partUser   = "alice-sentinel"
	partPass   = "pa:ss-sentinel-0003"
)

func partsBasicHeader() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(partUser+":"+partPass))
}

// partsSentinels are every form of the three secrets a leak could take.
func partsSentinels() []string {
	b64 := base64.StdEncoding.EncodeToString([]byte(partUser + ":" + partPass))
	return []string{partTenant, partQuery, url.QueryEscape(partQuery), strings.ReplaceAll(url.QueryEscape(partQuery), "+", "%20"),
		url.PathEscape(partQuery), partPass, b64, "sentinel&0002", "sentinel%260002", "sentinel+0002"}
}

func (e *partsEnv) assertNoSentinel(what, text string) {
	e.t.Helper()
	for _, s := range partsSentinels() {
		if strings.Contains(text, s) {
			e.t.Errorf("%s contains %q", what, s)
		}
	}
}

type partsEnv struct {
	*rtEnv
	logs *syncBuffer
	reg  *registry.Service
	// seen collects every response body the test made.
	seen []string
}

func newPartsEnv(t *testing.T) *partsEnv {
	t.Helper()
	logs := &syncBuffer{}
	log := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	var reg *registry.Service
	e := &partsEnv{logs: logs}
	e.rtEnv = newRuntimeEnvHook(t, log, func(d *httpapi.Deps) { reg = d.Registry })
	e.reg = reg
	e.fake.EnableEchoSecrets()
	return e
}

func (e *partsEnv) credentials(list ...map[string]any) map[string]any {
	items := make([]any, len(list))
	for i, c := range list {
		items[i] = c
	}
	return map[string]any{"credentials": items}
}

func (e *partsEnv) path() string { return toolsTeam + "/mcp-servers/" + e.server.Id.String() }

func (e *partsEnv) get(s *session) apitypes.McpServer {
	e.t.Helper()
	var sv apitypes.McpServer
	if code := s.get(e.path(), &sv); code != 200 {
		e.t.Fatalf("get = %d", code)
	}
	return sv
}

func (e *partsEnv) patch(s *session, body map[string]any) (int, []byte) {
	e.t.Helper()
	code, raw := s.raw("PATCH", e.path(), body, ifMatch(e.get(s).Revision))
	e.seen = append(e.seen, string(raw))
	return code, raw
}

// sentSince are the HTTP requests the fake got after the first n.
func sentSince(f *testutil.FakeMCP, n int) []testutil.HTTPRequest { return f.HTTPRequests()[n:] }

// wantParts checks that every request carries all three secrets as they
// should arrive: the header, the Basic Authorization and the query key.
func (e *partsEnv) wantParts(what string, reqs []testutil.HTTPRequest) {
	e.t.Helper()
	if len(reqs) == 0 {
		e.t.Fatalf("%s: no request reached the server", what)
	}
	for _, r := range reqs {
		q, _ := url.ParseQuery(r.RawQuery)
		if r.Header.Get("X-Tenant") != partTenant || r.Header.Get("Authorization") != partsBasicHeader() || q.Get("sig") != partQuery {
			e.t.Errorf("%s: a request lacks a part: %s?%s %v", what, r.Path, r.RawQuery, r.Header)
		}
	}
}

func TestStaticCredentialPartsAreSentEverywhere(t *testing.T) {
	e := newPartsEnv(t)
	ctx := context.Background()
	e.fake.RequireHeader("X-Tenant", partTenant)
	e.fake.RequireQuery("sig", partQuery)

	// Without the parts the server refuses everything.
	if code, raw := e.refreshRaw(e.owner); code == 200 {
		t.Fatalf("refresh without credentials = %d %s", code, raw)
	}

	before := len(e.fake.HTTPRequests())
	code, raw := e.patch(e.owner, e.credentials(
		map[string]any{"kind": "header", "name": "X-Tenant", "value": partTenant},
		map[string]any{"kind": "query", "name": "sig", "value": partQuery},
		map[string]any{"kind": "basic", "value": partUser, "secondary": partPass},
	))
	if code != 200 {
		t.Fatalf("set the parts = %d %s", code, raw)
	}
	sv := e.get(e.owner)
	if !sv.HasAuth || sv.AuthHeaderName != nil || sv.AuthValueHint != "" || sv.Credentials == nil || len(*sv.Credentials) != 3 ||
		sv.AuthMode == nil || *sv.AuthMode != "static_header" {
		t.Fatalf("server = %+v", sv)
	}
	got := *sv.Credentials
	if got[0].Kind != "header" || *got[0].Name != "X-Tenant" || got[0].Hint != "0001" || got[1].Kind != "query" || *got[1].Name != "sig" ||
		got[2].Kind != "basic" || got[2].Name != nil || got[2].Hint != "0003" {
		t.Fatalf("credentials = %+v", got)
	}
	// The row keeps nothing of the legacy columns and the values are sealed.
	if e.scalar(`SELECT (auth_header_name IS NULL AND auth_value_cipher IS NULL)::text FROM mcp_servers WHERE id = $1`, e.server.Id) != "true" {
		t.Error("the legacy columns were kept next to the parts")
	}
	if dump := e.scalar(`SELECT string_agg(encode(value_cipher, 'escape') || encode(secondary_cipher, 'escape') || coalesce(name, '') || hint, '|')
		FROM mcp_server_credentials`); strings.Contains(dump, partTenant) || strings.Contains(dump, partPass) || strings.Contains(dump, "sentinel") {
		t.Errorf("a value is stored in the clear: %q", dump)
	}

	// Setting them forgot the stored health and read the capabilities again
	// only when asked: discovery, the manual test and the scheduled check all
	// send every part.
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	e.wantParts("refresh", sentSince(e.fake, before))
	before = len(e.fake.HTTPRequests())
	code, raw = e.owner.raw("POST", e.path()+"/test", nil, nil)
	e.seen = append(e.seen, string(raw))
	if code != 200 || !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("test = %d %s", code, raw)
	}
	e.wantParts("test", sentSince(e.fake, before))
	before = len(e.fake.HTTPRequests())
	if _, err := e.app.Pool.Exec(ctx, `DELETE FROM mcp_health_checks`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reg.RunHealthChecks(ctx, time.Minute); err != nil {
		t.Fatal(err)
	}
	if s := e.get(e.owner); s.Health.Status != "healthy" {
		t.Fatalf("health = %+v", s.Health)
	}
	e.wantParts("health check", sentSince(e.fake, before))

	// A forwarded call, with the payload captured, and the client's identity
	// token moved out of Authorization (the Basic part has it).
	ids := []string{e.capID(e.owner, e.server, "tool", "echo_secrets")}
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(ids...))
	g := e.gateway(e.owner, e.supportTeamPath)
	if code, ec := e.owner.call("PATCH", e.supportTeamPath, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision)); code != 200 {
		t.Fatalf("capture: %d %s", code, ec)
	}
	before = len(e.fake.HTTPRequests())
	code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", map[string]any{"name": "status__echo_secrets",
		"arguments": map[string]any{"note": "pasted " + partQuery + " and " + partTenant}}), nil)
	if code != 200 {
		t.Fatalf("call = %d %v", code, out)
	}
	e.wantParts("forwarded call", sentSince(e.fake, before))
	calls := e.fake.ToolCalls()
	last := calls[len(calls)-1]
	if last.Tool != "echo_secrets" || last.Authorization != partsBasicHeader() || len(last.Identity) < 50 {
		t.Errorf("the call arrived as %+v: the identity token must be in MCP-Gateway-Identity and Basic in Authorization", last)
	}
	if !strings.Contains(resultTextOf(out), "sig=") {
		t.Fatalf("the fake didn't echo the query: %s", resultTextOf(out))
	}
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

	// The query value and the others are in no response, log or audit entry.
	e.assertNoSentinel("a response", strings.Join(e.seen, "\n"))
	e.assertNoSentinel("the logs", e.logs.String())
	e.assertNoSentinel("the audit log", e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`))
	e.assertNoSentinel("the stored errors", e.scalar(`SELECT coalesce(string_agg(coalesce(last_refresh_error, ''), '|'), '') || (SELECT coalesce(string_agg(message, '|'), '') FROM mcp_health_checks) FROM mcp_servers`))
	audit := e.scalar(`SELECT after_state::text FROM audit_log WHERE action = 'mcp_server.update' ORDER BY id DESC LIMIT 1`)
	if !strings.Contains(audit, `"credentials"`) || !strings.Contains(audit, "X-Tenant") || !strings.Contains(audit, "sig") {
		t.Errorf("the audit entry doesn't name the parts: %s", audit)
	}

	// Parts that don't work: the server's error page repeats the request
	// line, query and all. None of it reaches the stored error, the health
	// message, the refresh response or the logs.
	code, raw = e.patch(e.owner, e.credentials(
		map[string]any{"kind": "header", "name": "X-Tenant", "keep": true},
		map[string]any{"kind": "query", "name": "sig", "value": "wrong key & sentinel-9999"},
		map[string]any{"kind": "basic", "keep": true},
	))
	if code != 200 {
		t.Fatalf("change one part = %d %s", code, raw)
	}
	wrongs := []string{"wrong key & sentinel-9999", "wrong+key+%26+sentinel-9999", "wrong%20key%20%26%20sentinel-9999", "sentinel-9999"}
	code, raw = e.refreshRaw(e.owner)
	if code == 200 {
		t.Fatalf("refresh with a wrong key = %d %s", code, raw)
	}
	e.seen = append(e.seen, string(raw))
	code, raw = e.owner.raw("POST", e.path()+"/test", nil, nil)
	e.seen = append(e.seen, string(raw))
	stored := e.scalar(`SELECT coalesce(last_refresh_error, '') FROM mcp_servers WHERE id = $1`, e.server.Id)
	if stored == "" {
		t.Errorf("no refresh error was stored")
	}
	all := strings.Join(e.seen, "\n") + e.logs.String() + stored
	for _, w := range wrongs {
		if strings.Contains(all, w) {
			t.Errorf("the wrong query value %q leaked: %s", w, all)
		}
	}
	e.assertNoSentinel("responses, logs and stored errors after the failure", all)

	// An encrypted value is bound to its row: two parts that swap their
	// ciphertext don't open.
	if _, err := e.app.Pool.Exec(ctx, `UPDATE mcp_server_credentials a SET value_cipher = b.value_cipher
		FROM mcp_server_credentials b WHERE a.kind = 'header' AND b.kind = 'query'`); err != nil {
		t.Fatal(err)
	}
	if code, raw := e.refreshRaw(e.owner); code == 200 || !strings.Contains(string(raw), "can't be decrypted") {
		t.Errorf("a swapped ciphertext opened: %d %s", code, raw)
	}
}

func (e *partsEnv) refreshRaw(s *session) (int, []byte) {
	e.t.Helper()
	code, raw := s.raw("POST", e.path()+"/refresh", nil, nil)
	e.seen = append(e.seen, string(raw))
	return code, raw
}

// The saved URL is still refused when it has a query; a credential's query
// part is the only way to send one.
func TestStaticCredentialQueryNeverInTheURL(t *testing.T) {
	e := newRegistryEnv(t)
	for _, u := range []string{e.fake.URL() + "?api_key=abc", e.fake.URL() + "?"} {
		code, raw := e.editor.raw("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "q", "name": "Q", "url": u}, nil)
		if code != 422 || errorCode(raw) != "url_not_allowed" || errorDetails(raw)["reason"] != "query" {
			t.Errorf("create with %q = %d %s", u, code, raw)
		}
	}
	id := e.create(map[string]any{"slug": "q", "name": "Q", "url": e.fake.URL(), "credentials": []any{
		map[string]any{"kind": "query", "name": "api_key", "value": "k-1234567890"}}}).Server.Id.String()
	code, ec, raw, _ := e.patchServer(e.editor, id, map[string]any{"url": e.fake.URL() + "?api_key=other"})
	if code != 422 || ec != "url_not_allowed" || errorDetails(raw)["reason"] != "query" {
		t.Fatalf("patch with a query = %d %s", code, raw)
	}
	if sv := e.server(e.editor, id); sv.Url != e.fake.URL() {
		t.Fatalf("url = %s", sv.Url)
	}
	reqs := e.fake.HTTPRequests()
	if len(reqs) == 0 || !strings.Contains(reqs[len(reqs)-1].RawQuery, "api_key=k-1234567890") {
		t.Fatalf("discovery did not send the query part: %+v", reqs)
	}
	// A part that clashes with what the gateway owns is refused.
	for name, c := range map[string]map[string]any{
		"mcp-prefixed": {"kind": "query", "name": "mcp-session", "value": "v"},
		"bad chars":    {"kind": "query", "name": "a b", "value": "v"},
	} {
		code, raw := e.editor.raw("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "r" + strings.ReplaceAll(name, " ", ""), "name": "R", "url": e.fake.URL(),
			"credentials": []any{c}}, nil)
		if code != 400 || errorCode(raw) != "invalid_auth_query" || errorDetails(raw)["field"] != "credentials[0]" {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}
}

// F-1 for every kind: moving a server to another origin never carries a stored
// value of any part; each part's value is entered again or the credential
// goes. Nothing is sent to the new host before that.
func TestStaticCredentialPartsDoNotFollowOriginChange(t *testing.T) {
	for _, kind := range []string{"header", "bearer", "basic", "query"} {
		t.Run(kind, func(t *testing.T) {
			e := newRegistryEnv(t)
			part := func(value, secondary string) map[string]any {
				p := map[string]any{"kind": kind, "value": value}
				switch kind {
				case "header":
					p["name"] = "X-Api-Key"
				case "query":
					p["name"] = "api_key"
				case "basic":
					p["secondary"] = secondary
				}
				return p
			}
			keep := func() map[string]any {
				p := map[string]any{"kind": kind, "keep": true}
				if name := part("", "")["name"]; name != nil {
					p["name"] = name
				}
				return p
			}
			other := map[string]any{"kind": "header", "name": "X-Tenant", "value": "tenant-123456"}
			id := e.create(map[string]any{"slug": "multi", "name": "Multi", "url": e.fake.URL(),
				"credentials": []any{part("first-1234567890", "pw-1234567890"), other}}).Server.Id.String()
			rows := func() string {
				return e.scalar(`SELECT coalesce(string_agg(encode(value_cipher, 'hex') || coalesce(encode(secondary_cipher, 'hex'), '') || id::text, ','
					ORDER BY position), '') FROM mcp_server_credentials WHERE server_id = $1`, id)
			}
			before, rowsBefore := e.server(e.editor, id), rows()
			if before.Credentials == nil || len(*before.Credentials) != 2 {
				t.Fatalf("credentials = %+v", before.Credentials)
			}
			evil := testutil.NewFakeMCP(t)
			note := func(code int, raw []byte, field string) {
				t.Helper()
				d := errorDetails(raw)
				if code != 422 || errorCode(raw) != "auth_value_required" || d["field"] != field || d["kind"] == nil {
					t.Fatalf("= %d %s", code, raw)
				}
				if strings.Contains(string(raw), "first-1234567890") || strings.Contains(string(raw), "pw-1234567890") {
					t.Fatalf("the error leaks a value: %s", raw)
				}
			}
			// The URL alone, and with every other field, and with the parts kept: refused, naming the first part
			// whose value isn't entered again.
			tenantKept := map[string]any{"kind": "header", "name": "X-Tenant", "keep": true}
			for _, c := range []struct {
				body  map[string]any
				field string
			}{
				{map[string]any{"url": evil.URL()}, "credentials[0]"},
				{map[string]any{"url": evil.URL(), "name": "Other", "enabled": true}, "credentials[0]"},
				{map[string]any{"url": evil.URL(), "authMode": "static_header"}, "credentials[0]"},
				{map[string]any{"url": evil.URL(), "credentials": []any{keep(), other}}, "credentials[0]"},
				{map[string]any{"url": evil.URL(), "credentials": []any{part("new-1234567890", "pw-new-12345"), tenantKept}}, "credentials[1]"},
			} {
				code, _, raw, _ := e.patchServer(e.editor, id, c.body)
				note(code, raw, c.field)
			}
			if evil.Requests() != 0 || rows() != rowsBefore {
				t.Fatalf("a refused update reached the new host (%d requests) or changed the parts", evil.Requests())
			}
			after := e.server(e.editor, id)
			if after.Url != before.Url || after.Revision != before.Revision {
				t.Fatalf("a refused update changed the server: %+v", after)
			}
			// A value without its password is no value; a part left empty is none.
			if kind == "basic" {
				code, _, raw, _ := e.patchServer(e.editor, id, map[string]any{"url": evil.URL(), "credentials": []any{
					map[string]any{"kind": "basic", "value": "u"}, other}})
				if code != 400 || errorCode(raw) != "invalid_auth_value" {
					t.Fatalf("basic without a password = %d %s", code, raw)
				}
			}
			// Every part entered again: the move works, the old values are gone, and the new host sees only the new ones.
			evil.RequireHeader("X-Tenant", "tenant-new-12345")
			code, _, raw, moved := e.patchServer(e.editor, id, map[string]any{"url": evil.URL(), "credentials": []any{
				part("new-1234567890", "pw-new-12345"), map[string]any{"kind": "header", "name": "X-Tenant", "value": "tenant-new-12345"}}})
			if code != 200 || moved.Url != evil.URL() || moved.RefreshedAt == nil || moved.LastRefreshError != nil || rows() == rowsBefore || evil.Requests() == 0 {
				t.Fatalf("move with new values = %d %s %+v", code, raw, moved)
			}
			for _, r := range evil.HTTPRequests() {
				if strings.Contains(r.RawQuery+r.Header.Get("X-Api-Key")+r.Header.Get("Authorization"), "first-1234567890") ||
					r.Header.Get("X-Tenant") != "tenant-new-12345" {
					t.Fatalf("the new host got %v %s", r.Header, r.RawQuery)
				}
			}
			if got := e.scalar(`SELECT metadata->>'authValueChanged' || ' ' || (metadata->>'oldOrigin') || ' ' || (metadata->>'newOrigin')
				FROM audit_log WHERE action = 'mcp_server.update' ORDER BY id DESC LIMIT 1`); got != "true "+originOfURL(e.fake.URL())+" "+originOfURL(evil.URL()) {
				t.Fatalf("audit metadata = %q", got)
			}
			// Removing the credential (an empty list) while moving is fine, and so is authMode none.
			plain := testutil.NewFakeMCP(t)
			code, _, raw, moved = e.patchServer(e.editor, id, map[string]any{"url": plain.URL(), "credentials": []any{}})
			if code != 200 || moved.HasAuth || moved.Credentials == nil || len(*moved.Credentials) != 0 || rows() != "" {
				t.Fatalf("move with the list emptied = %d %s", code, raw)
			}
			id2 := e.create(map[string]any{"slug": "multi2", "name": "Multi2", "url": e.fake.URL(), "credentials": []any{part("first-1234567890", "pw-1234567890")}}).Server.Id.String()
			code, _, raw, moved = e.patchServer(e.editor, id2, map[string]any{"url": plain.URL(), "authMode": "none"})
			if code != 200 || moved.HasAuth || e.scalar(`SELECT count(*)::text FROM mcp_server_credentials WHERE server_id = $1`, id2) != "0" {
				t.Fatalf("move with authMode none = %d %s", code, raw)
			}
			// A same-origin edit keeps the parts without sealing them again.
			id3 := e.create(map[string]any{"slug": "multi3", "name": "Multi3", "url": e.fake.URL(), "credentials": []any{part("first-1234567890", "pw-1234567890"), other}}).Server.Id.String()
			rows3 := e.scalar(`SELECT string_agg(encode(value_cipher, 'hex') || id::text, ',' ORDER BY position) FROM mcp_server_credentials WHERE server_id = $1`, id3)
			code, _, raw, got := e.patchServer(e.editor, id3, map[string]any{"url": e.fake.URL() + "/", "name": "Renamed"})
			if code != 200 || got.Credentials == nil || len(*got.Credentials) != 2 || got.RefreshedAt == nil ||
				e.scalar(`SELECT string_agg(encode(value_cipher, 'hex') || id::text, ',' ORDER BY position) FROM mcp_server_credentials WHERE server_id = $1`, id3) != rows3 {
				t.Fatalf("same-origin edit = %d %s", code, raw)
			}
			// Keeping both parts, in the order they have, writes nothing.
			cur := e.server(e.editor, id3)
			code, _, raw, got = e.patchServer(e.editor, id3, map[string]any{"credentials": []any{keep(), map[string]any{"kind": "header", "name": "X-Tenant", "keep": true}}})
			if code != 200 || got.Revision != cur.Revision {
				t.Fatalf("keeping the parts = %d %s (revision %d, was %d)", code, raw, got.Revision, cur.Revision)
			}
		})
	}
}

// The single static header of a server saved before this release keeps working
// as it did; saving its credential as a list moves it into the table (a part
// kept stays the same secret), and the old fields stop applying to a list.
func TestLegacyStaticHeaderBecomesAPart(t *testing.T) {
	e := newRegistryEnv(t)
	const secret = "legacy-1234567890"
	e.fake.RequireHeader("X-API-Key", secret)
	id := e.create(map[string]any{"slug": "old", "name": "Old", "url": e.fake.URL(), "authHeaderName": "X-API-Key", "authValue": secret}).Server.Id.String()
	sv := e.server(e.editor, id)
	if !sv.HasAuth || sv.AuthHeaderName == nil || *sv.AuthHeaderName != "X-API-Key" || sv.AuthValueHint != "7890" || sv.Credentials == nil ||
		len(*sv.Credentials) != 1 || (*sv.Credentials)[0].Kind != "header" || *(*sv.Credentials)[0].Name != "X-API-Key" || (*sv.Credentials)[0].Hint != "7890" {
		t.Fatalf("legacy server = %+v", sv)
	}
	if e.scalar(`SELECT count(*)::text FROM mcp_server_credentials`) != "0" {
		t.Fatal("a server saved with the single header wrote a part")
	}
	cipher := e.scalar(`SELECT encode(auth_value_cipher, 'hex') FROM mcp_servers WHERE id = $1`, id)
	digest := *sv.ReviewDigest

	// The editor's UI sends the list with the header kept: nothing is written.
	code, _, raw, same := e.patchServer(e.editor, id, map[string]any{"credentials": []any{map[string]any{"kind": "header", "name": "x-api-key", "keep": true}}})
	if code != 200 || same.Revision != sv.Revision || e.scalar(`SELECT encode(auth_value_cipher, 'hex') FROM mcp_servers WHERE id = $1`, id) != cipher ||
		e.scalar(`SELECT count(*)::text FROM mcp_server_credentials`) != "0" {
		t.Fatalf("keeping the legacy header = %d %s", code, raw)
	}
	// Both ways of naming a credential at once is an error; so is keeping what isn't stored.
	for name, body := range map[string]map[string]any{
		"both":      {"authHeaderName": "X-API-Key", "credentials": []any{}},
		"no header": {"credentials": []any{map[string]any{"kind": "header", "name": "X-Other", "keep": true}}},
		"no query":  {"credentials": []any{map[string]any{"kind": "query", "name": "api_key", "keep": true}}},
	} {
		if code, _, raw, _ := e.patchServer(e.editor, id, body); code != 400 {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}

	// Adding a query key keeps the header (opened and sealed again under its own row), moves both into the
	// table, clears the legacy columns and changes the review digest.
	e.fake.RequireQuery("api_key", "query-1234567890")
	code, _, raw, moved := e.patchServer(e.editor, id, map[string]any{"credentials": []any{
		map[string]any{"kind": "header", "name": "X-API-Key", "keep": true},
		map[string]any{"kind": "query", "name": "api_key", "value": "query-1234567890"}}})
	if code != 200 {
		t.Fatalf("add a query part = %d %s", code, raw)
	}
	if moved.AuthHeaderName != nil || !moved.HasAuth || moved.Credentials == nil || len(*moved.Credentials) != 2 || *moved.ReviewDigest == digest {
		t.Fatalf("moved = %+v", moved)
	}
	if e.scalar(`SELECT (auth_header_name IS NULL AND auth_value_cipher IS NULL AND auth_value_hint = '')::text FROM mcp_servers WHERE id = $1`, id) != "true" ||
		e.scalar(`SELECT count(*)::text FROM mcp_server_credentials WHERE server_id = $1`, id) != "2" {
		t.Fatal("the credential is not in the table alone")
	}
	var h apitypes.McpTestResult
	if code, ec := e.editor.call("POST", toolsTeam+"/mcp-servers/"+id+"/test", nil, &h, nil); code != 200 || !h.Ok {
		t.Fatalf("test after the move = %d %s %+v", code, ec, h)
	}
	reqs := e.fake.HTTPRequests()
	if last := reqs[len(reqs)-1]; last.Header.Get("X-API-Key") != secret || !strings.Contains(last.RawQuery, "api_key=query-1234567890") {
		t.Errorf("the moved header's value changed: %v %s", last.Header, last.RawQuery)
	}
	// The old fields no longer apply to a list.
	for _, body := range []map[string]any{{"authHeaderName": "X-API-Key"}, {"authValue": "x-1234567890"}, {"authHeaderName": ""}} {
		if code, ec, raw, _ := e.patchServer(e.editor, id, body); code != 422 || ec != "credentials_in_use" {
			t.Errorf("%v on a list = %d %s", body, code, raw)
		}
	}
	// A field that isn't the credential leaves the parts alone; an empty list removes them; one part may be dropped.
	rows := e.scalar(`SELECT string_agg(id::text || encode(value_cipher, 'hex'), ',' ORDER BY position) FROM mcp_server_credentials WHERE server_id = $1`, id)
	if code, _, raw, _ := e.patchServer(e.editor, id, map[string]any{"description": "still works"}); code != 200 ||
		e.scalar(`SELECT string_agg(id::text || encode(value_cipher, 'hex'), ',' ORDER BY position) FROM mcp_server_credentials WHERE server_id = $1`, id) != rows {
		t.Fatalf("description = %d %s", code, raw)
	}
	code, _, raw, dropped := e.patchServer(e.editor, id, map[string]any{"credentials": []any{map[string]any{"kind": "query", "name": "api_key", "keep": true}}})
	if code != 200 || dropped.Credentials == nil || len(*dropped.Credentials) != 1 || (*dropped.Credentials)[0].Kind != "query" || *dropped.ReviewDigest == *moved.ReviewDigest {
		t.Fatalf("drop a part = %d %s", code, raw)
	}
	code, _, raw, gone := e.patchServer(e.editor, id, map[string]any{"credentials": []any{}})
	if code != 200 || gone.HasAuth || gone.AuthMode == nil || *gone.AuthMode != "none" {
		t.Fatalf("empty list = %d %s (%+v)", code, raw, gone.AuthMode)
	}
	if code, _, raw, _ := e.patchServer(e.editor, id, map[string]any{"authMode": "static_header"}); code != 400 {
		t.Errorf("static_header without credentials = %d %s", code, raw)
	}
}

// Only one part may set Authorization, and not in oauth mode; Authorization
// parts move the identity token to MCP-Gateway-Identity.
func TestStaticCredentialAuthorizationRules(t *testing.T) {
	e := newRegistryEnv(t)
	for name, list := range map[string][]any{
		"header and bearer": {map[string]any{"kind": "header", "name": "Authorization", "value": "Token x"}, map[string]any{"kind": "bearer", "value": "t"}},
		"bearer and basic":  {map[string]any{"kind": "bearer", "value": "t"}, map[string]any{"kind": "basic", "value": "u", "secondary": "p"}},
	} {
		code, raw := e.editor.raw("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "auth-twice", "name": "A", "url": e.fake.URL(), "credentials": list}, nil)
		if code != 422 || errorCode(raw) != "auth_conflict" || errorDetails(raw)["reason"] != "authorization_twice" {
			t.Errorf("%s = %d %s", name, code, raw)
		}
	}
	// A bearer part is sent as Authorization: Bearer.
	id := e.create(map[string]any{"slug": "bearer", "name": "B", "url": e.fake.URL(), "credentials": []any{
		map[string]any{"kind": "bearer", "value": "bearer-1234567890"}, map[string]any{"kind": "query", "name": "k", "value": "v-1234567890"}}}).Server.Id.String()
	for _, a := range e.fake.RequestAuths() {
		if a.Authorization != "Bearer bearer-1234567890" {
			t.Errorf("Authorization = %q", a.Authorization)
		}
	}
	// Not in oauth mode: one credential per call (decision 39); other parts are fine.
	code, ec, raw, _ := e.patchServer(e.editor, id, map[string]any{"authMode": "oauth", "oauth": map[string]any{}})
	if code != 422 || ec != "auth_conflict" || errorDetails(raw)["reason"] != "static_authorization" {
		t.Errorf("oauth with a bearer part = %d %s", code, raw)
	}
	code, raw = e.editor.raw("POST", toolsTeam+"/mcp-servers", map[string]any{"slug": "oauth-basic", "name": "O", "url": e.fake.URL(), "authMode": "oauth",
		"oauth": map[string]any{}, "credentials": []any{map[string]any{"kind": "basic", "value": "u", "secondary": "p"}}}, nil)
	if code != 422 || errorCode(raw) != "auth_conflict" || errorDetails(raw)["reason"] != "static_authorization" {
		t.Errorf("create oauth with a basic part = %d %s", code, raw)
	}
}
