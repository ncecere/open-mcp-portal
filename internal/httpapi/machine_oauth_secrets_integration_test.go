package httpapi_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	promtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// F-1: the client secret goes to the token endpoint it was entered for. Another
// token endpoint, another client or a server URL with another origin needs it
// entered again, in the same request; until then nothing is stored and
// nothing is sent to the new place.
func TestMachineOAuthSecretDoesNotFollowEndpointClientOrOrigin(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	evilAS := testutil.NewFakeOAuth(t)
	evilMCP := testutil.NewFakeMCP(t)
	e.mustPatch(e.editor, map[string]any{}) // a request that changes nothing writes nothing
	cur := e.get(e.owner)
	stored := e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`)
	n := e.tokenRequests()

	refuse := func(what, reason string, body map[string]any) {
		t.Helper()
		code, raw := e.patch(e.editor, body)
		d := errorDetails(raw)
		if code != 422 || errorCode(raw) != "client_secret_required" || d["reason"] != reason || d["field"] != "machineOAuth.clientSecret" {
			t.Errorf("%s = %d %s", what, code, raw)
		}
	}
	refuse("another token endpoint", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token"}})
	refuse("another token path", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": e.as.URL + "/token/v2"}})
	refuse("another client", "client_id_changed", map[string]any{"machineOAuth": map[string]any{"clientId": "another-client"}})
	refuse("another origin of the server", "origin_changed", map[string]any{"url": evilMCP.URL()})
	refuse("another origin of the server with other fields", "origin_changed", map[string]any{"url": evilMCP.URL(), "name": "Renamed",
		"machineOAuth": map[string]any{"scopes": []string{"read"}}})
	// Switching the mode off and on again starts from nothing: the secret too.
	e.mustPatch(e.editor, map[string]any{"authMode": "none"})
	code, raw := e.patch(e.editor, map[string]any{"authMode": "machine_oauth"})
	if code != 400 || errorCode(raw) != "invalid_machine_oauth" {
		t.Errorf("back to the mode without a client = %d %s", code, raw)
	}
	e.mustPatch(e.editor, e.machine(nil))
	n = e.tokenRequests()
	cur = e.get(e.owner)
	stored = e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`)
	refuse("another token endpoint again", "token_url_changed", map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token"}})

	if evilAS.TokenRequests() != 0 || evilMCP.Requests() != 0 || len(evilMCP.HTTPRequests()) != 0 || e.tokenRequests() != n {
		t.Fatalf("a refused change reached the new place: token endpoint %d, server %d, own endpoint %d",
			evilAS.TokenRequests(), evilMCP.Requests(), e.tokenRequests()-n)
	}
	if got := e.scalar(`SELECT encode(client_secret_cipher, 'hex') || token_url || client_id FROM mcp_server_machine_oauth`); got != stored {
		t.Errorf("a refused change changed the stored client")
	}
	if now := e.get(e.owner); now.Revision != cur.Revision || now.Url != cur.Url {
		t.Errorf("a refused change changed the server: %+v", now)
	}

	// With the secret entered again the endpoint moves, and the new
	// endpoint (and only it) gets the secret and issues the token.
	evilAS.Set(func(f *testutil.FakeOAuth) { f.ClientSecret, f.ClientID = "second-secret-0123456789", "second-client" })
	e.protect(evilAS) // the server now trusts the new authorization server
	e.mustPatch(e.editor, map[string]any{"machineOAuth": map[string]any{"tokenUrl": evilAS.URL + "/token", "clientId": "second-client",
		"clientSecret": "second-secret-0123456789"}})
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh with the new client = %d %s", code, raw)
	}
	reqs := evilAS.ClientCredentialsRequests()
	if len(reqs) != 1 || reqs[0].ClientSecret != "second-secret-0123456789" || !reqs[0].Authorized || e.tokenRequests() != n {
		t.Fatalf("the new endpoint got %+v (the old one %d more)", reqs, e.tokenRequests()-n)
	}
	for _, a := range e.fake.RequestAuths()[len(e.fake.RequestAuths())-1:] {
		if a.Authorization != "Bearer "+evilAS.Issued()[0] {
			t.Errorf("the server was sent %q, not the new token", a.Authorization)
		}
	}
	// The old secret is gone: the audit entry says the endpoint and client changed.
	if got := e.scalar(`SELECT metadata::text FROM audit_log WHERE action = 'mcp_server.auth_update' ORDER BY id DESC LIMIT 1`); !strings.Contains(got, `"tokenUrlChanged": true`) ||
		!strings.Contains(got, `"clientIdChanged": true`) || !strings.Contains(got, `"clientSecretChanged": true`) {
		t.Errorf("audit metadata = %s", got)
	}

	// The same for the origin of the server's URL: with the secret entered
	// again the move works and the new host gets the new token only.
	evilMCP.Protect(testutil.Protection{Issuer: evilAS.Issuer(), Introspect: func(_ context.Context, tok string) testutil.Introspection { return evilAS.Introspect(tok) }})
	e.mustPatch(e.editor, map[string]any{"url": evilMCP.URL(), "machineOAuth": map[string]any{"clientSecret": "second-secret-0123456789",
		"resource": evilMCP.URL()}})
	moved := e.get(e.owner)
	if moved.Url != evilMCP.URL() || moved.RefreshedAt == nil || moved.LastRefreshError != nil {
		t.Fatalf("after the move: %+v", moved)
	}
	for _, a := range evilMCP.RequestAuths() {
		if !strings.HasPrefix(a.Authorization, "Bearer fmt_") || a.Authorization == "Bearer "+e.token(0) {
			t.Errorf("the new host was sent %q", a.Authorization)
		}
	}
	// A path-only change of the URL keeps the secret.
	e.mustPatch(e.editor, map[string]any{"url": evilMCP.URL() + "/"})
	e.assertNoSecrets("a response", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
}

// No token or credential of any kind reaches a response, log, audit entry,
// call record or captured payload, even from a server that echoes its
// credentials and from calls that fail.
func TestMachineOAuthSentinels(t *testing.T) {
	e := newMachineEnv(t)
	ctx := context.Background()
	e.mustPatch(e.editor, e.machine(nil))
	if code, raw := e.refreshRaw(e.owner); code != 200 {
		t.Fatalf("refresh = %d %s", code, raw)
	}
	e.approve()
	// Put the echoing tools (approved with the server) on the gateway and record
	// the contents of calls.
	e.mustSetCaps(e.owner, e.supportTeamPath, sel(e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "echo_secrets"),
		e.capID(e.owner, e.server, "tool", "echo_tokens")))
	g := e.gateway(e.owner, e.supportTeamPath)
	if code, ec := e.owner.call("PATCH", e.supportTeamPath, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision)); code != 200 {
		t.Fatalf("capture: %d %s", code, ec)
	}
	for _, tool := range []string{"status__echo_secrets", "status__echo_tokens"} {
		code, out := e.callTool(e.key.Secret, tool, map[string]any{"note": "a harmless note"})
		if code != 200 || out["error"] != nil {
			t.Fatalf("%s = %d %v", tool, code, out)
		}
		text := resultTextOf(out)
		if strings.Contains(text, e.token(0)) || strings.Contains(text, machineSecret) {
			t.Errorf("%s returned a credential to the client: %s", tool, text)
		}
	}
	// What the server echoed back, as the person saw it and as it was captured.
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
	e.assertNoSecrets("a response or payload", strings.Join(e.seen, "\n"))
	e.assertNoSecrets("the logs", e.logs.String())
	e.assertNoSecrets("the audit log", e.scalar(`SELECT coalesce(string_agg(coalesce(before_state::text, '') || coalesce(after_state::text, '') || coalesce(metadata::text, ''), E'\n'), '') FROM audit_log`))
	e.assertNoSecrets("the call records", e.scalar(`SELECT coalesce(string_agg(to_jsonb(c)::text, E'\n'), '') FROM mcp_calls c`))
	e.assertNoSecrets("the stored payloads", e.scalar(`SELECT coalesce(string_agg(encode(arguments_cipher, 'escape') || encode(result_cipher, 'escape'), E'\n'), '') FROM mcp_call_payloads`))
	_ = ctx
}

// The secret is bound to its server (AAD): a ciphertext moved to another row
// doesn't open, and a key that can't open it is a config error, not a leak.
func TestMachineOAuthSecretIsBoundToItsServer(t *testing.T) {
	e := newMachineEnv(t)
	e.mustPatch(e.editor, e.machine(nil))
	other := e.createServer(e.owner, "tools", "second", e.otherFake.URL(), nil)
	if _, err := e.app.Pool.Exec(context.Background(), `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher)
		SELECT $1, token_url, client_id, client_secret_cipher FROM mcp_server_machine_oauth`, other.Id); err != nil {
		t.Fatal(err)
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE id = $1`, other.Id); err != nil {
		t.Fatal(err)
	}
	code, raw := e.owner.raw("POST", toolsTeam+"/mcp-servers/"+other.Id.String()+"/test", nil, nil)
	if code != 200 || !strings.Contains(string(raw), "can't be decrypted") || strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("a ciphertext of another server opened: %d %s", code, raw)
	}
}

// The token request is observable without a token in it: omp_machine_token_requests_total
// counts requests (not cache hits) by result, and the span of a token request
// carries only the allowed attributes and a class, never a token, secret or URL.
func TestMachineOAuthMetricsAndSpans(t *testing.T) {
	e := newMachineEnv(t)
	sr := tracingOn(t)
	count := func(result string) float64 {
		return promtest.ToFloat64(observability.MachineTokenRequests.WithLabelValues(result))
	}
	ok0, refused0, down0 := count("ok"), count("refused"), count("unavailable")
	e.mustPatch(e.editor, e.machine(nil))
	e.approve()
	for range 3 {
		if code, out := e.callTool(e.key.Secret, "status__whoami", nil); code != 200 || out["error"] != nil {
			t.Fatalf("call = %d %v", code, out)
		}
	}
	if count("ok")-ok0 != 1 {
		t.Fatalf("ok token requests = %v, want 1 (the cache serves the rest)", count("ok")-ok0)
	}
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "invalid_client" })
	e.forget()
	e.callTool(e.key.Secret, "status__whoami", nil)
	e.as.Set(func(f *testutil.FakeOAuth) { f.FailClientCredentials = "unavailable" })
	e.forget()
	e.callTool(e.key.Secret, "status__whoami", nil)
	if count("refused")-refused0 != 1 || count("unavailable")-down0 != 1 {
		t.Fatalf("refused %v, unavailable %v", count("refused")-refused0, count("unavailable")-down0)
	}
	allowed := map[string]bool{}
	for _, k := range observability.AllowedAttributeKeys() {
		allowed[k] = true
	}
	var token []string
	for _, sp := range sr.Ended() {
		if sp.Name() != "upstream.machine_token" {
			continue
		}
		token = append(token, sp.Name())
		texts := []string{sp.Name(), sp.Status().Description}
		for _, a := range sp.Attributes() {
			if !allowed[string(a.Key)] {
				t.Errorf("the token span carries %s", a.Key)
			}
			texts = append(texts, a.Value.Emit())
		}
		for _, text := range texts {
			for _, bad := range append(e.sentinels(), "127.0.0.1", "/token", e.as.ClientID) {
				if strings.Contains(text, bad) {
					t.Errorf("a token span holds %q: %q", bad, text)
				}
			}
		}
	}
	if len(token) != 3 {
		t.Fatalf("%d token spans, want 3", len(token))
	}
}

// An automation token can't choose where a client secret goes: it may not
// create a server in machine_oauth mode, send machineOAuth or switch a server
// to it, even on a server without credentials (decision 58, decision 73).
func TestMachineOAuthIsSessionOnlyForTokens(t *testing.T) {
	e := newMatrixEnv(t)
	var pub tokenCred
	for _, c := range e.tokenCreds() {
		if c.name == "publisher-write" {
			pub = c
		}
	}
	machine := map[string]any{"tokenUrl": "https://idp.example.com/token", "clientId": "c", "clientSecret": "token-sentinel-secret"}
	field := func(body []byte) string {
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		if env.Error.Code != "token_not_allowed" {
			return env.Error.Code
		}
		return env.Error.Details.Field
	}
	create := func(extra map[string]any) (int, []byte) {
		b := map[string]any{"slug": "from-ci", "name": "From CI", "url": e.fakeURL}
		for k, v := range extra {
			b[k] = v
		}
		code, _, body := e.bearer(pub.secret, post("/v1/teams/bravo/mcp-servers", b))
		return code, body
	}
	for name, c := range map[string]struct {
		extra map[string]any
		field string
	}{
		"machineOAuth with the mode": {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"machineOAuth alone":         {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"the mode alone":             {map[string]any{"authMode": "machine_oauth"}, "authMode"},
	} {
		if code, body := create(c.extra); code != 403 || field(body) != c.field || strings.Contains(string(body), "token-sentinel-secret") {
			t.Errorf("create with %s = %d %s", name, code, body)
		}
	}
	if n := e.exec(`SELECT count(*)::text FROM mcp_servers WHERE slug = 'from-ci'`); n != "0" {
		t.Errorf("a refused create stored a server")
	}
	// Updates: on a server without credentials too.
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"machineOAuth":        {map[string]any{"machineOAuth": machine}, "machineOAuth"},
		"the mode":            {map[string]any{"authMode": "machine_oauth", "machineOAuth": machine}, "machineOAuth"},
		"the mode alone":      {map[string]any{"authMode": "machine_oauth"}, "authMode"},
		"a null machineOAuth": {map[string]any{"machineOAuth": nil}, "machineOAuth"},
	} {
		if code, _, body := e.bearer(pub.secret, patch(path, c.body).h(rev())); code != 403 || field(body) != c.field {
			t.Errorf("update with %s = %d %s", name, code, body)
		}
	}
	// A server already in the mode is protected as one with credentials: the
	// token can't re-point it, change its client or leave the mode.
	e.run(`UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE id = $1`, srv)
	e.run(`INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) VALUES ($1, 'https://idp.example.com/token', 'c', '\x00')`, srv)
	for name, c := range map[string]struct {
		body  map[string]any
		field string
	}{
		"the url":         {map[string]any{"url": "https://attacker.example.com/mcp"}, "url"},
		"the mode":        {map[string]any{"authMode": "none"}, "authMode"},
		"the client":      {map[string]any{"machineOAuth": map[string]any{"scopes": []string{"x"}}}, "machineOAuth"},
		"sendIdentity":    {map[string]any{"sendIdentity": false}, "sendIdentity"},
		"a static header": {map[string]any{"authHeaderName": "X-Key", "authValue": "x-1234567890"}, "authHeaderName"},
	} {
		if code, _, body := e.bearer(pub.secret, patch(path, c.body).h(rev())); code != 403 || field(body) != c.field {
			t.Errorf("update of a machine server: %s = %d %s", name, code, body)
		}
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "still fine"}).h(rev())); code != 200 {
		t.Errorf("a harmless field = %d %s", code, body)
	}
	if got := e.exec(`SELECT token_url || client_id FROM mcp_server_machine_oauth WHERE server_id = $1`, srv); got != "https://idp.example.com/tokenc" {
		t.Errorf("a token changed the client: %s", got)
	}
}
