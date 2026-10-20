package httpapi_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// A server that echoes a token it was given must not get it into anything the
// portal stores or logs (threat model DC-4). The fake's echo_tokens tool
// returns the platform provider token and the bearer token verbatim, with no
// "Bearer " in front and in a shape no built-in pattern rule matches (the
// fake OAuth provider's tokens are "fat_" plus random text), so only the
// exact-value rule (capture.NewRedactor's secrets) can remove them from a
// recorded payload.
//
// What the portal does with the live result the calling client receives:
//   - an oauth-mode server's own token is scrubbed from it ("[REDACTED]"),
//     because it is that person's credential for another system (mcpgw
//     request.scrub);
//   - a platform provider's token is relayed unchanged (only the recorded
//     copy is redacted). The calling client is the person it belongs to.
//
// Each test says which of these it asserts.

// leakSurfaces is everything the portal stored or logged in a test that a token
// must be absent from: audit rows, call rows, logs, both payload routes, both
// call lists, and every API body the test read.
func leakSurfaces(t *testing.T, e *gwEnv, logs *syncBuffer, responses []string, callID string) string {
	t.Helper()
	dump := e.scalar(`SELECT coalesce(string_agg(row_to_json(a)::text, ' '), '') FROM audit_log a`) + " " +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(c)::text, ' '), '') FROM mcp_calls c`) + " " +
		e.scalar(`SELECT coalesce(string_agg(row_to_json(h)::text, ' '), '') FROM mcp_health_checks h`) + " " +
		logs.String() + " " + strings.Join(responses, " ")
	for _, route := range []struct {
		s    *session
		path string
	}{
		{e.owner, toolsTeam + "/calls/" + callID + "/payload"},
		{e.owner, toolsTeam + "/calls/" + callID},
		{e.owner, toolsTeam + "/calls?limit=200"},
		{e.admin, "/v1/admin/calls/" + callID + "/payload"},
		{e.admin, "/v1/admin/calls?limit=200"},
		{e.admin, "/v1/admin/audit?limit=200"},
		{e.auditor, "/v1/admin/calls/" + callID + "/payload"},
		{e.owner, toolsTeam + "/audit?limit=200"},
	} {
		code, raw := route.s.raw("GET", route.path, nil, nil)
		if code != 200 {
			t.Fatalf("GET %s = %d %s", route.path, code, raw)
		}
		dump += " " + string(raw)
	}
	return dump
}

// waitForPayload returns the ID of the newest call with a stored payload.
func waitForPayload(t *testing.T, e *gwEnv, after string) string {
	t.Helper()
	for range 150 {
		if id := e.scalar(`SELECT coalesce(max(call_id)::text, '') FROM mcp_call_payloads`); id != "" && id != after {
			return id
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no payload was stored")
	return ""
}

func readPayload(t *testing.T, s *session, base, callID string) apitypes.CallPayload {
	t.Helper()
	var env struct{ Data apitypes.CallPayload }
	code, raw := s.raw("GET", base+callID+"/payload", nil, nil)
	if code != 200 {
		t.Fatalf("payload %s = %d %s", callID, code, raw)
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	return env.Data
}

func echoedText(t *testing.T, out map[string]any) string {
	t.Helper()
	res, _ := out["result"].(map[string]any)
	content, _ := res["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("no result: %v", out)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

// A platform provider's token (a person's GitHub account, say) forwarded to a
// server that echoes it back: it is not in the recorded payload (seen by the
// team owner and by platform staff), the call lists, the audit log, the call
// rows or the logs.
func TestEchoedProviderTokenIsRedactedEverywhere(t *testing.T) {
	e := newProvEnv(t)
	e.fake.EnableEchoSecrets()
	e.refresh(e.owner, e.server)
	gwPath := toolsTeam + "/gateways/" + e.gateway.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(e.capID(e.owner, e.server, "tool", "echo_tokens")))

	// Capture is on for the gateway; blair connects the provider.
	g := e.gwEnv.gateway(e.owner, gwPath)
	code, ec := e.owner.call("PATCH", gwPath, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision))
	mustCode(t, "gateway capture", code, ec, 200, "")
	// The first call answers with the consent link (per server, decision 60);
	// following it connects the account and allows this server to use it.
	link := e.consentURL(e.callTool(e.key, "status__echo_tokens"), "not_connected")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "connected") {
		t.Fatalf("connect = %s", to)
	}

	// The bodies read so far; the live answer below is the one place the token
	// is allowed to be, so it is kept out of the dump.
	read := slices.Clone(e.responses)
	out := e.callTool(e.key, "status__echo_tokens")
	text := echoedText(t, out)
	token := between(text, "provider_token=", " ")
	if !strings.HasPrefix(token, "fat_") || !slices.Contains(e.oauth.Issued(), token) {
		t.Fatalf("the fake did not receive the provider token: %q", text)
	}
	// Documented behaviour: the client that made the call gets the live
	// result unchanged for a platform provider's token (the token is its
	// own); change this assertion with the behaviour if that is extended.
	if live := text; !strings.Contains(live, token) {
		t.Errorf("the live result to the client was changed: %q", live)
	}

	callID := waitForPayload(t, e.gwEnv, "")
	for _, view := range []struct {
		name string
		s    *session
		base string
	}{
		{"team owner", e.owner, toolsTeam + "/calls/"},
		{"platform admin", e.admin, "/v1/admin/calls/"},
	} {
		p := readPayload(t, view.s, view.base, callID)
		if p.Result == nil || !strings.Contains(p.Result.Content, "provider_token=[REDACTED]") {
			t.Fatalf("%s: stored result = %+v", view.name, p.Result)
		}
		if strings.Contains(p.Result.Content+p.Arguments.Content, token) || p.Redactions < 1 {
			t.Errorf("%s: the provider token is in the payload: %s (redactions %d)", view.name, p.Result.Content, p.Redactions)
		}
	}

	dump := leakSurfaces(t, e.gwEnv, e.logs, read, callID)
	if strings.Contains(dump, token) {
		t.Errorf("the provider token reached a stored or logged place (%d chars)", len(token))
	}
	for _, issued := range append(e.oauth.Issued(), e.oauth.IssuedRefresh()...) {
		if issued != token && strings.Contains(dump, issued) {
			t.Errorf("another token of the provider leaked (%d chars)", len(issued))
		}
	}
	if strings.Contains(dump, e.oauth.ClientSecret) {
		t.Error("the provider's client secret leaked")
	}
}

// An oauth-mode server's own bearer token, echoed by that server: scrubbed
// from the live result, and absent from every stored or logged place, with the
// server's own capture switch on.
func TestEchoedUpstreamOAuthTokenIsRedactedEverywhere(t *testing.T) {
	e := newUpEnv(t, true)
	code, raw := e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "auto", "scopes": []string{"repo"}}, nil)
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	sv := created.Data.Server
	id := sv.Id.String()
	if _, to := e.setup(e.editor, id); !strings.Contains(to, "setup=connected") {
		t.Fatalf("setup = %s", to)
	}
	sv = e.get(e.editor, id)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "ghgw")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(e.capID(e.owner, sv, "tool", "echo_tokens")))
	// The server's capture switch (a team owner's), not the gateway's.
	code, ec, _ := e.patch(e.owner, id, map[string]any{"capturePayloads": true})
	mustCode(t, "server capture", code, ec, 200, "")
	blairKey := newKey(t, e.member, "laptop").Secret
	l := e.link(e.call(blairKey, "ghgw", "gh__echo_tokens", nil), sv.Oauth.ProviderSlug, "not_connected")
	if to := e.connectVia(e.member, sv.Oauth.ProviderId.String(), l); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}

	out := e.call(blairKey, "ghgw", "gh__echo_tokens", nil)
	text := echoedText(t, out)
	// The server did receive the person's token (as Authorization); the live
	// result has it scrubbed.
	token := strings.TrimPrefix(e.lastAuthorization("echo_tokens"), "Bearer ")
	if !strings.HasPrefix(token, "fat_") || !slices.Contains(e.as.Issued(), token) {
		t.Fatalf("the server did not receive the person's token: %q", e.lastAuthorization("echo_tokens"))
	}
	if strings.Contains(text, token) || !strings.Contains(text, "oauth_token=[REDACTED]") {
		t.Errorf("the oauth token reached the client in the live result: %q", text)
	}

	callID := waitForPayload(t, e.gwEnv, "")
	for _, view := range []struct {
		name string
		s    *session
		base string
	}{
		{"team owner", e.owner, toolsTeam + "/calls/"},
		{"platform admin", e.admin, "/v1/admin/calls/"},
	} {
		p := readPayload(t, view.s, view.base, callID)
		if p.Result == nil || !strings.Contains(p.Result.Content, "oauth_token=[REDACTED]") || strings.Contains(p.Result.Content, token) {
			t.Fatalf("%s: stored result = %+v", view.name, p.Result)
		}
	}
	dump := leakSurfaces(t, e.gwEnv, e.logs, e.responses, callID)
	if strings.Contains(dump, token) {
		t.Errorf("the oauth token reached a stored or logged place (%d chars)", len(token))
	}
	for _, issued := range append(e.as.Issued(), e.as.IssuedRefresh()...) {
		if strings.Contains(dump, issued) {
			t.Errorf("a token of the authorization server leaked (%d chars)", len(issued))
		}
	}
}
