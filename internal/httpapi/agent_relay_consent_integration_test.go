package httpapi_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// An agent has no browser (#57): a relayed call for a person never returns
// -32042, a consent link or an input request. A capability that needs a
// connection the person hasn't made is a tool error naming the provider and
// where to connect. Delegated credentials are the person's own.

const wantConnect = "Connect your Github account under Account › My connections in Open MCP Portal, then try again."

// noLink fails when an answer carries a consent link, -32042 or an input request.
func noLink(t *testing.T, out map[string]any, what string) {
	t.Helper()
	b, _ := json.Marshal(out)
	s := string(b)
	for _, bad := range []string{"/connect/", "-32042", "input_required", "elicitation", "requestState", "http://", "https://"} {
		if strings.Contains(s, bad) {
			t.Fatalf("%s: the answer holds %q: %s", what, bad, s)
		}
	}
	if out["error"] != nil && rpcErrorCode(out) == -32042 {
		t.Fatalf("%s: -32042: %s", what, s)
	}
}

func (e *provEnv) connectRequests() string {
	return e.scalar(`SELECT count(*)::text FROM provider_connect_requests`)
}

func TestRelayedCallNeverStartsConsent(t *testing.T) {
	e, fx := newAgentEnv(t)
	blair := agentSpec{Email: "blair@localhost"}
	const tool = "status__provider_token"

	// 1. Not connected: a tool error, no link, no stored consent request, and
	// the server is never contacted.
	id := fx.lastCallID()
	code, out := fx.callTool(blair, tool, nil)
	text, isErr := toolText(t, out)
	if code != 200 || !isErr || !strings.HasSuffix(text, wantConnect) || !strings.HasPrefix(text, tool+" needs your Github account (repo).") {
		t.Fatalf("not connected = %d %q", code, text)
	}
	noLink(t, out, "not connected")
	if r := fx.recordAfter(id); r.Outcome != "needs_authorization" || r.Class != "needs_connection" || r.Provider != "github" || r.Agent == "" ||
		r.User != e.userID("blair@localhost") || r.Kind != "service_account" {
		t.Fatalf("record = %+v", r)
	}
	if n := e.connectRequests(); n != "0" {
		t.Fatalf("%s consent requests stored for an agent call", n)
	}
	if n := e.toolCalls("provider_token"); n != 0 {
		t.Fatalf("the server was contacted %d times without a connection", n)
	}
	// A modern client that declared URL elicitation gets no input request either.
	mcode, _, mout := rawModern(t, e.app, "support", fx.key, "tools/call", toolCall(tool, nil), urlCaps, map[string]string{"MCP-Gateway-Identity": fx.toolToken(blair, tool)})
	mtext, mErr := toolText(t, mout)
	if mcode != 200 || !mErr || !strings.HasSuffix(mtext, wantConnect) {
		t.Fatalf("modern not connected = %d %v", mcode, mout)
	}
	noLink(t, mout, "modern not connected")
	// A resource read has no tool result: -32010 with the same text, no link.
	_, out = fx.post(fx.key, fx.token(blair), "support", rpc(5, "resources/read", map[string]any{"uri": "omp://status/status://services"}))
	if c, msg, data := rpcErr(out); c != -32010 || data["reason"] != "needs_connection" || data["provider"] != "github" || !strings.HasSuffix(msg, wantConnect) {
		t.Fatalf("resource read = %v", out)
	}
	noLink(t, out, "resource read")
	if n := e.connectRequests(); n != "0" {
		t.Fatalf("%s consent requests after the modern and read calls", n)
	}

	// 2. Connected, but this server isn't allowed to use the account (F-3
	// server_not_allowed): a tool error saying to allow it, no link.
	e.connectBroadly("repo")
	code, out = fx.callTool(blair, tool, nil)
	text, isErr = toolText(t, out)
	if code != 200 || !isErr || !strings.Contains(text, "needs you to allow STATUS (tools) to use your Github account (repo)") {
		t.Fatalf("server not allowed = %d %q", code, text)
	}
	noLink(t, out, "server not allowed")
	if n := e.connectRequests(); n != "0" {
		t.Fatalf("%s consent requests for server_not_allowed", n)
	}
	mcode, _, mout = rawModern(t, e.app, "support", fx.key, "tools/call", toolCall(tool, nil), urlCaps, map[string]string{"MCP-Gateway-Identity": fx.toolToken(blair, tool)})
	if _, isErr := toolText(t, mout); mcode != 200 || !isErr {
		t.Fatalf("modern server not allowed = %d %v", mcode, mout)
	}
	noLink(t, mout, "modern server not allowed")
	if n := e.toolCalls("provider_token"); n != 0 {
		t.Fatalf("the server was contacted %d times", n)
	}

	// 3. The scopes aren't enough: a tool error asking for more access.
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo", "read:org"}})
	code, out = fx.callTool(blair, tool, nil)
	text, isErr = toolText(t, out)
	if code != 200 || !isErr || !strings.Contains(text, "needs your Github account (repo, read:org). Grant more access to your Github account under Account › My connections") {
		t.Fatalf("missing scopes = %d %q", code, text)
	}
	noLink(t, out, "missing scopes")
	if n := e.connectRequests(); n != "0" {
		t.Fatalf("%s consent requests for missing scopes", n)
	}
	e.setRequirement(map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}})

	// 4. The same person's own call, as a control, still gets the link.
	own := e.callTool(e.key, tool)
	if c, _, _ := rpcErr(own); c != -32042 {
		t.Fatalf("control: blair's own call = %v", own)
	}
	if n := e.connectRequests(); n != "1" {
		t.Fatalf("control stored %s consent requests, want 1", n)
	}
	fx.noSecrets(e.logs)
	e.noSecretsAnywhere()
}

// A person who connected their account (with the server allowed) is served
// with their own token through an agent; the relay's own call and another
// person's are not.
func TestRelayedCallUsesThePersonsDelegatedCredential(t *testing.T) {
	e, fx := newAgentEnv(t)
	const tool = "status__provider_token"
	blair, owner := agentSpec{Email: "blair@localhost"}, agentSpec{Email: "user@localhost"}

	// Blair connects the usual way (a link from her own client) and allows the server.
	link := e.consentURL(e.callTool(e.key, tool), "not_connected")
	if to := e.connect(e.member, map[string]any{"providerId": e.provider.Id, "requestId": requestID(link)}); !strings.Contains(to, "connected") {
		t.Fatalf("connect = %s", to)
	}
	if out := e.callTool(e.key, tool); out["error"] != nil {
		if c, _, _ := rpcErr(out); c == -32042 {
			e.allow(e.consentURL(out, "server_not_allowed"))
		}
	}
	issued := e.oauth.Issued()
	token := issued[len(issued)-1]

	id := fx.lastCallID()
	code, out := fx.callTool(blair, tool, nil)
	rep := e.providerReport(out)
	if code != 200 || !rep.Received || rep.Provider != "github" || rep.TokenSHA256 != testutil.TokenDigest(token) || rep.Claim != "github" || !rep.ClaimMatches || !rep.Verified {
		t.Fatalf("provider report = %d %+v", code, rep)
	}
	// The downstream call carried blair's token and an identity token naming
	// her and the agent.
	calls := e.fake.ToolCalls()
	h := calls[len(calls)-1].Header
	if h.Get("MCP-Gateway-Provider-Token") != token || h.Get("MCP-Gateway-Provider") != "github" {
		t.Fatalf("provider headers = %v", h)
	}
	if r := fx.recordAfter(id); r.Outcome != "ok" || r.Provider != "github" || r.User != e.userID("blair@localhost") || r.Agent == "" {
		t.Fatalf("record = %+v", r)
	}
	// Another person (the owner) hasn't connected: a tool error, and never blair's token.
	code, out = fx.callTool(owner, tool, nil)
	text, isErr := toolText(t, out)
	if code != 200 || !isErr || !strings.HasSuffix(text, wantConnect) {
		t.Fatalf("owner through the relay = %d %q", code, text)
	}
	// The relay account's own call (no person) can't use a provider's tool.
	_, out = fx.callTool("", tool, nil)
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "service_account" {
		t.Fatalf("relay without a person = %v", out)
	}
	// An agent call that is not for a present person still uses the person's credential.
	_, out = fx.callTool(agentSpec{Email: "blair@localhost", Absent: true}, tool, nil)
	if rep := e.providerReport(out); !rep.Received || rep.TokenSHA256 != testutil.TokenDigest(token) {
		t.Fatalf("absent person's report = %+v", rep)
	}
	for _, c := range e.fake.ToolCalls() {
		if c.Tool == "provider_token" && c.Header.Get("MCP-Gateway-Provider-Token") != "" && c.Header.Get("MCP-Gateway-Provider-Token") != token {
			t.Fatal("a call carried a token that is not blair's")
		}
	}
	fx.noSecrets(e.logs)
	e.noSecretsAnywhere()
}

// Requires a present person (decision 66): per server and per capability,
// only for calls relayed for a person; reviewed like a requirement; audited.
func TestRequiresPresentPerson(t *testing.T) {
	e, fx := newAgentEnv(t)
	blair := agentSpec{Email: "blair@localhost"}
	absent := agentSpec{Email: "blair@localhost", Absent: true}
	whoami := func(spec agentSpec) (int, map[string]any) { return fx.callTool(spec, "status__whoami", nil) }
	echo := func(spec agentSpec) (int, map[string]any) {
		return fx.callTool(spec, "status__echo", map[string]any{"text": "hi"})
	}
	notPresent := func(out map[string]any, what string) {
		t.Helper()
		text, isErr := toolText(t, out)
		if !isErr || !strings.Contains(text, "needs the person to be present") {
			t.Fatalf("%s = %v", what, out)
		}
		noLink(t, out, what)
	}

	// Default off: absent people are served.
	if code, out := whoami(absent); code != 200 || whoamiClaims(t, out).Claims["act"] == nil {
		t.Fatalf("default off = %d %v", code, out)
	}
	// Turn the server's switch on (editors can; it is in the server).
	var sv struct {
		Revision int64
		Required *bool `json:"requiresPresentPerson"`
	}
	patch := func(s *session, body map[string]any) (int, string) {
		var cur struct{ Revision int64 }
		e.owner.get(e.serverPath(), &cur)
		return s.call("PATCH", e.serverPath(), body, &sv, ifMatch(cur.Revision))
	}
	if code, ec := patch(e.member, map[string]any{"requiresPresentPerson": true}); code != 403 {
		t.Fatalf("a member changed the switch: %d %s", code, ec)
	}
	code, ec := patch(e.editor, map[string]any{"requiresPresentPerson": true})
	mustCode(t, "switch on", code, ec, 200, "")
	if sv.Required == nil || !*sv.Required {
		t.Fatalf("server = %+v", sv)
	}
	id := fx.lastCallID()
	code, out := whoami(absent)
	notPresent(out, "absent person")
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "person_not_present" || r.Agent == "" || r.PersonPresent != "false" || r.User != e.userID("blair@localhost") {
		t.Fatalf("record = %+v", r)
	}
	served := e.toolCalls("whoami")
	// A present person, and calls that are not on a relay account (a personal
	// key, an ordinary service account, with or without a token the account
	// can't use), are served.
	if code, out := whoami(blair); code != 200 || whoamiClaims(t, out).Claims["sub"] != e.userID("blair@localhost") {
		t.Fatalf("present person = %d %v", code, out)
	}
	if _, out := fx.post(e.key, "", "support", whoamiCall()); whoamiClaims(t, out).Claims["principal_type"] != "user" {
		t.Fatalf("personal key = %v", out)
	}
	plain := createSA(t, e.owner, map[string]any{"name": "plain-bot", "role": "editor"})
	plainKey := createSAKey(t, e.owner, plain.Id.String(), map[string]any{"name": "k", "expiresInDays": 30}).Secret
	if _, out := fx.post(plainKey, "", "support", whoamiCall()); whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("an ordinary service account = %v", out)
	}
	if _, out := fx.post(plainKey, fx.toolToken(agentSpec{Email: "blair@localhost", Absent: true}, "status__whoami"), "support", whoamiCall()); whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("an ordinary service account with a token it can't use = %v", out)
	}
	if e.toolCalls("whoami") != served+4 {
		t.Fatalf("whoami served %d times, want 4", e.toolCalls("whoami")-served)
	}
	// M-2: on the relay account, a call that names nobody is refused too: a
	// valid token with no person (a team agent's shared thread or background
	// run) and the relay's key with no token at all. Recorded as denied,
	// person_not_present, and nothing reaches the server.
	for _, c := range []struct {
		what  string
		who   any
		agent bool
	}{
		{"a valid token that names nobody", agentSpec{}, true},
		{"the relay key with no token", "", false},
	} {
		id := fx.lastCallID()
		_, out := fx.callTool(c.who, "status__whoami", nil)
		notPresent(out, c.what)
		if text, _ := toolText(t, out); !strings.Contains(text, "names nobody") {
			t.Errorf("%s: the message doesn't say the call names nobody: %q", c.what, text)
		}
		r := fx.recordAfter(id)
		if r.Outcome != "denied" || r.Class != "person_not_present" || r.User != "" || (r.Agent != "") != c.agent || r.ServiceAccount != fx.account.Id.String() {
			t.Errorf("%s: record = %+v", c.what, r)
		}
	}
	// A resource read and a modern client are held to it as well.
	_, out = fx.post(fx.key, fx.token(agentSpec{}), "support", rpc(5, "resources/read", map[string]any{"uri": "omp://status/status://services"}))
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "person_not_present" {
		t.Fatalf("a personless resource read = %v", out)
	}
	_, out = fx.post(fx.key, "", "support", rpc(5, "resources/read", map[string]any{"uri": "omp://status/status://services"}))
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "person_not_present" {
		t.Fatalf("a resource read with no token = %v", out)
	}
	if e.toolCalls("whoami") != served+4 {
		t.Fatalf("a refused call reached the server: whoami served %d times, want 4", e.toolCalls("whoami")-served)
	}
	// A resource read of an absent person is refused with -32010.
	_, out = fx.post(fx.key, fx.token(absent), "support", rpc(5, "resources/read", map[string]any{"uri": "omp://status/status://services"}))
	if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "person_not_present" {
		t.Fatalf("resource = %v", out)
	}

	// A capability's override wins over the server's switch, both ways.
	capPath := func(name string) string {
		return e.serverPath() + "/capabilities/" + e.capID(e.owner, e.server, "tool", name) + "/present-person"
	}
	setMode := func(s *session, name, mode string) (int, string) {
		var cur struct{ Revision int64 }
		e.owner.get(e.serverPath(), &cur)
		return s.call("PUT", capPath(name), map[string]any{"mode": mode}, nil, ifMatch(cur.Revision))
	}
	for _, mode := range []string{"bogus", ""} {
		if code, ec := setMode(e.editor, "whoami", mode); code != 400 || ec != "invalid_mode" {
			t.Fatalf("mode %q = %d %s", mode, code, ec)
		}
	}
	if code, _ := setMode(e.member, "whoami", "not_required"); code != 403 {
		t.Fatalf("a member set an override: %d", code)
	}
	code, ec = setMode(e.editor, "whoami", "not_required")
	mustCode(t, "whoami not_required", code, ec, 200, "")
	if code, out := whoami(absent); code != 200 || whoamiClaims(t, out).Claims["act"] == nil {
		t.Fatalf("not_required override = %d %v", code, out)
	}
	// ... and a capability that doesn't need a present person serves calls that
	// name nobody, with or without a token.
	if code, out := whoami(agentSpec{}); code != 200 || whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("not_required, a token naming nobody = %d %v", code, out)
	}
	if code, out := fx.callTool("", "status__whoami", nil); code != 200 || whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("not_required, no token = %d %v", code, out)
	}
	if _, out := echo(absent); out["result"] == nil {
		_ = out
	}
	notPresent(second(echo(absent)), "echo follows the server")
	code, ec = setMode(e.editor, "whoami", "inherit")
	mustCode(t, "whoami inherit", code, ec, 200, "")
	notPresent(second(whoami(absent)), "inherit follows the server again")

	// Server off, capability on.
	code, ec = patch(e.editor, map[string]any{"requiresPresentPerson": false})
	mustCode(t, "switch off", code, ec, 200, "")
	if code, _ := echo(absent); code != 200 {
		t.Fatalf("server off = %d", code)
	}
	code, ec = setMode(e.editor, "echo", "required")
	mustCode(t, "echo required", code, ec, 200, "")
	notPresent(second(echo(absent)), "echo required")
	notPresent(second(echo(agentSpec{})), "echo required, a token naming nobody")
	notPresent(second(fx.callTool("", "status__echo", map[string]any{"text": "hi"})), "echo required, no token")
	if code, out := whoami(agentSpec{}); code != 200 || out["result"] == nil {
		t.Fatalf("whoami is not required, a token naming nobody: %d %v", code, out)
	}
	if code, out := whoami(absent); code != 200 || out["result"] == nil {
		t.Fatalf("whoami is not required: %d %v", code, out)
	}
	// The capability view says what applies.
	var caps []struct {
		Name          string
		PresentPerson struct {
			Mode      string
			Effective bool
		}
	}
	e.owner.get(e.serverPath()+"/capabilities", &caps)
	for _, c := range caps {
		switch c.Name {
		case "echo":
			if c.PresentPerson.Mode != "required" || !c.PresentPerson.Effective {
				t.Fatalf("echo = %+v", c)
			}
		case "whoami":
			if c.PresentPerson.Mode != "inherit" || c.PresentPerson.Effective {
				t.Fatalf("whoami = %+v", c)
			}
		}
	}
	// Audited: the switch in mcp_server.update, overrides in mcp_capability.presence_set.
	if n := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_capability.presence_set'`); n != "3" {
		t.Fatalf("presence_set audits = %s", n)
	}
	if v := e.scalar(`SELECT (after_state::jsonb->>'requiresPresentPerson') || ' ' || (before_state::jsonb->>'requiresPresentPerson') FROM audit_log
		WHERE action = 'mcp_server.update' ORDER BY id DESC LIMIT 1`); v != "false true" {
		t.Fatalf("mcp_server.update audit = %q", v)
	}
	fx.noSecrets(e.logs)
}

// Relaxing a present-person requirement sends a published server back to
// review under approval_required, like widening a requirement; requiring one
// never does.
func TestPresentPersonRelaxationGoesBackToReview(t *testing.T) {
	e, _ := newAgentEnv(t)
	e.publish(e.owner, e.server)
	state := func() string {
		return e.scalar(`SELECT publish_state FROM mcp_servers WHERE id = $1`, e.server.Id.String())
	}
	if state() != "published" {
		t.Fatalf("state = %s", state())
	}
	patch := func(on bool) {
		var cur struct{ Revision int64 }
		e.owner.get(e.serverPath(), &cur)
		code, ec := e.editor.call("PATCH", e.serverPath(), map[string]any{"requiresPresentPerson": on}, nil, ifMatch(cur.Revision))
		mustCode(t, fmt.Sprint("switch ", on), code, ec, 200, "")
	}
	setMode := func(name, mode string) {
		var cur struct{ Revision int64 }
		e.owner.get(e.serverPath(), &cur)
		code, ec := e.editor.call("PUT", e.serverPath()+"/capabilities/"+e.capID(e.owner, e.server, "tool", name)+"/present-person",
			map[string]any{"mode": mode}, nil, ifMatch(cur.Revision))
		mustCode(t, "override "+mode, code, ec, 200, "")
	}
	reviewed := func() { // an admin approves the server again
		code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(t, e.admin, e.server.Id.String()), nil, nil)
		mustCode(t, "approve", code, ec, 200, "")
	}
	// Requiring never needs review.
	patch(true)
	setMode("echo", "required")
	if state() != "published" {
		t.Fatalf("requiring: state = %s", state())
	}
	// whoami followed the server (required); an override of false relaxes it.
	setMode("whoami", "not_required")
	if state() != "pending" {
		t.Fatalf("relaxing one capability: state = %s, want pending", state())
	}
	if v := e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action = 'mcp_server.publish_request' ORDER BY id DESC LIMIT 1`); v != "requirement_changed" {
		t.Fatalf("publish_request reason = %q", v)
	}
	reviewed()
	if state() != "published" {
		t.Fatalf("state = %s", state())
	}
	setMode("whoami", "inherit") // required again: tightening
	setMode("echo", "inherit")   // still required, through the server: no change
	if state() != "published" {
		t.Fatalf("tightening and no-change: state = %s", state())
	}
	patch(false) // every capability that followed the server is relaxed
	if state() != "pending" {
		t.Fatalf("switching the server off: state = %s, want pending", state())
	}
	reviewed()
	// The review digest covers the switch: a digest read before it was turned on is stale.
	var before, after struct{ ReviewDigest string }
	e.owner.get(e.serverPath(), &before)
	patch(true)
	if state() != "published" {
		t.Fatalf("requiring again: state = %s", state())
	}
	e.owner.get(e.serverPath(), &after)
	if before.ReviewDigest == after.ReviewDigest {
		t.Fatal("the review digest doesn't cover the present-person switch")
	}
}

// An automation token can't change the present-person switch.
func TestPresentPersonIsNotForAutomationTokens(t *testing.T) {
	e, _ := newAgentEnv(t)
	var tok struct{ Secret string }
	code, ec := e.owner.call("POST", toolsTeam+"/automation-tokens", map[string]any{"name": "ci", "scopes": []string{"servers:write"}, "expiresInDays": 30}, &tok, nil)
	mustCode(t, "token", code, ec, 201, "")
	var cur struct{ Revision int64 }
	e.owner.get(e.serverPath(), &cur)
	code, raw := e.app.do("PATCH", "/v1/teams/tools/mcp-servers/"+e.server.Id.String(), map[string]any{"requiresPresentPerson": true},
		map[string]string{"Authorization": "Bearer " + tok.Secret, "If-Match": fmt.Sprintf("%q", fmt.Sprint(cur.Revision)), "Origin": ""})
	if code != 403 || errorCode(raw) != "token_not_allowed" || errorDetails(raw)["field"] != "requiresPresentPerson" {
		t.Fatalf("token PATCH = %d %s", code, raw)
	}
	// The same token may still PATCH what it was allowed to (the field is only refused when it changes).
	code, raw = e.app.do("PATCH", "/v1/teams/tools/mcp-servers/"+e.server.Id.String(), map[string]any{"requiresPresentPerson": false, "description": "by a token"},
		map[string]string{"Authorization": "Bearer " + tok.Secret, "If-Match": fmt.Sprintf("%q", fmt.Sprint(cur.Revision)), "Origin": ""})
	if code != 200 {
		t.Fatalf("token PATCH of an unchanged switch = %d %s", code, raw)
	}
}

// An MCP server in oauth mode (its own sign-in per person): an agent call
// for a person without a usable sign-in, after an upstream 401 that can't be
// refreshed, and after an upstream 403 insufficient_scope are tool errors
// naming the server and where to sign in; never a link.
func TestRelayedCallToAnOAuthServerNeverStartsConsent(t *testing.T) {
	e := newUpEnv(t, true)
	code, raw := e.createOAuth(e.editor, "gh", e.pm.URL(), map[string]any{"registration": "auto", "scopes": []string{"repo"}}, nil)
	if code != 201 {
		t.Fatalf("create = %d %s", code, raw)
	}
	var created struct{ Data apitypes.McpServerCreated }
	_ = json.Unmarshal(raw, &created)
	sv := created.Data.Server
	slug, providerID := sv.Oauth.ProviderSlug, sv.Oauth.ProviderId.String()
	e.setup(e.editor, sv.Id.String())
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "ghgw")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(e.capID(e.owner, sv, "tool", "whoami"), e.capID(e.owner, sv, "tool", "write")))
	blairKey := newKey(t, e.member, "laptop").Secret
	fx := setupRelay(t, e.gwEnv)
	blair := agentSpec{Email: "blair@localhost"}
	relay := func(tool string) map[string]any {
		t.Helper()
		code, out := fx.post(fx.key, fx.toolToken(blair, tool), "ghgw", rpc(9, "tools/call", map[string]any{"name": tool, "arguments": map[string]any{}}))
		if code != 200 {
			t.Fatalf("%s = %d %v", tool, code, out)
		}
		return out
	}
	requests := func() string { return e.scalar(`SELECT count(*)::text FROM provider_connect_requests`) }
	signIn := "Sign in to GH under Account › My connections in Open MCP Portal, then try again."

	// No sign-in yet.
	baseline := requests()
	id := fx.lastCallID()
	out := relay("gh__whoami")
	text, isErr := toolText(t, out)
	if !isErr || !strings.HasPrefix(text, "gh__whoami needs your own sign-in to GH (repo). ") || !strings.HasSuffix(text, signIn) {
		t.Fatalf("no sign-in = %v", out)
	}
	noLink(t, out, "no sign-in")
	if r := fx.recordAfter(id); r.Outcome != "needs_authorization" || r.Class != "needs_connection" || r.Provider != slug || r.Agent == "" {
		t.Fatalf("record = %+v", r)
	}
	if requests() != baseline || len(e.pm.ToolCalls()) != 0 {
		t.Fatalf("consent requests %s -> %s, or the server was called", baseline, requests())
	}

	// Blair signs in herself (a link from her own client): the agent call then
	// carries her own token for the server.
	l := e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "not_connected")
	if to := e.connectVia(e.member, providerID, l); !strings.Contains(to, "result=connected") {
		t.Fatalf("connect = %s", to)
	}
	baseline = requests()
	who := whoamiOf(t, relay("gh__whoami"))
	tok := strings.TrimPrefix(e.lastAuthorization("whoami"), "Bearer ")
	if who.BearerSHA256 == "" || who.BearerSHA256 != testutil.TokenDigest(tok) || who.Claims["act"] == nil || who.Claims["sub"] != e.userID("blair@localhost") {
		t.Fatalf("signed-in agent call = %+v", who)
	}

	// An upstream 401 is refreshed once; when that fails, a tool error.
	e.as.Invalidate(tok)
	if who2 := whoamiOf(t, relay("gh__whoami")); who2.BearerSHA256 == who.BearerSHA256 {
		t.Fatal("the token was not refreshed after a 401")
	}
	e.as.InvalidateAll(true)
	out = relay("gh__whoami")
	text, isErr = toolText(t, out)
	if !isErr || !strings.HasSuffix(text, "Sign in again to GH under Account › My connections in Open MCP Portal, then try again.") {
		t.Fatalf("after a refused refresh = %v", out)
	}
	noLink(t, out, "401")
	if st := e.scalar(`SELECT status FROM provider_connections WHERE provider_id = $1 AND user_id = $2`, providerID, e.userID("blair@localhost")); st != "needs_reconsent" {
		t.Fatalf("connection = %s", st)
	}
	if requests() != baseline {
		t.Fatalf("consent requests %s -> %s after a 401", baseline, requests())
	}

	// A 403 insufficient_scope (reconnect first, with her own client).
	l = e.link(e.call(blairKey, "ghgw", "gh__whoami", nil), slug, "needs_reconsent")
	e.connectVia(e.member, providerID, l)
	baseline = requests()
	out = relay("gh__write")
	text, isErr = toolText(t, out)
	if !isErr || !strings.Contains(text, "Grant more access to GH") || !strings.HasSuffix(text, "under Account › My connections in Open MCP Portal, then try again.") {
		t.Fatalf("insufficient scope = %v", out)
	}
	noLink(t, out, "insufficient_scope")
	if requests() != baseline {
		t.Fatalf("consent requests %s -> %s after a 403", baseline, requests())
	}
	e.recorded("needs_authorization needs_connection " + slug)
	// Nothing leaked: the sentinel of this flow (tokens, secrets, links).
	fx.noSecrets(e.logs, e.as.ClientSecret)
	for _, s := range append(e.as.Issued(), e.as.IssuedRefresh()...) {
		if strings.Contains(e.logs.String(), s) || strings.Contains(strings.Join(fx.responses, " "), s) {
			t.Fatal("a provider token leaked")
		}
	}
}
