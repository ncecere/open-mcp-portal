package httpapi_test

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// Calls relayed by a trusted agent platform (decisions 65 and 66,
// docs/agent-platforms.md): a relay service account's token names the
// person; the call is authorised as the person limited to what the relay
// could reach; every other case fails closed.

// newAgentEnv is a support gateway whose whoami is open to everyone (no provider
// needed) and a fake agent platform with its relay account.
func newAgentEnv(t *testing.T) (*provEnv, *relayFx) {
	t.Helper()
	e := newProvEnv(t)
	fx := setupRelay(t, e.gwEnv)
	for _, tool := range []string{"whoami", "echo"} {
		if code, msg := e.override(tool, map[string]any{"mode": "none"}); code != 200 {
			t.Fatalf("override %s = %d %s", tool, code, msg)
		}
	}
	return e, fx
}

func whoamiCall() map[string]any {
	return rpc(3, "tools/call", map[string]any{"name": "status__whoami", "arguments": map[string]any{}})
}

// A service account's key alone, with no token, behaves exactly as before:
// the account's own call, whether or not it is marked as a relay.
func TestRelayKeyAloneBehavesAsBefore(t *testing.T) {
	e, fx := newAgentEnv(t)
	plain := createSA(t, e.owner, map[string]any{"name": "plain-bot", "role": "editor"})
	plainKey := createSAKey(t, e.owner, plain.Id.String(), map[string]any{"name": "k", "expiresInDays": 30}).Secret
	for name, key := range map[string]string{"relay": fx.key, "plain": plainKey} {
		id := fx.lastCallID()
		code, out := fx.post(key, "", "support", whoamiCall())
		who := whoamiClaims(t, out)
		if code != 200 || !who.Verified || who.Claims["principal_type"] != "service_account" || who.Claims["act"] != nil || who.Act != nil || who.ActedBy != "" || who.Claims["email"] != nil {
			t.Fatalf("%s: %d %+v", name, code, who)
		}
		if r := fx.recordAfter(id); r.Kind != "service_account" || r.User != "" || r.Agent != "" || r.Platform != "" || r.PersonPresent != "" || r.Outcome != "ok" {
			t.Fatalf("%s record = %+v", name, r)
		}
		// A capability that needs a person's account: refused as ever.
		_, out = fx.callTool("", "status__provider_token", nil)
		if c, _, data := rpcErr(out); c != -32010 || data["reason"] != "service_account" {
			t.Fatalf("%s provider tool = %v", name, out)
		}
	}
	a := fx.listTools(fx.key, "")
	b := fx.listTools(plainKey, "")
	if !slices.Equal(a, b) {
		t.Fatalf("lists differ: %v vs %v", a, b)
	}
	if n := e.scalar(`SELECT count(*)::text FROM agent_token_jtis`); n != "0" {
		t.Fatalf("%s jtis recorded without a token", n)
	}
}

func (fx *relayFx) listTools(key, token string) []string {
	fx.t.Helper()
	code, out := fx.post(key, token, "support", rpc(1, "tools/list", nil))
	if code != 200 {
		fx.t.Fatalf("tools/list = %d %v", code, out)
	}
	names := []string{}
	if r, ok := out["result"].(map[string]any); ok {
		tools, _ := r["tools"].([]any)
		for _, tool := range tools {
			names = append(names, tool.(map[string]any)["name"].(string))
		}
	}
	slices.Sort(names)
	return names
}

// A valid token naming a person makes the call the person's, with the agent
// as the actor, in the downstream token, the call record and the call log.
func TestRelayedCallIsThePersonsWithTheAgentAsActor(t *testing.T) {
	e, fx := newAgentEnv(t)
	blairID := e.userID("blair@localhost")

	id := fx.lastCallID()
	code, out := fx.callTool(fx.token(agentSpec{Email: "blair@localhost"}), "status__whoami", nil)
	who := whoamiClaims(t, out)
	c := who.Claims
	teams, _ := c["teams"].([]any)
	if code != 200 || !who.Verified || c["principal_type"] != "user" || c["sub"] != blairID || c["email"] != "blair@localhost" ||
		len(teams) != 1 || teams[0] != "tools" || c["client"] != "pdp-relay" || c["gateway"] != "support" || c["tool"] != "status__whoami" {
		t.Fatalf("downstream identity = %d %+v", code, who)
	}
	if who.Act == nil || !strings.Contains(who.ActedBy, `"Mail assistant"`) || !strings.Contains(who.ActedBy, "while the person was present") {
		t.Fatalf("the fake server's whoami doesn't show act: %+v", who)
	}
	act, _ := c["act"].(map[string]any)
	if len(act) != 5 || act["sub"] != "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21" || act["name"] != "Mail assistant" || act["iss"] != relayIssuerURL ||
		act["principal_type"] != "agent" || act["person_present"] != true {
		t.Fatalf("act = %v", act)
	}
	r := fx.recordAfter(id)
	if r.Kind != "service_account" || r.ServiceAccount != fx.account.Id.String() || r.User != blairID || r.Agent != "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21" ||
		r.AgentName != "Mail assistant" || r.Platform != "Pi Durable Platform" || r.PersonPresent != "true" || r.Outcome != "ok" {
		t.Fatalf("record = %+v", r)
	}

	// The person is not present.
	_, out = fx.callTool(fx.token(agentSpec{Email: "blair@localhost", Absent: true}), "status__whoami", nil)
	act, _ = whoamiClaims(t, out).Claims["act"].(map[string]any)
	if act["person_present"] != false {
		t.Fatalf("act when absent = %v", act)
	}

	// No person (a shared thread): the account's own call, with the agent
	// recorded and no act claim.
	id = fx.lastCallID()
	_, out = fx.callTool(fx.token(agentSpec{}), "status__whoami", nil)
	who = whoamiClaims(t, out)
	if who.Claims["principal_type"] != "service_account" || who.Claims["sub"] != fx.account.Id.String() || who.Claims["act"] != nil || who.Claims["email"] != nil {
		t.Fatalf("no person: %+v", who)
	}
	if r := fx.recordAfter(id); r.Kind != "service_account" || r.User != "" || r.Agent == "" || r.Platform != "Pi Durable Platform" || r.PersonPresent != "" {
		t.Fatalf("no person record = %+v", r)
	}

	// The person is found by (iss, sub), never by the email the token carries.
	_, out = fx.callTool(fx.token(agentSpec{Email: "casey@localhost", Subject: fx.subject("blair@localhost")}), "status__whoami", nil)
	if w := whoamiClaims(t, out); w.Claims["sub"] != blairID || w.Claims["email"] != "blair@localhost" {
		t.Fatalf("email in the token decided who: %+v", w.Claims)
	}

	// The call log shows the person, the agent, the relay account and the
	// platform: to the relay team's admins and to platform staff.
	for name, s := range map[string]*session{"team": e.owner, "admin": e.admin} {
		var page apitypes.McpCallPage
		path := toolsTeam + "/calls?limit=10"
		if name == "admin" {
			path = "/v1/admin/calls?limit=10"
		}
		if code := s.get(path, &page); code != 200 {
			t.Fatalf("%s calls = %d", name, code)
		}
		var found bool
		for _, it := range page.Items {
			if it.Agent == nil || it.Agent.Person == nil || it.Agent.Person.UserId == nil || it.Agent.Person.UserId.String() != blairID {
				continue
			}
			found = true
			if it.Principal.Kind != "service_account" || it.Principal.DisplayName != "pdp-relay" || it.Agent.AgentId != "0e6a3d4c-5f1b-4f0e-9b8e-2d7c1a9f3b21" ||
				it.Agent.AgentName == nil || *it.Agent.AgentName != "Mail assistant" || it.Agent.PlatformName != "Pi Durable Platform" ||
				it.Agent.PersonPresent == nil || it.Agent.Person.DisplayName == "" || it.Agent.Person.Email == nil || *it.Agent.Person.Email != "blair@localhost" {
				t.Fatalf("%s call row = %+v / %+v", name, it.Principal, it.Agent)
			}
			break
		}
		if !found {
			t.Fatalf("%s call log has no relayed call: %+v", name, page.Items)
		}
	}
	var page apitypes.McpCallPage
	e.owner.get(toolsTeam+"/calls?limit=50", &page)
	for _, it := range page.Items {
		if it.Agent == nil && (it.Principal.Kind != "service_account" && it.Principal.Kind != "api_key" && it.Principal.Kind != "oauth") {
			t.Fatalf("row without an agent has kind %s", it.Principal.Kind)
		}
	}
	fx.noSecrets(e.logs)
}

// effective access = the person's gateway access and minimum roles
// intersected with the relay account's.
func TestRelayedAccessIsThePersonIntersectedWithTheRelay(t *testing.T) {
	e, fx := newAgentEnv(t)
	whoami, echo := e.capID(e.owner, e.server, "tool", "whoami"), e.capID(e.owner, e.server, "tool", "echo")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(e.capID(e.owner, e.server, "tool", "provider_token"), whoami+":editor", echo+":admin"))

	// The relay account is an editor: it reaches provider_token and whoami.
	if got := fx.listTools(fx.key, ""); !slices.Equal(got, []string{"status__provider_token", "status__whoami"}) {
		t.Fatalf("relay alone sees %v", got)
	}
	cases := []struct {
		who  string
		want []string
	}{
		// A member is below the relay: the call is the member's.
		{"blair@localhost", []string{"status__provider_token"}},
		// An editor equals the relay.
		{"alex@localhost", []string{"status__provider_token", "status__whoami"}},
		// An owner is above the relay: the call can't reach more than the relay could.
		{"user@localhost", []string{"status__provider_token", "status__whoami"}},
	}
	for _, c := range cases {
		if got := fx.listTools(fx.key, fx.token(agentSpec{Email: c.who})); !slices.Equal(got, c.want) {
			t.Errorf("relay for %s lists %v, want %v", c.who, got, c.want)
		}
	}
	// A refused capability looks unknown, is recorded as denied for its role
	// with the agent, and never reaches the server.
	before := len(e.fake.ToolCalls())
	id := fx.lastCallID()
	_, out := fx.callTool(fx.token(agentSpec{Email: "user@localhost"}), "status__echo", map[string]any{"text": "x"})
	if rpcErrorCode(out) != -32602 {
		t.Fatalf("owner through an editor relay called an admin tool: %v", out)
	}
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "role" || r.Agent == "" || r.User != e.userID("user@localhost") {
		t.Fatalf("record = %+v", r)
	}
	_, out = fx.callTool(fx.token(agentSpec{Email: "blair@localhost"}), "status__whoami", nil)
	if rpcErrorCode(out) != -32602 {
		t.Fatalf("a member through an editor relay called an editor tool: %v", out)
	}
	if len(e.fake.ToolCalls()) != before {
		t.Fatal("a refused call reached the server")
	}

	// Gateway access: platform gateways are granted to the relay's team or to a person.
	e.publish(e.owner, e.server)
	var corp, vip apitypes.Gateway
	for slug, out := range map[string]*apitypes.Gateway{"corp": &corp, "vip": &vip} {
		code, ec := e.admin.call("POST", "/v1/admin/gateways", map[string]any{"slug": slug, "name": strings.ToUpper(slug)}, out, nil)
		mustCode(t, "create "+slug, code, ec, 201, "")
		e.mustSetCaps(e.admin, "/v1/admin/gateways/"+out.Id.String(), sel(echo))
	}
	grant := func(g apitypes.Gateway, body map[string]any) {
		code, ec := e.admin.call("POST", "/v1/admin/gateways/"+g.Id.String()+"/grants", body, nil, nil)
		mustCode(t, "grant", code, ec, 201, "")
	}
	grant(corp, map[string]any{"subjectKind": "team", "team": "tools"})
	grant(vip, map[string]any{"subjectKind": "user", "userEmail": "casey@localhost"})
	caseyKey := newKey(t, e.outsider, "casey").Secret
	list := func(key, slug, token string) int {
		code, _ := fx.post(key, token, slug, rpc(1, "tools/list", nil))
		return code
	}
	// corp: the relay's team has it, and so does blair (a member), not casey.
	if list(fx.key, "corp", "") != 200 || list(fx.key, "corp", fx.token(agentSpec{Email: "blair@localhost"})) != 200 {
		t.Fatal("relay and blair should reach corp")
	}
	id = fx.lastCallID()
	if list(fx.key, "corp", fx.token(agentSpec{Email: "casey@localhost"})) != 404 {
		t.Fatal("casey is not in the relay's team: the relay can't hand her corp")
	}
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "no_access" || r.Agent == "" || r.User != e.userID("casey@localhost") {
		t.Fatalf("denied record = %+v", r)
	}
	// vip: casey has it herself; the relay's team doesn't, so no token helps.
	if list(caseyKey, "vip", "") != 200 {
		t.Fatal("casey should reach vip with her own key")
	}
	if list(fx.key, "vip", fx.token(agentSpec{Email: "casey@localhost"})) != 404 || list(fx.key, "vip", "") != 404 {
		t.Fatal("the relay's team has no grant to vip")
	}
	fx.noSecrets(e.logs)
}

// Suspended, removed and unknown people, and people removed from a team,
// lose access through agents on the next call, and never fall back to the
// service account.
func TestRelayedPersonStatusIsReadEveryCall(t *testing.T) {
	e, fx := newAgentEnv(t)
	blair := agentSpec{Email: "blair@localhost"}
	blairID := e.userID("blair@localhost")
	call := func(spec agentSpec) (int, map[string]any) { return fx.callTool(fx.token(spec), "status__whoami", nil) }
	if code, out := call(blair); code != 200 || whoamiClaims(t, out).Claims["sub"] != blairID {
		t.Fatalf("baseline = %d %v", code, out)
	}
	served := e.toolCalls("whoami")

	// Unknown to the portal: a tool error, never the account's call.
	id := fx.lastCallID()
	code, out := call(agentSpec{Email: "ghost@example.com", Subject: "no-such-subject"})
	text, isErr := toolText(t, out)
	if code != 200 || !isErr || !strings.Contains(text, "no active Open MCP Portal account") {
		t.Fatalf("unknown person = %d %v", code, out)
	}
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "person_no_account" || r.User != "" || r.Agent == "" || r.PersonPresent != "true" {
		t.Fatalf("unknown person record = %+v", r)
	}
	// Other methods are refused with an error too.
	if c, _, data := rpcErr(second(fx.post(fx.key, fx.token(agentSpec{Subject: "no-such-subject", Email: "g@example.com"}), "support", rpc(1, "tools/list", nil)))); c != -32010 || data["reason"] != "person_no_account" {
		t.Fatalf("tools/list for an unknown person = %v %v", c, data)
	}
	// A notification has nothing to answer.
	if code, _, _ := rawMCP(t, e.app, "POST", "support", fx.key, map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"},
		map[string]string{"MCP-Gateway-Identity": fx.token(agentSpec{Subject: "no-such-subject", Email: "g@example.com"})}); code != 202 {
		t.Fatalf("notification = %d", code)
	}

	// Suspended: the next call is refused (decision 53); reactivated, it works.
	e.scalar(`UPDATE users SET status = 'suspended' WHERE id = $1 RETURNING 'x'`, blairID)
	id = fx.lastCallID()
	code, out = call(blair)
	if text, isErr = toolText(t, out); code != 200 || !isErr || !strings.Contains(text, "suspended") {
		t.Fatalf("suspended person = %d %v", code, out)
	}
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "person_suspended" || r.User != blairID || r.Agent == "" {
		t.Fatalf("suspended record = %+v", r)
	}
	e.scalar(`UPDATE users SET status = 'active' WHERE id = $1 RETURNING 'x'`, blairID)
	if code, out := call(blair); code != 200 || whoamiClaims(t, out).Claims["sub"] != blairID {
		t.Fatalf("reactivated = %d %v", code, out)
	}

	// Removed from the team: the gateway is gone for them at once.
	served = e.toolCalls("whoami")
	code, ec := e.owner.call("DELETE", toolsTeam+"/members/"+blairID, nil, nil, nil)
	mustCode(t, "remove blair", code, ec, 200, "")
	id = fx.lastCallID()
	if code, out := call(blair); code != 404 || rpcErrorCode(out) != -32001 {
		t.Fatalf("removed person = %d %v", code, out)
	}
	if r := fx.recordAfter(id); r.Outcome != "denied" || r.Class != "no_access" || r.User != blairID || r.Agent == "" {
		t.Fatalf("removed record = %+v", r)
	}
	// ... while the relay account's own call (no person) still works.
	if code, out := fx.callTool(fx.token(agentSpec{}), "status__whoami", nil); code != 200 || whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("relay without a person = %d %v", code, out)
	}
	if got := e.toolCalls("whoami"); got != served+1 {
		t.Fatalf("whoami reached the server %d times since the removal, want 1 (the account's own call)", got-served)
	}
	// Added back: it works again.
	code, ec = e.owner.call("POST", toolsTeam+"/members", map[string]any{"email": "blair@localhost", "role": "member"}, nil, nil)
	mustCode(t, "add blair", code, ec, 201, "")
	if code, out := call(blair); code != 200 || whoamiClaims(t, out).Claims["sub"] != blairID {
		t.Fatalf("added back = %d %v", code, out)
	}
	fx.noSecrets(e.logs)
}

func second(_ int, out map[string]any) map[string]any { return out }

// A token with any credential that isn't a relay account's is ignored: the
// call is the credential's own, and the token is counted and logged.
func TestAgentTokenOnOtherCredentialsIsIgnored(t *testing.T) {
	e, fx := newAgentEnv(t)
	plain := createSA(t, e.owner, map[string]any{"name": "plain-bot", "role": "editor"})
	plainKey := createSAKey(t, e.owner, plain.Id.String(), map[string]any{"name": "k", "expiresInDays": 30}).Secret
	alexToken := func() string { return fx.token(agentSpec{Email: "alex@localhost"}) }
	before := tokenCount("ignored_not_relay")

	// Blair's personal key with a token naming alex: still blair's call.
	_, out := fx.post(e.key, alexToken(), "support", whoamiCall())
	who := whoamiClaims(t, out)
	if who.Claims["principal_type"] != "user" || who.Claims["sub"] != e.userID("blair@localhost") || who.Claims["act"] != nil {
		t.Fatalf("personal key + token = %+v", who.Claims)
	}
	// A service account that is not a relay: its own call.
	_, out = fx.post(plainKey, alexToken(), "support", whoamiCall())
	who = whoamiClaims(t, out)
	if who.Claims["principal_type"] != "service_account" || who.Claims["sub"] != plain.Id.String() || who.Claims["act"] != nil {
		t.Fatalf("plain service account + token = %+v", who.Claims)
	}
	// Even garbage is only ignored with such a credential.
	if code, out := fx.post(plainKey, "not-a-token", "support", whoamiCall()); code != 200 || whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("garbage + plain account = %d %v", code, out)
	}
	if got := tokenCount("ignored_not_relay") - before; got != 3 {
		t.Fatalf("ignored tokens counted = %v, want 3", got)
	}
	if !strings.Contains(e.logs.String(), "not a relay account's") {
		t.Fatal("an ignored token was not logged")
	}
	// An ignored token is never recorded as used: it could still be replayed
	// by the real relay, which is why it is not consumed either way, and a
	// credential that can't relay learns nothing from the refusal.
	if n := e.scalar(`SELECT count(*)::text FROM agent_token_jtis`); n != "0" {
		t.Fatalf("%s jtis recorded for ignored tokens", n)
	}
	// The relay account itself isn't affected by the above.
	_, out = fx.callTool(alexToken(), "status__whoami", nil)
	if who := whoamiClaims(t, out); who.Claims["sub"] != e.userID("alex@localhost") {
		t.Fatalf("relay + token = %+v", who.Claims)
	}
	fx.noSecrets(e.logs)
}

// A token that fails any check on a relay account's request refuses the
// request: nothing runs, the caller is neither the account nor the person.
func TestRelayTokenFailuresRefuseTheRequest(t *testing.T) {
	e, fx := newAgentEnv(t)
	blair := agentSpec{Email: "blair@localhost"}
	other := newRelayIssuer(t, "https://other-platform.example.test")
	otherID := fx.addPlatform("Another platform", other)
	cases := []struct {
		name   string
		token  func() string
		reason string
	}{
		{"expired", func() string { return fx.token(agentSpec{Email: "blair@localhost", Mutate: expireToken}) }, "expired"},
		{"another audience", func() string {
			return fx.token(agentSpec{Email: "blair@localhost", Mutate: func(c map[string]any) { c["aud"] = "https://other.example" }})
		}, "audience"},
		{"a person of another identity provider", func() string {
			return fx.token(agentSpec{Email: "blair@localhost", Mutate: func(c map[string]any) {
				c["person"] = map[string]any{"iss": "https://other-idp.example", "sub": "x"}
			}})
		}, "person_issuer"},
		{"not an agent", func() string {
			return fx.token(agentSpec{Email: "blair@localhost", Mutate: func(c map[string]any) { c["principal_type"] = "user" }})
		}, "principal_type"},
		{"a bad signature", func() string {
			tok := fx.token(blair)
			return tok[:len(tok)-4] + "AAAA"
		}, "signature"},
		{"a key the issuer never published", func() string {
			var claims map[string]any
			fx.token(agentSpec{Email: "blair@localhost", Mutate: func(c map[string]any) { claims = c }})
			return fx.ri.signUnpublished(claims)
		}, "unknown_kid"},
		{"an issuer nobody trusts", func() string {
			return newRelayIssuer(t, "https://stranger.example.test").mint(e.app.URL, fx.subject, blair)
		}, "untrusted_issuer"},
		{"another trusted platform's token", func() string { return other.mint(e.app.URL, fx.subject, blair) }, "other_platform"},
		{"garbage", func() string { return "garbage" }, "malformed"},
	}
	served := len(e.fake.ToolCalls())
	for _, c := range cases {
		before := tokenCount("rejected_" + c.reason)
		code, out := fx.callTool(c.token(), "status__whoami", nil)
		msg, _ := out["error"].(map[string]any)["message"].(string)
		if code != 403 || rpcErrorCode(out) != -32001 || !strings.Contains(msg, "("+c.reason+")") || !strings.Contains(msg, "was not run") {
			t.Errorf("%s: %d %v (want 403 refused as %s)", c.name, code, out, c.reason)
		}
		if tokenCount("rejected_"+c.reason) != before+1 {
			t.Errorf("%s: not counted as rejected_%s", c.name, c.reason)
		}
		// A list is refused the same way, so a bad token never changes who the caller is.
		if code, _ := fx.post(fx.key, c.token(), "support", rpc(1, "tools/list", nil)); code != 403 {
			t.Errorf("%s: tools/list = %d, want 403", c.name, code)
		}
	}
	if len(e.fake.ToolCalls()) != served {
		t.Fatal("a refused request reached the server")
	}
	// Two tokens in one request.
	tok := fx.token(blair)
	req := fx.rawWithTwoTokens(tok, fx.token(blair))
	if req != 403 {
		t.Fatalf("two tokens = %d", req)
	}
	// A reused jti is refused.
	tok = fx.token(blair)
	if code, _ := fx.callTool(tok, "status__whoami", nil); code != 200 {
		t.Fatalf("first use = %d", code)
	}
	if code, out := fx.callTool(tok, "status__whoami", nil); code != 403 || !strings.Contains(fmt.Sprint(out), "(replay)") {
		t.Fatalf("second use = %d %v", code, out)
	}
	// A disabled platform's tokens are refused at once; turning it back on restores them.
	var plat apitypes.AgentPlatform
	e.admin.get("/v1/admin/agent-platforms/"+fx.platformID, &plat)
	code, ec := e.admin.call("PATCH", "/v1/admin/agent-platforms/"+fx.platformID, map[string]any{"enabled": false}, &plat, ifMatch(plat.Revision))
	mustCode(t, "disable", code, ec, 200, "")
	if code, out := fx.callTool(fx.token(blair), "status__whoami", nil); code != 403 || !strings.Contains(fmt.Sprint(out), "(disabled_issuer)") {
		t.Fatalf("disabled platform = %d %v", code, out)
	}
	// ... but the relay's own calls with no token are untouched by it.
	if code, out := fx.callTool("", "status__whoami", nil); code != 200 || whoamiClaims(t, out).Claims["principal_type"] != "service_account" {
		t.Fatalf("relay without a token while disabled = %d %v", code, out)
	}
	code, ec = e.admin.call("PATCH", "/v1/admin/agent-platforms/"+fx.platformID, map[string]any{"enabled": true}, &plat, ifMatch(plat.Revision))
	mustCode(t, "enable", code, ec, 200, "")
	if code, _ := fx.callTool(fx.token(blair), "status__whoami", nil); code != 200 {
		t.Fatalf("re-enabled = %d", code)
	}
	// The relay mark moves with the platform: deleting it clears the mark, and
	// a token with the key is then ignored (and counted).
	if n := e.scalar(`SELECT count(*)::text FROM agent_platforms WHERE id = $1`, otherID); n != "1" {
		t.Fatal("the other platform vanished")
	}
	code, ec = e.admin.call("DELETE", "/v1/admin/agent-platforms/"+fx.platformID, nil, nil, nil)
	mustCode(t, "delete platform", code, ec, 200, "")
	before := tokenCount("ignored_not_relay")
	_, out := fx.callTool(fx.token(blair), "status__whoami", nil)
	if w := whoamiClaims(t, out); w.Claims["principal_type"] != "service_account" || w.Claims["act"] != nil || tokenCount("ignored_not_relay") != before+1 {
		t.Fatalf("after deleting the platform: %+v", w.Claims)
	}
	fx.noSecrets(e.logs)
}

func expireToken(c map[string]any) {
	c["iat"], c["nbf"], c["exp"] = nowMinus(10*60), nowMinus(10*60+30), nowMinus(5*60)
}

// A second token header on one request.
func (fx *relayFx) rawWithTwoTokens(a, b string) int {
	fx.t.Helper()
	code, _, _ := rawMCPMulti(fx.t, fx.e.app, "support", fx.key, whoamiCall(), []string{a, b})
	return code
}
