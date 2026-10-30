package httpapi_test

import (
	"encoding/json"
	"strings"
	"testing"
)

// An automation token can never change a server's owner, on-call contact,
// sensitivity, lifecycle or replacement, never ask for or answer a transfer and
// never set a gateway's ceiling (decision 88): the rule holds on a server with
// no credentials, where the other field rules let a token edit.
func TestTokenGovernanceFieldRules(t *testing.T) {
	e := newMatrixEnv(t)
	creds := map[string]tokenCred{}
	for _, c := range e.tokenCreds() {
		creds[c.name] = c
	}
	pub, plat := creds["publisher-write"], creds["platform-write"]
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	field := func(body []byte) (code, field string) {
		var env struct {
			Error struct {
				Code    string
				Details struct{ Field string }
			}
		}
		_ = json.Unmarshal(body, &env)
		return env.Error.Code, env.Error.Details.Field
	}
	before := e.exec(`SELECT sensitivity || '/' || lifecycle || '/' || coalesce(owner_user_id::text, '') || '/' || coalesce(oncall_contact, '') FROM mcp_servers WHERE id = $1`, srv)
	for name, gov := range map[string]map[string]any{
		"sensitivity": {"sensitivity": "restricted"}, "owner": {"ownerUserId": e.userIDs[cEditor]}, "clearing the owner": {"ownerUserId": nil},
		"on-call": {"oncallContact": "#x"}, "lifecycle": {"lifecycle": "deprecated"}, "replacement": {"replacementServerId": nil}, "an empty object": {},
	} {
		code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"governance": gov}).h(rev()))
		if c, f := field(body); code != 403 || c != "token_not_allowed" || f != "governance" {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// A null object too, and alongside a harmless field: nothing is applied.
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"governance": nil, "description": "x"}).h(rev())); code != 403 {
		t.Errorf("null governance: %d %s", code, body)
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "harmless", "governance": map[string]any{"sensitivity": "public"}}).h(rev())); code != 403 {
		t.Errorf("governance with a harmless field: %d %s", code, body)
	}
	if got := e.exec(`SELECT sensitivity || '/' || lifecycle || '/' || coalesce(owner_user_id::text, '') || '/' || coalesce(oncall_contact, '') FROM mcp_servers WHERE id = $1`, srv); got != before {
		t.Errorf("a token changed governance: %s -> %s", before, got)
	}
	if e.exec(`SELECT description FROM mcp_servers WHERE id = $1`, srv) == "harmless" {
		t.Error("the harmless field of a refused request was applied")
	}
	// The harmless fields still work, and reading governance is allowed.
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "still fine"}).h(rev())); code != 200 || !strings.Contains(string(body), `"governance"`) {
		t.Errorf("description: %d %s", code, body)
	}
	// A publisher token's own team servers: the platform token has no team role at all.
	if code, _, _ := e.bearer(plat.secret, patch(path, map[string]any{"governance": map[string]any{"sensitivity": "public"}}).h(rev())); code != 403 && code != 404 {
		t.Errorf("platform token: %d", code)
	}

	// Transfers and the platform's governance settings are session-only.
	for name, req := range map[string]request{
		"request transfer": post(path+"/transfer", map[string]any{"toTeam": "alpha"}),
		"list transfers":   get("/v1/teams/bravo/mcp-server-transfers"),
		"force transfer":   post("/v1/admin/mcp-servers/"+srv+"/transfer", map[string]any{"toTeam": "alpha"}).h(rev()),
		"read settings":    get("/v1/admin/settings/governance"),
		"change settings":  request{method: "PUT", path: "/v1/admin/settings/governance", body: map[string]any{"returnOverdueToReview": true}, headers: map[string]string{"If-Match": `"1"`}},
	} {
		for _, c := range []tokenCred{pub, plat} {
			if code, _, body := e.bearer(c.secret, req); code != 403 || !strings.Contains(string(body), "token_not_allowed") {
				t.Errorf("%s with %s: %d %s", name, c.name, code, body)
			}
		}
	}
	if e.exec(`SELECT count(*)::text FROM server_transfers`) != "0" || e.exec(`SELECT governance_return_overdue::text FROM platform_settings`) != "false" {
		t.Error("a token changed a transfer or the settings")
	}

	// A gateway's ceiling decides which servers it serves: no token sets it,
	// on create or update, even on the gateways platform tokens provision.
	code, _, body := e.bearer(plat.secret, post("/v1/admin/gateways", map[string]any{"slug": "tok-gw", "name": "Tok", "maxSensitivity": "public"}))
	if c, f := field(body); code != 403 || c != "token_not_allowed" || f != "maxSensitivity" {
		t.Errorf("create with a ceiling: %d %s", code, body)
	}
	if code, _, body := e.bearer(plat.secret, post("/v1/admin/gateways", map[string]any{"slug": "tok-gw", "name": "Tok"})); code != 201 {
		t.Fatalf("create without a ceiling: %d %s", code, body)
	}
	if got := e.exec(`SELECT max_sensitivity FROM gateways WHERE slug = 'tok-gw'`); got != "restricted" {
		t.Errorf("default ceiling = %s", got)
	}
	gw := "/v1/admin/gateways/" + e.exec(`SELECT id::text FROM gateways WHERE slug = 'tok-gw'`)
	gwRev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM gateways WHERE slug = 'tok-gw'`) + `"`}
	}
	code, _, body = e.bearer(plat.secret, patch(gw, map[string]any{"maxSensitivity": "public"}).h(gwRev()))
	if c, f := field(body); code != 403 || c != "token_not_allowed" || f != "maxSensitivity" {
		t.Errorf("update with a ceiling: %d %s", code, body)
	}
	if code, _, body := e.bearer(plat.secret, patch(gw, map[string]any{"description": "fine"}).h(gwRev())); code != 200 {
		t.Errorf("update without a ceiling: %d %s", code, body)
	}
	if got := e.exec(`SELECT max_sensitivity FROM gateways WHERE slug = 'tok-gw'`); got != "restricted" {
		t.Errorf("a token changed the ceiling to %s", got)
	}
	// A person can.
	if code, _ := e.callers[cPlatformAdmin].raw("PATCH", gw, map[string]any{"maxSensitivity": "confidential"}, gwRev()); code != 200 {
		t.Errorf("a platform admin's ceiling: %d", code)
	}
	if code, _ := e.callers[cPlatformAdmin].raw("PATCH", gw, map[string]any{"maxSensitivity": "secret"}, gwRev()); code != 400 {
		t.Errorf("an invalid ceiling: %d", code)
	}
}
