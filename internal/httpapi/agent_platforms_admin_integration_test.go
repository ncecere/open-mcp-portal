package httpapi_test

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// Trusted agent platforms and relay marks are platform admins' (decision 66):
// not a team's owners or admins, and never an automation token (decision 58).
func TestAgentPlatformAdministration(t *testing.T) {
	e := newGwEnv(t, nil)
	fx := setupRelay(t, e)
	base := "/v1/admin/agent-platforms"
	relayPath := base + "/" + fx.platformID + "/relays/" + fx.account.Id.String()

	// A platform token (even with write) is refused on every operation.
	var tok struct{ Secret string }
	code, ec := e.admin.call("POST", "/v1/admin/automation-tokens", map[string]any{"name": "ci", "scopes": []string{"platform:write"}, "expiresInDays": 30}, &tok, nil)
	mustCode(t, "platform token", code, ec, 201, "")
	for _, op := range []struct{ method, path string }{
		{"GET", base}, {"POST", base}, {"GET", base + "/" + fx.platformID}, {"PATCH", base + "/" + fx.platformID},
		{"DELETE", base + "/" + fx.platformID}, {"POST", base + "/" + fx.platformID + "/test"}, {"GET", base + "/" + fx.platformID + "/relays"},
		{"PUT", relayPath}, {"DELETE", relayPath},
	} {
		var body any
		if op.method == "POST" && op.path == base {
			body = map[string]any{"name": "x", "issuer": "https://x.example.test"}
		}
		code, raw := e.app.do(op.method, op.path, body, map[string]string{"Authorization": "Bearer " + tok.Secret, "If-Match": `"1"`, "Origin": ""})
		if code != 403 || errorCode(raw) != "token_not_allowed" {
			t.Errorf("%s %s with a platform token = %d %s", op.method, op.path, code, raw)
		}
	}
	// Team owners and admins, editors and members can't mark relays or trust platforms.
	for name, s := range map[string]*session{"owner": e.owner, "editor": e.editor, "member": e.member, "outsider": e.outsider} {
		if code, _ := s.call("PUT", relayPath, nil, nil, nil); code != 403 {
			t.Errorf("%s marked a relay: %d", name, code)
		}
		if code, _ := s.call("POST", base, map[string]any{"name": "x", "issuer": "https://x.example.test"}, nil, nil); code != 403 {
			t.Errorf("%s trusted a platform: %d", name, code)
		}
		if code := s.get(base, nil); code != 403 {
			t.Errorf("%s listed platforms: %d", name, code)
		}
	}
	// An auditor reads, and can't change.
	var list []apitypes.AgentPlatform
	if code := e.auditor.get(base, &list); code != 200 || len(list) != 1 || list[0].RelayCount != 1 {
		t.Fatalf("auditor list = %d %+v", code, list)
	}
	if code, _ := e.auditor.call("PUT", relayPath, nil, nil, nil); code != 403 {
		t.Fatalf("auditor marked a relay: %d", code)
	}

	// The team's view of its account says it relays; its admins can edit the
	// account but the mark stays, and they can't clear it.
	var sa apitypes.ServiceAccount
	if code := e.owner.get(saBase+"/"+fx.account.Id.String(), &sa); code != 200 || sa.RelayPlatform == nil || sa.RelayPlatform.Name != "Pi Durable Platform" {
		t.Fatalf("service account = %d %+v", code, sa)
	}
	sa = patchSA(t, e.owner, fx.account.Id.String(), map[string]any{"description": "relay for PDP", "role": "editor"})
	if sa.RelayPlatform == nil {
		t.Fatal("editing the account cleared the relay mark")
	}
	var relays []apitypes.AgentPlatformRelay
	if code := e.admin.get(base+"/"+fx.platformID+"/relays", &relays); code != 200 || len(relays) != 1 || relays[0].TeamSlug != "tools" || relays[0].Name != "pdp-relay" || relays[0].MarkedAt == nil {
		t.Fatalf("relays = %d %+v", code, relays)
	}
	// An unknown platform or account; clearing something that isn't a relay.
	for _, p := range []string{base + "/00000000-0000-0000-0000-000000000000/relays/" + fx.account.Id.String(), base + "/" + fx.platformID + "/relays/00000000-0000-0000-0000-000000000000"} {
		if code, ec := e.admin.call("PUT", p, nil, nil, nil); code != 404 {
			t.Errorf("PUT %s = %d %s", p, code, ec)
		}
	}
	other := newRelayIssuer(t, "https://second.example.test")
	otherID := fx.addPlatform("Second platform", other)
	if code, ec := e.admin.call("DELETE", base+"/"+otherID+"/relays/"+fx.account.Id.String(), nil, nil, nil); code != 404 || ec != "relay_not_found" {
		t.Fatalf("clearing another platform's relay = %d %s", code, ec)
	}
	// A disabled platform can't get new relays.
	var plat apitypes.AgentPlatform
	e.admin.get(base+"/"+otherID, &plat)
	if code, ec := e.admin.call("PATCH", base+"/"+otherID, map[string]any{"enabled": false}, &plat, ifMatch(plat.Revision)); code != 200 {
		t.Fatalf("disable = %d %s", code, ec)
	}
	if code, ec := e.admin.call("PUT", base+"/"+otherID+"/relays/"+fx.account.Id.String(), nil, nil, nil); code != 409 || ec != "platform_disabled" {
		t.Fatalf("relay for a disabled platform = %d %s", code, ec)
	}
	// Moving the account to the other platform (enabled again) and back.
	e.admin.get(base+"/"+otherID, &plat)
	e.admin.call("PATCH", base+"/"+otherID, map[string]any{"enabled": true}, &plat, ifMatch(plat.Revision))
	fx.mark(otherID, fx.account.Id.String())
	if code := e.owner.get(saBase+"/"+fx.account.Id.String(), &sa); code != 200 || sa.RelayPlatform == nil || sa.RelayPlatform.Name != "Second platform" {
		t.Fatalf("moved = %d %+v", code, sa.RelayPlatform)
	}
	// Validation and uniqueness.
	for name, body := range map[string]map[string]any{
		"an http issuer":     {"name": "n1", "issuer": "http://plain.example.test"},
		"a duplicate name":   {"name": "Second platform", "issuer": "https://dup-name.example.test"},
		"a duplicate issuer": {"name": "n2", "issuer": "https://second.example.test"},
		"unknown fields":     {"name": "n4", "issuer": "https://n4.example.test", "secret": "x"},
	} {
		if code, _ := e.admin.call("POST", base, body, nil, nil); code < 400 || code >= 500 {
			t.Errorf("%s = %d", name, code)
		}
	}
	// Clear, edit and delete, each audited; nothing secret is in any of it.
	if code, ec := e.admin.call("DELETE", base+"/"+otherID+"/relays/"+fx.account.Id.String(), nil, nil, nil); code != 200 {
		t.Fatalf("clear = %d %s", code, ec)
	}
	if code, ec := e.admin.call("DELETE", base+"/"+otherID, nil, nil, nil); code != 200 {
		t.Fatalf("delete = %d %s", code, ec)
	}
	actions := e.scalar(`SELECT string_agg(action, ',' ORDER BY id) FROM audit_log WHERE action LIKE 'agent_platform.%' OR action LIKE 'service_account.relay_%'`)
	for _, want := range []string{"agent_platform.create", "service_account.relay_set", "agent_platform.update", "service_account.relay_clear", "agent_platform.delete"} {
		if !strings.Contains(actions, want) {
			t.Errorf("audit lacks %s: %s", want, actions)
		}
	}
	if v := e.scalar(`SELECT actor_kind || ' ' || coalesce(team_id::text, '-') FROM audit_log WHERE action = 'service_account.relay_set' ORDER BY id LIMIT 1`); !strings.HasPrefix(v, "user ") || strings.HasSuffix(v, "-") {
		t.Fatalf("relay_set audit = %q (a person, on the account's team)", v)
	}
	// The team's own audit log shows the relay marking of its account.
	_, raw := e.owner.raw("GET", toolsTeam+"/audit?limit=50", nil, nil)
	if !strings.Contains(string(raw), "service_account.relay_set") {
		t.Fatalf("team audit = %s", raw)
	}
	fx.noSecrets(nil)
}
