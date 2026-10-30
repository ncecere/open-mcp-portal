package httpapi_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Server governance end to end (decision 88): what a gateway serves, what the
// API shows and who may change it.

func (e *gwEnv) govPatch(s *session, sv apitypes.McpServer, governance map[string]any) (int, string, apitypes.McpServer) {
	e.t.Helper()
	path := "/v1/teams/" + sv.TeamSlug + "/mcp-servers/" + sv.Id.String()
	var out apitypes.McpServer
	code, ec := s.call("PATCH", path, map[string]any{"governance": governance}, &out, ifMatch(e.revisionOf(sv)))
	return code, ec, out
}

func (e *gwEnv) patchGateway(s *session, path string, body map[string]any) (int, string) {
	e.t.Helper()
	var cur apitypes.Gateway
	if code := s.get(path, &cur); code != 200 {
		e.t.Fatalf("get gateway = %d", code)
	}
	return s.call("PATCH", path, body, nil, ifMatch(cur.Revision))
}

func reasons(items []apitypes.GatewayCapability) map[string]string {
	out := map[string]string{}
	for _, it := range items {
		r := ""
		if it.UnavailableReason != nil {
			r = string(*it.UnavailableReason)
		}
		out[it.ExposedName] = r
	}
	return out
}

// A server above a gateway's ceiling is listed as unavailable with the reason
// and is never served.
func TestGatewayCeilingNeverServesAboveIt(t *testing.T) {
	e := newGwEnv(t, nil)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	gwPath := toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(e.capID(e.owner, e.server, "tool", "echo"), e.capID(e.owner, e.server, "tool", "whoami")))
	key := newKey(t, e.member, "laptop")
	if gw.MaxSensitivity == nil || *gw.MaxSensitivity != "restricted" {
		t.Fatalf("default ceiling = %v", gw.MaxSensitivity)
	}
	cs := connect(t, e.app, "support", key.Secret)
	if got := toolNames(t, cs); !slices.Equal(got, []string{"status__echo", "status__whoami"}) {
		t.Fatalf("tools = %v", got)
	}
	// Label the server confidential (its team's admin), then lower the ceiling.
	if code, ec, out := e.govPatch(e.owner, e.server, map[string]any{"sensitivity": "confidential"}); code != 200 || out.Governance == nil || out.Governance.Sensitivity != "confidential" {
		t.Fatalf("label: %d %s", code, ec)
	}
	for _, ceiling := range []string{"internal", "public"} {
		if code, ec := e.patchGateway(e.owner, gwPath, map[string]any{"maxSensitivity": ceiling}); code != 200 {
			t.Fatalf("ceiling %s: %d %s", ceiling, code, ec)
		}
		cs = connect(t, e.app, "support", key.Secret)
		if got := toolNames(t, cs); len(got) != 0 {
			t.Fatalf("above a %s ceiling the gateway lists %v", ceiling, got)
		}
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__echo", Arguments: map[string]any{"text": "hi"}})
		if err == nil && !res.IsError {
			t.Fatalf("a call above the ceiling was served: %+v", res)
		}
		var caps apitypes.GatewayCapabilities
		if code := e.owner.get(gwPath+"/capabilities", &caps); code != 200 {
			t.Fatal(code)
		}
		for name, why := range reasons(caps.Items) {
			if why != "sensitivity_exceeds_gateway" {
				t.Errorf("%s: reason %q", name, why)
			}
		}
		if g := e.gateway(e.owner, gwPath); g.UnavailableCount != 2 || g.MaxSensitivity == nil || string(*g.MaxSensitivity) != ceiling {
			t.Errorf("gateway = %+v", g)
		}
	}
	if len(e.fake.ToolCalls()) != 0 {
		t.Errorf("the server saw %d calls", len(e.fake.ToolCalls()))
	}
	// Raising the ceiling to the label serves it again; an editor can't.
	if code, ec := e.patchGateway(e.editor, gwPath, map[string]any{"maxSensitivity": "confidential"}); code != 403 {
		t.Errorf("an editor set a ceiling: %d %s", code, ec)
	}
	if code, ec := e.patchGateway(e.owner, gwPath, map[string]any{"maxSensitivity": "confidential"}); code != 200 {
		t.Fatalf("ceiling: %d %s", code, ec)
	}
	cs = connect(t, e.app, "support", key.Secret)
	if got := toolNames(t, cs); !slices.Equal(got, []string{"status__echo", "status__whoami"}) {
		t.Fatalf("at the ceiling: %v", got)
	}
	// The audit trail names both changes.
	if e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'gateway.update' AND after_state->>'maxSensitivity' = 'public'`) != "1" ||
		e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.governance_update' AND after_state->>'sensitivity' = 'confidential'`) != "1" {
		t.Error("the changes are not audited")
	}
}

// A deprecated server shows a banner (its governance), is still served, and
// stops being served at its sunset date, with the reason.
func TestSunsetStopsServing(t *testing.T) {
	e := newGwEnv(t, nil)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	gwPath := toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(e.capID(e.owner, e.server, "tool", "echo")))
	key := newKey(t, e.member, "laptop")
	replacement := e.createServer(e.owner, "tools", "status-next", testutil.NewFakeMCP(t).URL(), nil)
	sunset := time.Now().Add(4 * time.Second).UTC().Truncate(time.Millisecond)
	code, ec, out := e.govPatch(e.owner, e.server, map[string]any{"lifecycle": "deprecated", "sunsetAt": sunset.Format(time.RFC3339Nano),
		"replacementServerId": replacement.Id.String()})
	if code != 200 {
		t.Fatalf("deprecate: %d %s", code, ec)
	}
	g := out.Governance
	if g == nil || g.Lifecycle != "deprecated" || g.DeprecatedAt == nil || g.SunsetAt == nil || g.Replacement == nil || g.Replacement.Slug != "status-next" {
		t.Fatalf("governance = %+v", g)
	}
	if code, ec, _ := e.govPatch(e.owner, e.server, map[string]any{"sunsetAt": time.Now().Add(-time.Hour).Format(time.RFC3339)}); code != 422 || ec != "sunset_in_past" {
		t.Errorf("a past date: %d %s", code, ec)
	}
	cs := connect(t, e.app, "support", key.Secret)
	if got := toolNames(t, cs); !slices.Equal(got, []string{"status__echo"}) {
		t.Fatalf("deprecated but served: %v", got)
	}
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__echo", Arguments: map[string]any{"text": "before"}}); err != nil || res.IsError {
		t.Fatalf("a call before the sunset: %v %+v", err, res)
	}
	// Until the date: no change anywhere else. After it: unavailable with the reason.
	time.Sleep(time.Until(sunset) + 300*time.Millisecond)
	cs = connect(t, e.app, "support", key.Secret)
	if got := toolNames(t, cs); len(got) != 0 {
		t.Fatalf("after the sunset the gateway lists %v", got)
	}
	calls := len(e.fake.ToolCalls())
	if res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__echo", Arguments: map[string]any{"text": "after"}}); err == nil && !res.IsError {
		t.Fatalf("a call after the sunset was served: %+v", res)
	}
	if len(e.fake.ToolCalls()) != calls {
		t.Error("the server saw a call after its sunset")
	}
	var caps apitypes.GatewayCapabilities
	if code := e.owner.get(gwPath+"/capabilities", &caps); code != 200 || reasons(caps.Items)["status__echo"] != "sunset" {
		t.Errorf("reason = %v (%d)", reasons(caps.Items), code)
	}
	if got := e.gateway(e.owner, gwPath); got.UnavailableCount != 1 {
		t.Errorf("unavailable = %d", got.UnavailableCount)
	}
	// The server's own view reports the effective lifecycle, and a team may bring it back.
	var sv apitypes.McpServer
	e.owner.get(toolsTeam+"/mcp-servers/"+e.server.Id.String(), &sv)
	if sv.Governance.Lifecycle != "sunset" {
		t.Errorf("lifecycle = %s", sv.Governance.Lifecycle)
	}
	if code, ec, _ := e.govPatch(e.owner, e.server, map[string]any{"lifecycle": "active"}); code != 200 {
		t.Fatalf("active again: %d %s", code, ec)
	}
	cs = connect(t, e.app, "support", key.Secret)
	if got := toolNames(t, cs); !slices.Equal(got, []string{"status__echo"}) {
		t.Errorf("after reactivation: %v", got)
	}
}

func TestGovernanceAPIRules(t *testing.T) {
	e := newGwEnv(t, nil)
	sv := e.server
	// Owners and admins; not an editor, a member, an outsider.
	for name, c := range map[string]struct {
		who  *session
		code int
		err  string
	}{"editor": {e.editor, 403, "governance_role"}, "member": {e.member, 403, "forbidden"}, "outsider": {e.outsider, 404, "team_not_found"}, "platform admin": {e.admin, 403, "forbidden"}} {
		if code, ec, _ := e.govPatch(c.who, sv, map[string]any{"sensitivity": "public"}); code != c.code || ec != c.err {
			t.Errorf("%s: %d %s", name, code, ec)
		}
	}
	// The creator is the owner; an owner is named, validated and cleared.
	var cur apitypes.McpServer
	e.owner.get(toolsTeam+"/mcp-servers/"+sv.Id.String(), &cur)
	if cur.Governance == nil || cur.Governance.OwnerName == nil || cur.Governance.Ownerless || cur.Governance.Sensitivity != "internal" || cur.Governance.Lifecycle != "active" {
		t.Fatalf("a new server's governance = %+v", cur.Governance)
	}
	editorID := e.userID("alex@localhost")
	code, ec, out := e.govPatch(e.owner, sv, map[string]any{"ownerUserId": editorID, "oncallContact": "oncall@example.com"})
	if code != 200 || out.Governance.OwnerUserId == nil || out.Governance.OwnerUserId.String() != editorID || out.Governance.OncallContact == nil {
		t.Fatalf("name an owner: %d %s %+v", code, ec, out.Governance)
	}
	if code, ec, _ := e.govPatch(e.owner, sv, map[string]any{"ownerUserId": e.userID("blair@localhost")}); code != 422 || ec != "invalid_owner" {
		t.Errorf("a member as owner: %d %s", code, ec)
	}
	for _, bad := range []string{"javascript:alert(1)", "two words", strings.Repeat("x", 201)} {
		if code, ec, _ := e.govPatch(e.owner, sv, map[string]any{"oncallContact": bad}); code != 422 && code != 400 {
			t.Errorf("on-call %q: %d %s", bad, code, ec)
		}
	}
	if code, ec, _ := e.govPatch(e.owner, sv, map[string]any{"sensitivity": "secret"}); code != 400 {
		t.Errorf("a label that is not one: %d %s", code, ec)
	}
	if code, ec, out := e.govPatch(e.owner, sv, map[string]any{"ownerUserId": nil, "oncallContact": nil}); code != 200 || !out.Governance.Ownerless || out.Governance.OncallContact != nil {
		t.Errorf("clear: %d %s %+v", code, ec, out.Governance)
	}
	// A stale revision changes nothing.
	path := toolsTeam + "/mcp-servers/" + sv.Id.String()
	code, ec = e.owner.call("PATCH", path, map[string]any{"governance": map[string]any{"sensitivity": "public"}}, nil, ifMatch(1))
	if code != 412 {
		t.Errorf("stale: %d %s", code, ec)
	}
	// A null object and a body without governance.
	if code, _ := e.owner.raw("PATCH", path, map[string]any{"governance": nil}, ifMatch(e.revisionOf(sv))); code != 400 {
		t.Errorf("null governance: %d", code)
	}

	// Raising the sensitivity of a published server sends it back to review;
	// lowering does not; the reviewer's digest moves with it.
	e.publish(e.owner, sv)
	var pub apitypes.McpServer
	e.owner.get(path, &pub)
	if pub.PublishState != "published" {
		t.Fatalf("state = %s", pub.PublishState)
	}
	code, ec, out = e.govPatch(e.owner, sv, map[string]any{"sensitivity": "public"})
	if code != 200 || out.PublishState != "published" || out.ReviewDigest == nil || *out.ReviewDigest == *pub.ReviewDigest {
		t.Fatalf("lower: %d %s %s", code, ec, out.PublishState)
	}
	code, ec, out = e.govPatch(e.owner, sv, map[string]any{"sensitivity": "restricted"})
	if code != 200 || out.PublishState != "pending" || out.Governance.Sensitivity != "restricted" {
		t.Fatalf("raise: %d %s %s", code, ec, out.PublishState)
	}
	if e.scalar(`SELECT count(*)::text FROM notification_events WHERE event = 'publish.requested' AND payload->>'reason' = 'sensitivity_raised'`) != "1" {
		t.Error("the platform's admins were not told why")
	}
	// The catalog and its detail show the label, never the owner or contact.
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+sv.Id.String()+"/review", approveBody(t, e.admin, sv.Id.String()), nil, nil); code != 200 {
		t.Fatalf("approve: %d %s", code, ec)
	}
	code, ec, _ = e.govPatch(e.owner, sv, map[string]any{"ownerUserId": editorID, "oncallContact": "#secret-oncall"})
	if code != 200 {
		t.Fatalf("%d %s", code, ec)
	}
	code, raw := e.outsider.raw("GET", "/v1/catalog/servers/"+sv.Id.String(), nil, nil)
	if code != 200 || !strings.Contains(string(raw), `"sensitivity":"restricted"`) || strings.Contains(string(raw), "secret-oncall") || strings.Contains(string(raw), "ownerUserId") || strings.Contains(string(raw), "ownerName") {
		t.Errorf("catalog detail: %d %s", code, raw)
	}
	code, raw = e.outsider.raw("GET", "/v1/catalog/servers", nil, nil)
	if code != 200 || strings.Contains(string(raw), "secret-oncall") || strings.Contains(string(raw), "ownerName") {
		t.Errorf("catalog list: %d %s", code, raw)
	}
}

func (e *gwEnv) revisionOf(sv apitypes.McpServer) int64 {
	var cur apitypes.McpServer
	e.owner.get("/v1/teams/"+sv.TeamSlug+"/mcp-servers/"+sv.Id.String(), &cur)
	return cur.Revision
}

// The platform's governance settings: validated, revisioned, audited, admins only.
func TestGovernanceSettingsAPI(t *testing.T) {
	e := newGwEnv(t, nil)
	var cur apitypes.GovernanceSettings
	if code := e.admin.get("/v1/admin/settings/governance", &cur); code != 200 || cur.ReviewIntervalDays.Restricted != 90 || cur.ReturnOverdueToReview || cur.Revision != 1 {
		t.Fatalf("defaults: %d %+v", code, cur)
	}
	if code := e.auditor.get("/v1/admin/settings/governance", nil); code != 200 {
		t.Errorf("auditor read: %d", code)
	}
	if code := e.owner.get("/v1/admin/settings/governance", nil); code != 403 {
		t.Errorf("team owner read: %d", code)
	}
	body := map[string]any{"reviewIntervalDays": map[string]any{"internal": 30, "restricted": 14}, "returnOverdueToReview": true}
	if code, ec := e.auditor.call("PUT", "/v1/admin/settings/governance", body, nil, ifMatch(1)); code != 403 {
		t.Errorf("auditor write: %d %s", code, ec)
	}
	if code, ec := e.admin.call("PUT", "/v1/admin/settings/governance", map[string]any{"reviewIntervalDays": map[string]any{"internal": 99999}}, nil, ifMatch(1)); code != 400 && code != 422 {
		t.Errorf("a 99999-day interval: %d %s", code, ec)
	}
	if code, _ := e.admin.call("PUT", "/v1/admin/settings/governance", body, nil, ifMatch(9)); code != 412 {
		t.Errorf("stale: %d", code)
	}
	var out apitypes.GovernanceSettings
	if code, ec := e.admin.call("PUT", "/v1/admin/settings/governance", body, &out, ifMatch(1)); code != 200 || out.Revision != 2 || out.ReviewIntervalDays.Internal != 30 ||
		out.ReviewIntervalDays.Restricted != 14 || out.ReviewIntervalDays.Confidential != 180 || !out.ReturnOverdueToReview {
		t.Fatalf("update: %d %s %+v", code, ec, out)
	}
	if e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'settings.governance_update'`) != "1" {
		t.Error("not audited")
	}
	// The publishing policy's revision did not move with it.
	var ps apitypes.PublishingSettings
	if e.admin.get("/v1/admin/settings/publishing", &ps); ps.Revision != 1 {
		t.Errorf("publishing revision = %d", ps.Revision)
	}
}

// A cross-team transfer needs the receiving team's owner, keeps what is bound
// to the server and sends it back to review; a gateway keeps serving it once
// it is approved again, with its sealed credential.
func TestTransferKeepsGrantsGatewaysAndSealedSecrets(t *testing.T) {
	e := newGwEnv(t, nil)
	fake := testutil.NewFakeMCP(t)
	fake.EnableGatewayTools()
	fake.RequireHeader("X-Api-Key", "sealed-1234567890")
	sv := e.createServer(e.owner, "tools", "secured", fake.URL(), map[string]any{"authHeaderName": "X-Api-Key", "authValue": "sealed-1234567890"})
	e.publish(e.owner, sv)
	shared := e.createGateway(e.admin, "/v1/admin/gateways", "shared")
	sharedPath := "/v1/admin/gateways/" + shared.Id.String()
	e.mustSetCaps(e.admin, sharedPath, sel(e.capID(e.owner, sv, "tool", "echo")))
	if code, ec := e.admin.call("POST", sharedPath+"/grants", map[string]any{"subjectKind": "team", "team": "tools"}, nil, nil); code != 201 {
		t.Fatalf("grant: %d %s", code, ec)
	}
	key := newKey(t, e.member, "laptop")
	serve := func() []string { return toolNames(t, connect(t, e.app, "shared", key.Secret)) }
	if got := serve(); !slices.Equal(got, []string{"secured__echo"}) {
		t.Fatalf("before: %v", got)
	}
	call := func() error {
		res, err := connect(t, e.app, "shared", key.Secret).CallTool(context.Background(), &mcp.CallToolParams{Name: "secured__echo", Arguments: map[string]any{"text": "hi"}})
		if err == nil && res.IsError {
			return context.DeadlineExceeded
		}
		return err
	}
	if err := call(); err != nil {
		t.Fatalf("a call before the transfer: %v", err)
	}
	counts := func() string {
		return e.scalar(`SELECT (SELECT count(*) FROM gateway_capabilities) || '/' || (SELECT count(*) FROM gateway_grants) || '/' || (SELECT md5(auth_value_cipher::text) FROM mcp_servers WHERE id = $1)`, sv.Id)
	}
	before := counts()

	base := toolsTeam + "/mcp-servers/" + sv.Id.String() + "/transfer"
	if code, ec := e.editor.call("POST", base, map[string]any{"toTeam": "other"}, nil, nil); code != 403 {
		t.Errorf("an editor offered it: %d %s", code, ec)
	}
	if code, ec := e.owner.call("POST", base, map[string]any{"toTeam": "nowhere"}, nil, nil); code != 422 || ec != "invalid_team" {
		t.Errorf("unknown team: %d %s", code, ec)
	}
	var tr apitypes.ServerTransfer
	if code, ec := e.owner.call("POST", base, map[string]any{"toTeam": "other", "note": "yours now"}, &tr, nil); code != 201 || tr.State != "pending" || tr.ToTeamSlug != "other" {
		t.Fatalf("request: %d %s %+v", code, ec, tr)
	}
	if code, ec := e.owner.call("POST", base, map[string]any{"toTeam": "other"}, nil, nil); code != 409 || ec != "transfer_pending" {
		t.Errorf("twice: %d %s", code, ec)
	}
	var cur apitypes.McpServer
	e.owner.get(toolsTeam+"/mcp-servers/"+sv.Id.String(), &cur)
	if cur.Governance.PendingTransfer == nil || cur.Governance.PendingTransfer.Id != tr.Id {
		t.Errorf("the server does not show its transfer: %+v", cur.Governance.PendingTransfer)
	}
	// The receiving team sees it; only its owner answers.
	var list []apitypes.ServerTransfer
	if code := e.outsider.get("/v1/teams/other/mcp-server-transfers?pendingOnly=true", &list); code != 200 || len(list) != 1 || list[0].Id != tr.Id {
		t.Fatalf("the receiving team's list: %d %+v", code, list)
	}
	acceptPath := "/v1/teams/other/mcp-server-transfers/" + tr.Id.String() + "/accept"
	if code, ec := e.owner.call("POST", acceptPath, nil, nil, ifMatch(1)); code != 404 {
		t.Errorf("the offering owner accepted: %d %s", code, ec)
	}
	if code, ec := e.outsider.call("POST", acceptPath, nil, nil, nil); code != 428 {
		t.Errorf("accept without a revision: %d %s", code, ec)
	}
	if e.scalar(`SELECT team_id::text FROM mcp_servers WHERE id = $1`, sv.Id) == e.scalar(`SELECT id::text FROM teams WHERE slug = 'other'`) {
		t.Fatal("it moved before it was accepted")
	}
	var done apitypes.ServerTransfer
	if code, ec := e.outsider.call("POST", acceptPath, nil, &done, ifMatch(1)); code != 200 || done.State != "accepted" {
		t.Fatalf("accept: %d %s %+v", code, ec, done)
	}
	var moved apitypes.McpServer
	if code := e.outsider.get("/v1/teams/other/mcp-servers/"+sv.Id.String(), &moved); code != 200 || moved.PublishState != "pending" || moved.Governance.Ownerless {
		t.Fatalf("after: %d state %s %+v", code, moved.PublishState, moved.Governance)
	}
	if code := e.owner.get(toolsTeam+"/mcp-servers/"+sv.Id.String(), nil); code != 404 {
		t.Errorf("the old team still sees it: %d", code)
	}
	// While it is back in review the catalog gateway does not serve it...
	if got := serve(); len(got) != 0 {
		t.Errorf("served while in review: %v", got)
	}
	// ...and nothing bound to it was touched.
	if after := counts(); after != before {
		t.Errorf("selections, grants, sealed header: %s -> %s", before, after)
	}
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+sv.Id.String()+"/review", approveBody(t, e.admin, sv.Id.String()), nil, nil); code != 200 {
		t.Fatalf("approve: %d %s", code, ec)
	}
	if got := serve(); !slices.Equal(got, []string{"secured__echo"}) {
		t.Fatalf("after approval: %v", got)
	}
	if err := call(); err != nil {
		t.Fatalf("a call with the sealed credential after the transfer: %v", err)
	}
	if code, ec := e.outsider.call("POST", acceptPath, nil, nil, ifMatch(2)); code != 409 || ec != "transfer_closed" {
		t.Errorf("accepting twice: %d %s", code, ec)
	}
	// A platform admin moves a server without the receiving team's say.
	var forced apitypes.McpServer
	if code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+sv.Id.String()+"/transfer", map[string]any{"toTeam": "tools"}, &forced, ifMatch(e.outsiderRevision(sv))); code != 200 ||
		forced.TeamSlug != "tools" || !forced.Governance.Ownerless {
		t.Fatalf("force: %d %s %+v", code, ec, forced.Governance)
	}
	if code, _ := e.owner.call("POST", "/v1/admin/mcp-servers/"+sv.Id.String()+"/transfer", map[string]any{"toTeam": "other"}, nil, ifMatch(forced.Revision)); code != 403 {
		t.Errorf("a team owner forced: %d", code)
	}
}

func (e *gwEnv) outsiderRevision(sv apitypes.McpServer) int64 {
	var cur apitypes.McpServer
	e.outsider.get("/v1/teams/other/mcp-servers/"+sv.Id.String(), &cur)
	return cur.Revision
}
