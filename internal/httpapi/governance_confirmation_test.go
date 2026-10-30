package httpapi_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// The sensitivity confirmation over HTTP (decision 88): `sensitivityConfirmed`
// is an optional, read-only field of the team and platform view of a server's
// governance; only an owner's or admin's browser session sending `sensitivity`
// sets it, also with the value the server already has; and it is bookkeeping
// that never changes what a gateway serves.

// The field is optional in the contract (and has no default), so a client that
// predates it, and every fixture that omits it, stays valid.
func TestSensitivityConfirmedIsAnOptionalContractField(t *testing.T) {
	doc, err := openapi3.NewLoader().LoadFromFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	gov := doc.Components.Schemas["McpServerGovernance"].Value
	prop := gov.Properties["sensitivityConfirmed"]
	if prop == nil || prop.Value.Type == nil || !prop.Value.Type.Is("boolean") || prop.Value.Default != nil || prop.Value.Nullable {
		t.Fatalf("sensitivityConfirmed = %+v", prop)
	}
	if slices.Contains(gov.Required, "sensitivityConfirmed") {
		t.Error("sensitivityConfirmed is required in the contract")
	}
	for _, name := range []string{"McpServerGovernanceInput", "CatalogServerGovernance"} {
		if _, ok := doc.Components.Schemas[name].Value.Properties["sensitivityConfirmed"]; ok {
			t.Errorf("%s carries the read-only marker", name)
		}
	}
	// Both with and without the field a governance object satisfies the schema.
	for name, v := range map[string]map[string]any{
		"with it":    {"sensitivity": "internal", "lifecycle": "active", "ownerless": true, "reviewOverdue": false, "sensitivityConfirmed": false},
		"without it": {"sensitivity": "internal", "lifecycle": "active", "ownerless": true, "reviewOverdue": false},
	} {
		if err := gov.VisitJSON(v); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := gov.VisitJSON(map[string]any{"sensitivity": "internal", "lifecycle": "active", "ownerless": true, "reviewOverdue": false, "sensitivityConfirmed": "yes"}); err == nil {
		t.Error("a non-boolean marker satisfies the contract")
	}
	kinds := doc.Components.Schemas["AttentionKind"].Value.Enum
	if !slices.Contains(kinds, any("server_unlabelled")) {
		t.Errorf("AttentionKind lacks server_unlabelled: %v", kinds)
	}
}

type govJSON struct {
	Governance map[string]any `json:"governance"`
	Revision   int64          `json:"revision"`
}

func (e *gwEnv) govRaw(s *session, sv apitypes.McpServer, path string) (int, govJSON, []byte) {
	e.t.Helper()
	code, raw := s.raw("GET", "/v1/teams/"+sv.TeamSlug+"/mcp-servers/"+sv.Id.String()+path, nil, nil)
	var out govJSON
	_ = json.Unmarshal(raw, &struct {
		Data *govJSON `json:"data"`
	}{&out})
	return code, out, raw
}

func (e *gwEnv) confirmedColumn(sv apitypes.McpServer) string {
	return e.scalar(`SELECT (sensitivity_confirmed_at IS NOT NULL)::text FROM mcp_servers WHERE id = $1`, sv.Id)
}

func (e *gwEnv) unlabelledItems(s *session, path string) (items []apitypes.AttentionItem, total int64) {
	e.t.Helper()
	var out apitypes.TeamAttention // the platform overview has the same attention and totals
	if c := s.get(path, &out); c != 200 {
		e.t.Fatalf("%s = %d", path, c)
	}
	for _, it := range out.Attention {
		if it.Kind == apitypes.AttentionKindServerUnlabelled {
			items = append(items, it)
		}
	}
	return items, out.Totals["server_unlabelled"]
}

func TestSensitivityConfirmationAPI(t *testing.T) {
	e := newGwEnv(t, nil)
	sv := e.server
	path := toolsTeam + "/mcp-servers/" + sv.Id.String()
	e.publish(e.owner, sv)

	// A server nobody confirmed: the field is present and false, in the team's
	// view; the catalog never shows it.
	code, g, raw := e.govRaw(e.owner, sv, "")
	if code != 200 || g.Governance["sensitivityConfirmed"] != false || g.Governance["sensitivity"] != "internal" || e.confirmedColumn(sv) != "false" {
		t.Fatalf("unconfirmed: %d %s", code, raw)
	}
	if code, raw := e.outsider.raw("GET", "/v1/catalog/servers/"+sv.Id.String(), nil, nil); code != 200 || json.Valid(raw) && containsKey(raw, "sensitivityConfirmed") {
		t.Errorf("the catalog shows the marker: %d %s", code, raw)
	}
	// Published and unconfirmed: listed for the platform and for the team, with a
	// link to the server page; nothing else about the server changed.
	var adminItems, teamItems []apitypes.AttentionItem
	var adminTotal, teamTotal int64
	adminItems, adminTotal = e.unlabelledItems(e.admin, "/v1/admin/overview")
	teamItems, teamTotal = e.unlabelledItems(e.owner, toolsTeam+"/attention")
	for name, items := range map[string][]apitypes.AttentionItem{"admin": adminItems, "team": teamItems} {
		var found *apitypes.AttentionItem
		for i, it := range items {
			if it.Subject != nil && it.Subject.Id == sv.Id.String() {
				found = &items[i]
			}
		}
		if found == nil || found.Severity != apitypes.Info || found.Link == nil || found.Link.Id == nil || *found.Link.Id != sv.Id.String() {
			t.Fatalf("%s attention: %+v", name, items)
		}
	}
	if adminTotal < 1 || teamTotal != int64(len(teamItems)) || teamTotal < 1 {
		t.Errorf("totals: admin %d, team %d (%d listed)", adminTotal, teamTotal, len(teamItems))
	}

	// What does not confirm: ordinary edits, other governance fields, an empty
	// governance object, a refused role and a stale revision.
	rev := e.revisionOf(sv)
	patch := func(s *session, body map[string]any, rev int64) (int, string) {
		return s.call("PATCH", path, body, nil, ifMatch(rev))
	}
	for name, body := range map[string]map[string]any{
		"the description":   {"description": "changed by hand"},
		"the owner":         {"governance": map[string]any{"ownerUserId": e.userID("alex@localhost")}},
		"the on-call":       {"governance": map[string]any{"oncallContact": "#ops"}},
		"the lifecycle":     {"governance": map[string]any{"lifecycle": "deprecated"}},
		"an empty object":   {"governance": map[string]any{}},
		"no sensitivity":    {"governance": map[string]any{"lifecycle": "active"}},
		"enabled unchanged": {"enabled": true},
	} {
		if c, ec := patch(e.owner, body, e.revisionOf(sv)); c != 200 {
			t.Fatalf("%s: %d %s", name, c, ec)
		}
		if e.confirmedColumn(sv) != "false" {
			t.Fatalf("%s confirmed the label", name)
		}
	}
	for name, c := range map[string]struct {
		who  *session
		code int
	}{"an editor": {e.editor, 403}, "a member": {e.member, 403}, "an outsider": {e.outsider, 404}, "a platform admin outside the team": {e.admin, 403}} {
		if code, ec := patch(c.who, map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, e.revisionOf(sv)); code != c.code {
			t.Errorf("%s: %d %s", name, code, ec)
		}
		if e.confirmedColumn(sv) != "false" {
			t.Fatalf("%s confirmed the label", name)
		}
	}
	stale := e.revisionOf(sv) - 1
	if code, ec := patch(e.owner, map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, stale); code != 412 {
		t.Errorf("stale: %d %s", code, ec)
	}
	if e.confirmedColumn(sv) != "false" {
		t.Fatal("a stale revision confirmed the label")
	}

	// The explicit confirmation, with the label the server already has.
	rev = e.revisionOf(sv)
	audits := func() string {
		return e.scalar(`SELECT count(*)::text FROM audit_log WHERE action = 'mcp_server.governance_update' AND target_id = $1
			AND before_state->>'sensitivity' = 'internal' AND after_state->>'sensitivity' = 'internal'
			AND before_state->>'sensitivityConfirmed' = 'false' AND after_state->>'sensitivityConfirmed' = 'true'`, sv.Id.String())
	}
	var out apitypes.McpServer
	if c, ec := e.owner.call("PATCH", path, map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, &out, ifMatch(rev)); c != 200 {
		t.Fatalf("confirm: %d %s", c, ec)
	}
	if out.Governance == nil || out.Governance.SensitivityConfirmed == nil || !*out.Governance.SensitivityConfirmed || out.Governance.Sensitivity != "internal" ||
		out.Revision != rev+1 || out.PublishState != "published" || e.confirmedColumn(sv) != "true" || audits() != "1" {
		t.Fatalf("confirmed: %+v revision %d -> %d audits %s", out.Governance, rev, out.Revision, audits())
	}
	if code, g, raw := e.govRaw(e.owner, sv, ""); code != 200 || g.Governance["sensitivityConfirmed"] != true {
		t.Errorf("read back: %d %s", code, raw)
	}
	// Confirming again, with the new revision: accepted and unchanged.
	var again apitypes.McpServer
	if c, ec := e.owner.call("PATCH", path, map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, &again, ifMatch(out.Revision)); c != 200 {
		t.Fatalf("confirm again: %d %s", c, ec)
	}
	if again.Revision != out.Revision || audits() != "1" {
		t.Errorf("a repeated confirmation mutated: revision %d -> %d, audits %s", out.Revision, again.Revision, audits())
	}
	// A confirmed internal label is legitimate: gone from both lists.
	if items, total := e.unlabelledItems(e.admin, "/v1/admin/overview"); total != adminTotal-1 || len(items) != len(adminItems)-1 {
		t.Errorf("admin after confirming: %d listed, total %d (was %d)", len(items), total, adminTotal)
	}
	if items, total := e.unlabelledItems(e.owner, toolsTeam+"/attention"); total != teamTotal-1 || len(items) != len(teamItems)-1 {
		t.Errorf("team after confirming: %d listed, total %d (was %d)", len(items), total, teamTotal)
	}
	// A later explicit label keeps it confirmed.
	if c, ec := patch(e.owner, map[string]any{"governance": map[string]any{"sensitivity": "public"}}, again.Revision); c != 200 || e.confirmedColumn(sv) != "true" {
		t.Errorf("a later label: %d %s", c, ec)
	}
}

func containsKey(raw []byte, key string) bool {
	var walk func(v any) bool
	walk = func(v any) bool {
		switch x := v.(type) {
		case map[string]any:
			for k, c := range x {
				if k == key || walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	var v any
	return json.Unmarshal(raw, &v) == nil && walk(v)
}

// The marker is not a gateway rule: the same tools are served and the same
// ones are refused above a ceiling before and after a confirmation.
func TestSensitivityConfirmationDoesNotChangeWhatIsServed(t *testing.T) {
	e := newGwEnv(t, nil)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "support")
	gwPath := toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, gwPath, sel(e.capID(e.owner, e.server, "tool", "echo"), e.capID(e.owner, e.server, "tool", "whoami")))
	key := newKey(t, e.member, "laptop")
	served := func() []string { return toolNames(t, connect(t, e.app, "support", key.Secret)) }
	want := []string{"status__echo", "status__whoami"}
	if got := served(); !slices.Equal(got, want) || e.confirmedColumn(e.server) != "false" {
		t.Fatalf("unconfirmed default label: %v", got)
	}
	if code, ec, _ := e.govPatch(e.owner, e.server, map[string]any{"sensitivity": "internal"}); code != 200 || e.confirmedColumn(e.server) != "true" {
		t.Fatalf("confirm: %d %s", code, ec)
	}
	if got := served(); !slices.Equal(got, want) {
		t.Fatalf("confirmed: %v", got)
	}
	// A ceiling below the label refuses it, confirmed or not.
	if code, ec := e.patchGateway(e.owner, gwPath, map[string]any{"maxSensitivity": "public"}); code != 200 {
		t.Fatalf("ceiling: %d %s", code, ec)
	}
	if got := served(); len(got) != 0 {
		t.Errorf("a confirmed server above the ceiling is served: %v", got)
	}
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE mcp_servers SET sensitivity_confirmed_at = NULL WHERE id = $1`, e.server.Id); err != nil {
		t.Fatal(err)
	}
	if got := served(); len(got) != 0 {
		t.Errorf("an unconfirmed server above the ceiling is served: %v", got)
	}
	if code, ec := e.patchGateway(e.owner, gwPath, map[string]any{"maxSensitivity": "internal"}); code != 200 {
		t.Fatalf("ceiling: %d %s", code, ec)
	}
	if got := served(); !slices.Equal(got, want) {
		t.Errorf("an unconfirmed server at its ceiling is not served: %v", got)
	}
}

// An automation token never confirms a label (it sends no governance at all),
// and its ordinary edits and registrations leave the marker alone.
func TestTokenCannotConfirmSensitivity(t *testing.T) {
	e := newMatrixEnv(t)
	creds := map[string]tokenCred{}
	for _, c := range e.tokenCreds() {
		creds[c.name] = c
	}
	pub := creds["publisher-write"]
	srv := e.newServer(e.b, "private")
	path := "/v1/teams/bravo/mcp-servers/" + srv
	rev := func() map[string]string {
		return map[string]string{"If-Match": `"` + e.exec(`SELECT revision::text FROM mcp_servers WHERE id = $1`, srv) + `"`}
	}
	marker := func() string {
		return e.exec(`SELECT (sensitivity_confirmed_at IS NOT NULL)::text FROM mcp_servers WHERE id = $1`, srv)
	}
	for name, gov := range map[string]map[string]any{"the label it has": {"sensitivity": "internal"}, "another label": {"sensitivity": "restricted"}, "an empty object": {}} {
		if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"governance": gov}).h(rev())); code != 403 || !strings.Contains(string(body), "token_not_allowed") {
			t.Errorf("a token sending %s: %d %s", name, code, body)
		}
		if marker() != "false" {
			t.Fatalf("a token sending %s confirmed the label", name)
		}
	}
	if code, _, body := e.bearer(pub.secret, patch(path, map[string]any{"description": "by token"}).h(rev())); code != 200 || marker() != "false" {
		t.Errorf("a token's ordinary edit: %d %s (marker %s)", code, body, marker())
	}
	// A person can, in a browser session; the token's own edits stay unconfirmed until then.
	if code, _ := e.callers[cOwner].raw("PATCH", path, map[string]any{"governance": map[string]any{"sensitivity": "internal"}}, rev()); code != 200 || marker() != "true" {
		t.Errorf("an owner's confirmation: %d (marker %s)", code, marker())
	}
}
