package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestToolClassificationValidationAndAtomicity(t *testing.T) {
	e := newRegistryEnv(t)
	sv := e.create(map[string]any{"slug": "status", "name": "Status", "url": e.fake.URL()}).Server
	id := sv.Id.String()
	base := toolsTeam + "/mcp-servers/" + id
	caps := e.capabilities(e.owner, id)
	tool := caps["check_outage"]
	path := base + "/capabilities/" + tool.Id.String() + "/class"
	for _, tc := range []struct {
		s      *session
		status int
		code   string
	}{
		{e.editor, 403, "forbidden"}, {e.member, 403, "forbidden"}, {e.outsider, 404, "team_not_found"}, {e.admin, 403, "forbidden"}, {e.auditor, 403, "forbidden"},
	} {
		code, ec := tc.s.call("PUT", path, map[string]any{"toolClass": "read"}, nil, ifMatch(sv.Revision))
		mustCode(t, "role", code, ec, tc.status, tc.code)
	}
	for _, tc := range []struct {
		body    any
		headers map[string]string
		status  int
		code    string
	}{
		{map[string]any{"toolClass": "read"}, nil, 428, "revision_required"},
		{map[string]any{"toolClass": "read"}, ifMatch(sv.Revision + 5), 412, "revision_conflict"},
		{map[string]any{}, ifMatch(sv.Revision), 400, "invalid_tool_class"},
		{map[string]any{"toolClass": "invalid"}, ifMatch(sv.Revision), 400, "invalid_tool_class"},
		{map[string]any{"toolClass": true}, ifMatch(sv.Revision), 400, "invalid_tool_class"},
		{map[string]any{"toolClass": "read", "viaSuggestion": true}, ifMatch(sv.Revision), 409, "suggestion_changed"},
	} {
		code, ec := e.owner.call("PUT", path, tc.body, nil, tc.headers)
		mustCode(t, "validation", code, ec, tc.status, tc.code)
	}
	if tool.ToolClass != nil || tool.SuggestedClass == nil || *tool.SuggestedClass != "destructive" || tool.ClassDrift {
		t.Fatalf("initial %+v", tool)
	}
	prompt := caps["incident_summary"]
	if prompt.SuggestedClass != nil || prompt.ToolClass != nil || prompt.ClassDrift {
		t.Fatalf("prompt %+v", prompt)
	}
	set := func(class any, via bool) apitypes.McpCapability {
		t.Helper()
		var c apitypes.McpCapability
		before := e.server(e.owner, id).Revision
		code, ec := e.owner.call("PUT", path, map[string]any{"toolClass": class, "viaSuggestion": via}, &c, ifMatch(before))
		mustCode(t, "classify", code, ec, 200, "")
		if got := e.server(e.owner, id).Revision; got != before+1 {
			t.Fatalf("revision %d -> %d", before, got)
		}
		if c.Fingerprint != tool.Fingerprint {
			t.Fatal("classification changed fingerprint")
		}
		a, _ := json.Marshal(c.Definition)
		b, _ := json.Marshal(tool.Definition)
		if string(a) != string(b) {
			t.Fatal("classification changed definition")
		}
		return c
	}
	c := set("destructive", true)
	if c.ToolClass == nil || *c.ToolClass != "destructive" || c.ClassDrift {
		t.Fatalf("set %+v", c)
	}
	if got := e.scalar(`SELECT (class_set_by IS NOT NULL AND class_set_at IS NOT NULL)::text FROM mcp_capabilities WHERE id=$1`, tool.Id); got != "true" {
		t.Fatalf("metadata %s", got)
	}
	c = set("read", false)
	if !c.ClassDrift {
		t.Fatal("expected drift")
	}
	if got := e.scalar(`SELECT metadata->>'viaSuggestion' FROM audit_log WHERE action='mcp_capability.class_set' ORDER BY id DESC LIMIT 1`); got != "false" {
		t.Fatalf("audit %s", got)
	}
	other := e.create(map[string]any{"slug": "another", "name": "Another", "url": e.fake.URL()}).Server
	foreign := e.capabilities(e.owner, other.Id.String())["check_outage"]
	// Invalid batches roll back both classification and audit, and don't bump revision.
	rev := e.server(e.owner, id).Revision
	audits := e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='mcp_capability.class_set'`)
	first := map[string]any{"capabilityId": tool.Id, "toolClass": "write"}
	for _, tc := range []struct {
		items  []any
		status int
		code   string
	}{
		{[]any{}, 400, "invalid_items"},
		{[]any{first, first}, 400, "duplicate_capability"},
		{[]any{first, map[string]any{"capabilityId": prompt.Id, "toolClass": "read"}}, 400, "not_a_tool"},
		{[]any{first, map[string]any{"capabilityId": uuid.New(), "toolClass": "read"}}, 404, "mcp_capability_not_found"},
		{[]any{first, map[string]any{"capabilityId": foreign.Id, "toolClass": "read"}}, 404, "mcp_capability_not_found"},
		{[]any{first, map[string]any{"capabilityId": caps["create_ticket"].Id}}, 400, "invalid_tool_class"},
	} {
		code, ec := e.owner.call("PUT", base+"/capabilities/classes", map[string]any{"items": tc.items}, nil, ifMatch(rev))
		mustCode(t, "atomic", code, ec, tc.status, tc.code)
		if e.server(e.owner, id).Revision != rev || e.scalar(`SELECT count(*)::text FROM audit_log WHERE action='mcp_capability.class_set'`) != audits {
			t.Fatal("failed batch changed revision/audit")
		}
		if got := e.capabilities(e.owner, id)["check_outage"].ToolClass; got == nil || *got != "read" {
			t.Fatal("failed batch changed class")
		}
	}
	large := make([]any, 501)
	for i := range large {
		large[i] = map[string]any{"capabilityId": uuid.New(), "toolClass": "read"}
	}
	code, ec := e.owner.call("PUT", base+"/capabilities/classes", map[string]any{"items": large}, nil, ifMatch(rev))
	mustCode(t, "limit", code, ec, 400, "invalid_items")
	var batch []apitypes.McpCapability
	code, ec = e.owner.call("PUT", base+"/capabilities/classes", map[string]any{"items": []any{first, map[string]any{"capabilityId": caps["create_ticket"].Id, "toolClass": "destructive", "viaSuggestion": true}}}, &batch, ifMatch(rev))
	mustCode(t, "bulk", code, ec, 200, "")
	if len(batch) != 2 || batch[0].Id != tool.Id || batch[1].Name != "create_ticket" || e.server(e.owner, id).Revision != rev+1 {
		t.Fatalf("bulk %+v", batch)
	}
	c = set(nil, false)
	if c.ToolClass != nil || c.ClassDrift || e.scalar(`SELECT (class_set_by IS NULL AND class_set_at IS NULL)::text FROM mcp_capabilities WHERE id=$1`, tool.Id) != "true" {
		t.Fatal("clear didn't clear metadata")
	}
	// Archived teams remain readable, but cannot classify.
	_, err := e.app.Pool.Exec(context.Background(), `UPDATE teams SET status='archived' WHERE slug='tools'`)
	if err != nil {
		t.Fatal(err)
	}
	code, ec = e.owner.call("PUT", path, map[string]any{"toolClass": "read"}, nil, ifMatch(e.server(e.owner, id).Revision))
	mustCode(t, "archived", code, ec, 409, "team_archived")
}

func TestToolClassificationRefreshAndReview(t *testing.T) {
	e := newRegistryEnv(t)
	e.fake.SetAnnotations("check_outage", &mcp.ToolAnnotations{ReadOnlyHint: true})
	sv := e.create(map[string]any{"slug": "status", "name": "Status", "url": e.fake.URL()}).Server
	id := sv.Id.String()
	base := toolsTeam + "/mcp-servers/" + id
	tool := e.capabilities(e.owner, id)["check_outage"]
	if tool.ToolClass != nil || tool.SuggestedClass == nil || *tool.SuggestedClass != "read" {
		t.Fatalf("suggestion %+v", tool)
	}
	path := base + "/capabilities/" + tool.Id.String() + "/class"
	set := func(class any, via bool) {
		t.Helper()
		code, ec := e.owner.call("PUT", path, map[string]any{"toolClass": class, "viaSuggestion": via}, nil, ifMatch(e.server(e.owner, id).Revision))
		mustCode(t, "classify", code, ec, 200, "")
	}
	code, ec := e.owner.call("POST", base+"/publish", nil, nil, nil)
	mustCode(t, "request", code, ec, 200, "")
	seen := reviewDigestOf(t, e.admin, id)
	set("read", true)
	if reviewDigestOf(t, e.admin, id) == seen {
		t.Fatal("class didn't move review digest")
	}
	code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", map[string]any{"decision": "approve", "expectedDigest": seen}, nil, nil)
	mustCode(t, "stale approval", code, ec, 409, "changed_since_review")
	approve := func() {
		t.Helper()
		code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+id+"/review", approveBody(t, e.admin, id), nil, nil)
		mustCode(t, "approve", code, ec, 200, "")
	}
	approve()
	// Raising, and clearing (fail closed), never resubmit. Unclassified -> write does.
	for _, tc := range []struct {
		class   any
		pending bool
	}{
		{"write", false}, {"destructive", false}, {nil, false}, {"write", true}, {"read", true}, {"destructive", false}, {"read", true},
	} {
		set(tc.class, false)
		state := e.server(e.owner, id).PublishState
		if (state == "pending") != tc.pending {
			t.Fatalf("class %v -> %s", tc.class, state)
		}
		if tc.pending {
			if e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action='mcp_server.publish_request' ORDER BY id DESC LIMIT 1`) != "classification_changed" {
				t.Fatal("review reason")
			}
			approve()
		}
	}
	// A changed definition preserves owner class but updates suggestion/drift,
	// and still withdraws the changed definition from the catalog.
	e.fake.SetAnnotations("check_outage", &mcp.ToolAnnotations{DestructiveHint: ptrBool(true)})
	e.refresh(id)
	changed := e.capabilities(e.owner, id)["check_outage"]
	if changed.ToolClass == nil || *changed.ToolClass != "read" || !changed.ClassDrift || *changed.SuggestedClass != "destructive" || !changed.Changed || changed.Approved {
		t.Fatalf("refresh %+v", changed)
	}
	// A stale suggestion is checked against today's definition, atomically.
	code, ec = e.owner.call("PUT", path, map[string]any{"toolClass": "read", "viaSuggestion": true}, nil, ifMatch(e.server(e.owner, id).Revision))
	mustCode(t, "stale suggestion", code, ec, 409, "suggestion_changed")
	e.fake.Hide("check_outage")
	e.refresh(id)
	gone := e.capabilities(e.owner, id)["check_outage"]
	if gone.GoneAt == nil || gone.ToolClass != nil || gone.ClassDrift {
		t.Fatalf("gone %+v", gone)
	}
	if e.scalar(`SELECT (class_set_by IS NULL AND class_set_at IS NULL)::text FROM mcp_capabilities WHERE id=$1`, tool.Id) != "true" {
		t.Fatal("gone class metadata")
	}
	code, ec = e.owner.call("PUT", path, map[string]any{"toolClass": "read"}, nil, ifMatch(e.server(e.owner, id).Revision))
	mustCode(t, "gone classify", code, ec, 409, "capability_gone")
	e.fake.Show("check_outage")
	e.refresh(id)
	if e.capabilities(e.owner, id)["check_outage"].ToolClass != nil {
		t.Fatal("reappearing tool inherited withdrawn class")
	}
}

func ptrBool(v bool) *bool { return &v }

func TestToolClassRuntimeIdentityAndCallMetadata(t *testing.T) {
	e := newGwEnv(t, nil)
	e.fake.SetJWKS(e.app.URL+"/.well-known/jwks.json", e.fake.URL())
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "classified")
	capID := e.capID(e.owner, e.server, "tool", "whoami")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(capID))
	key := newKey(t, e.member, "test")
	base := toolsTeam + "/mcp-servers/" + e.server.Id.String()
	var server apitypes.McpServer
	set := func(class any) {
		t.Helper()
		if code := e.owner.get(base, &server); code != 200 {
			t.Fatal(code)
		}
		code, ec := e.owner.call("PUT", base+"/capabilities/"+capID+"/class", map[string]any{"toolClass": class}, nil, ifMatch(server.Revision))
		mustCode(t, "set", code, ec, 200, "")
	}
	cs := connect(t, e.app, "classified", key.Secret)
	for _, class := range []any{nil, "read", "write", "destructive", nil} {
		set(class)
		tools, err := cs.ListTools(context.Background(), nil)
		if err != nil || len(tools.Tools) != 1 {
			t.Fatalf("list %v %+v", err, tools)
		}
		if class != nil {
			a := tools.Tools[0].Annotations
			if a == nil || a.ReadOnlyHint != (class == "read") || a.DestructiveHint == nil || *a.DestructiveHint != (class == "destructive") {
				t.Fatalf("annotations %v: %+v", class, a)
			}
		}
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "status__whoami", Arguments: map[string]any{}})
		if err != nil || res.IsError {
			t.Fatalf("call %v %+v", err, res)
		}
		var who struct {
			Claims map[string]any `json:"claims"`
		}
		if err := json.Unmarshal([]byte(resultText(t, res)), &who); err != nil {
			t.Fatal(err)
		}
		if who.Claims["tool_class"] != class {
			t.Fatalf("claim %v: %+v", class, who.Claims)
		}
		var detail apitypes.MyGatewayDetail
		if code := e.member.get("/v1/me/gateways/"+gw.Id.String(), &detail); code != 200 {
			t.Fatalf("detail %d", code)
		}
		if len(detail.Capabilities) != 1 {
			t.Fatalf("detail %+v", detail)
		}
		got := detail.Capabilities[0].ToolClass
		if class == nil && got != nil || class != nil && (got == nil || string(*got) != class) {
			t.Fatalf("detail class %v", got)
		}
	}
	var page apitypes.McpCallPage
	if code := e.owner.get(toolsTeam+"/calls", &page); code != http.StatusOK {
		t.Fatalf("calls %d", code)
	}
	classes := []string{}
	for _, c := range page.Items {
		if c.Method == "tools/call" {
			if c.ToolClass == nil {
				classes = append(classes, "null")
			} else {
				classes = append(classes, string(*c.ToolClass))
			}
		}
	}
	if fmt.Sprint(classes) != "[null destructive write read null]" {
		t.Fatalf("call classes %v", classes)
	}
	// Class is tool-only even on a gateway with a classified tool. Prompt
	// and resource identities omit it, and their call snapshots stay null.
	set("read")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(capID,
		e.capID(e.owner, e.server, "prompt", "incident_summary"),
		e.capID(e.owner, e.server, "resource", "status://services")))
	before := len(e.fake.HTTPRequests())
	if _, err := cs.GetPrompt(context.Background(), &mcp.GetPromptParams{Name: "status__incident_summary", Arguments: map[string]string{"service": "email"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "omp://status/status://services"}); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, req := range e.fake.HTTPRequests()[before:] {
		_, token := testutil.IdentityToken(req.Header)
		if token == "" {
			continue
		}
		var claims map[string]any
		if err := testutil.VerifyIdentity(context.Background(), token, e.app.URL+"/.well-known/jwks.json", e.fake.URL(), &claims); err != nil {
			t.Fatal(err)
		}
		if _, ok := claims["tool_class"]; ok {
			t.Fatalf("non-tool identity carried a class: %+v", claims)
		}
		for _, kind := range []string{"prompt", "resource"} {
			if claims[kind] != nil {
				seen[kind] = true
			}
		}
	}
	if !seen["prompt"] || !seen["resource"] {
		t.Fatalf("missing non-tool identity: %v", seen)
	}
	page = apitypes.McpCallPage{}
	if code := e.owner.get(toolsTeam+"/calls", &page); code != 200 {
		t.Fatal(code)
	}
	seen = map[string]bool{}
	for _, c := range page.Items {
		if c.Method == "prompts/get" || c.Method == "resources/read" {
			seen[c.Method] = true
			if c.ToolClass != nil {
				t.Fatalf("non-tool call has class: %+v", c)
			}
		}
	}
	if !seen["prompts/get"] || !seen["resources/read"] {
		t.Fatalf("missing non-tool calls: %v", seen)
	}
}
