package httpapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func approvalOperations() []request {
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	out := []request{get("/v1/me/approvals"), get("/v1/approvals/" + id), post("/v1/approvals/"+id+"/decision", nil), post("/v1/approvals/"+id+"/cancel", nil), post("/v1/approvals/"+id+"/renew", nil)}
	for _, base := range []string{toolsTeam + "/approval-rules", "/v1/admin/approval-rules"} {
		out = append(out, get(base), post(base, nil), request{method: "PUT", path: base + "/" + id}, del(base+"/"+id))
	}
	return out
}

func TestApprovalsHTTPAllOperationsRequireSessionsAndFailClosedWithoutService(t *testing.T) {
	for _, nilService := range []bool{false, true} {
		name := "wired"
		if nilService {
			name = "nil service"
		}
		t.Run(name, func(t *testing.T) {
			app := newTestAppDeps(t, nil, testutil.Logger(), func(d *httpapi.Deps) {
				if nilService {
					d.Approvals = nil
				}
			})
			admin, owner := app.signIn("admin"), app.signIn("user")
			createTeam(t, admin, "tools", "user@localhost")
			var platform, publisher apitypes.AutomationTokenCreated
			c, ec := admin.call("POST", "/v1/admin/automation-tokens", map[string]any{"name": "broad platform", "scopes": []string{"platform:read", "platform:write"}}, &platform, nil)
			mustCode(t, "mint platform token", c, ec, 201, "")
			c, ec = owner.call("POST", toolsTeam+"/automation-tokens", map[string]any{"name": "broad publisher", "scopes": []string{"servers:read", "servers:write"}}, &publisher, nil)
			mustCode(t, "mint publisher token", c, ec, 201, "")
			ops := approvalOperations()
			if len(ops) != 13 {
				t.Fatal("approval operation inventory changed")
			}
			for _, op := range ops {
				t.Run(op.method+" "+op.path, func(t *testing.T) {
					for _, token := range []string{platform.Secret, publisher.Secret} {
						c, body := app.do(op.method, op.path, op.body, map[string]string{"Authorization": "Bearer " + token})
						if c != http.StatusForbidden || errorCode(body) != "token_not_allowed" {
							t.Fatalf("automation token accepted: %d %s", c, body)
						}
					}
					c, ec := anonSession(t, app).call(op.method, op.path, op.body, nil, nil)
					if c != 401 {
						t.Fatalf("anonymous approval route: %d %s", c, ec)
					}
					if nilService {
						c, ec = admin.call(op.method, op.path, op.body, nil, nil)
						mustCode(t, "nil service fails closed", c, ec, 503, "approval_unavailable")
					}
				})
			}
		})
	}
}

func TestApprovalsHTTPRuleValidationRevisionAndPrivateErrors(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	path := toolsTeam + "/approval-rules/" + e.rule.ID.String()
	for _, tc := range []struct {
		headers map[string]string
		status  int
		code    string
	}{
		{nil, 428, "revision_required"}, {ifMatch(e.rule.Revision + 1), 412, "revision_conflict"},
	} {
		c, ec := e.owner.call("PUT", path, e.ruleInput, nil, tc.headers)
		mustCode(t, "rule If-Match", c, ec, tc.status, tc.code)
		c, ec = e.owner.call("DELETE", path, nil, nil, tc.headers)
		mustCode(t, "delete If-Match", c, ec, tc.status, tc.code)
	}
	for _, edit := range []func(map[string]any){
		func(b map[string]any) { b["name"] = strings.Repeat("x", 101) },
		func(b map[string]any) {
			b["approvers"] = []any{map[string]any{"kind": "group", "groupName": strings.Repeat("g", 257)}}
		},
		func(b map[string]any) {
			b["approvers"] = []any{map[string]any{"kind": "user", "userId": uuid.New(), "groupName": "ambiguous"}}
		},
		func(b map[string]any) { b["classes"] = []string{"destructive", "destructive"} },
		func(b map[string]any) { b["pendingMinutes"] = 4 },
	} {
		b := map[string]any{"name": "invalid", "targetKind": "server", "targetId": e.server.Id, "classes": []string{"destructive"}, "enabled": true}
		edit(b)
		c, ec := e.owner.call("POST", toolsTeam+"/approval-rules", b, nil, nil)
		mustCode(t, "malformed rule DTO", c, ec, 422, "invalid_approval_rule")
	}
	for _, id := range []uuid.UUID{e.rule.ID, uuid.New()} {
		c, ec := e.outsider.call("PUT", toolsTeam+"/approval-rules/"+id.String(), e.ruleInput, nil, ifMatch(1))
		mustCode(t, "private rule scope", c, ec, 404, "team_not_found")
	}
	// Exact, case-sensitive group names survive HTTP serialization unchanged.
	in := e.ruleInput
	in.Enabled = false
	group := " Approvers/CaseSensitive "
	in.Approvers = []approvals.Selector{{Kind: "group", GroupName: &group}}
	var got approvals.Rule
	c, ec := e.owner.call("PUT", path, in, &got, ifMatch(e.rule.Revision))
	mustCode(t, "exact group selector", c, ec, 200, "")
	if len(got.Approvers) != 1 || got.Approvers[0].GroupName == nil || *got.Approvers[0].GroupName != group {
		t.Fatalf("group selector was normalized: %+v", got)
	}
	c, ec = e.owner.call("DELETE", path, nil, nil, ifMatch(got.Revision))
	mustCode(t, "delete rule", c, ec, 200, "")
}

// Narrow fixtures for the existing exhaustive authz/token matrices. Their
// authorization checker is unchanged. Real dispatch acceptance is independently
// exercised above through app.NewDeps and HTTP; these builders create fresh
// bindings so the matrix can test each browser operation without state sharing.
func approvalMatrixRule(c *mctx, platform, insert bool) approvals.Rule {
	e := c.e
	target, kind, team := e.newServer(*c.tf, "private"), "server", c.tf.id
	if platform {
		target, kind, team = e.newGateway(""), "gateway", ""
	}
	r := approvals.Rule{RuleInput: approvals.RuleInput{Name: "matrix approval", TargetKind: kind, TargetID: uuid.MustParse(target), Classes: []string{"destructive"}, Enabled: true, PendingMinutes: 5, ValidMinutes: 1}, Revision: 1}
	if insert {
		r.ID = uuid.MustParse(e.exec(`INSERT INTO approval_rules(name,team_id,target_kind,target_id,classes,created_by,pending_minutes,valid_minutes) VALUES ('matrix approval',NULLIF($1,'')::uuid,$2,$3,'{destructive}',$4,5,1) RETURNING id::text`, team, kind, target, e.userIDs[cOwner]))
	}
	return r
}

func approvalMatrixReceipt(c *mctx, operation string) approvals.Receipt {
	e, t := c.e, c.e.t
	rule := approvalMatrixRule(c, false, true)
	server := rule.TargetID.String()
	e.exec(`UPDATE mcp_servers SET publish_state='published',published_at=now() WHERE id=$1 RETURNING id::text`, server)
	cap := e.newChangedCapability(server)
	e.exec(`UPDATE mcp_capabilities SET approved_fingerprint=fingerprint,tool_class='destructive' WHERE id=$1 RETURNING id::text`, cap)
	gw := e.newGateway("")
	requester, reviewer := e.spareUser, e.userIDs[cOwner]
	if c.allowed {
		if operation == "decision" {
			reviewer = e.userIDs[c.who]
		} else {
			requester = e.userIDs[c.who]
			reviewer = e.spareUser
		}
	}
	e.exec(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES ($1,$2) RETURNING capability_id::text`, gw, cap)
	e.exec(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2) RETURNING id::text`, gw, requester)
	e.exec(`INSERT INTO approval_rule_approvers(rule_id,kind,user_id) VALUES ($1,'user',$2) RETURNING rule_id::text`, rule.ID, reviewer)
	key, err := secrets.ParseKey(testEncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	box, err := secrets.New(key)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := approvals.New(e.app.Pool, box, nil, e.app.URL)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := svc.Epoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	class := "destructive"
	// Matrix server slugs and names are generated by newServer, not a fixed label.
	slug := e.exec(`SELECT slug FROM mcp_servers WHERE id=$1`, server)
	in := approvals.BeginInput{Binding: approvals.Binding{Epoch: epoch, RequesterKind: "user", RequesterID: uuid.MustParse(requester), GatewayID: uuid.MustParse(gw), ServerID: rule.TargetID, CapabilityID: uuid.MustParse(cap), ExposedName: slug + "__fixture_tool", ToolClass: &class, CapabilityFingerprint: strings.Repeat("a", 64), ServerOrigin: e.fakeURL}, Arguments: []byte(`{}`)}
	plan, err := svc.Begin(context.Background(), in)
	if err != nil {
		t.Fatalf("matrix Begin: %v", err)
	}
	r := plan.Receipt
	if operation == "renew" {
		r, err = svc.Decide(context.Background(), authz.Actor{UserID: uuid.MustParse(reviewer), PlatformRole: authz.PlatformNone}, r.ID, approvals.Decision{Decision: "deny", ExpectedArgsDigest: r.ArgsDigest, ExpectedReviewRevision: r.ReviewRevision})
		if err != nil {
			t.Fatalf("matrix deny before renewal: %v", err)
		}
	}
	return r
}
