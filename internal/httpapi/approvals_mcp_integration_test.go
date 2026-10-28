package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/mcpgw"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// These tests deliberately use app.NewDeps' real approval service and runtime.
// The only network seam is an actual HTTP upstream, which counts tool POSTs
// before SDK processing (including rejected or lost-response attempts).
type approvalWire struct {
	*gwEnv
	svc           *approvals.Service
	runtime       *mcpgw.Handler
	key, otherKey apitypes.ApiKeyCreated
	rule          approvals.Rule
	ruleInput     approvals.RuleInput
	path          string
	posts         atomic.Int64
	logs          *syncBuffer
}

type approvalUpstreamHook func(http.ResponseWriter, *http.Request, map[string]any) bool

func newApprovalWire(t *testing.T, era testutil.Protocol, hook approvalUpstreamHook) *approvalWire {
	t.Helper()
	e := &approvalWire{logs: new(syncBuffer)}
	e.gwEnv = newGwEnvHook(t, slog.New(slog.NewJSONHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})), func(d *httpapi.Deps) {
		var ok bool
		e.svc, ok = d.Approvals.(*approvals.Service)
		if !ok {
			t.Fatalf("app.NewDeps approval service = %T", d.Approvals)
		}
		e.runtime, ok = d.MCP.(*mcpgw.Handler)
		if !ok || e.runtime.Approvals != e.svc {
			t.Fatalf("app.NewDeps MCP approval runtime is not the browser service: %T", d.MCP)
		}
	})
	e.fake.SetProtocol(era)
	e.fake.EnableSchemaTools()
	// Wrap the real fake's handler, not its client or the approval runtime.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var msg map[string]any
		if r.Body != nil {
			raw, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(raw))
			_ = json.Unmarshal(raw, &msg)
		}
		if msg["method"] == "tools/call" {
			e.posts.Add(1)
		}
		if hook != nil && hook(w, r, msg) {
			return
		}
		e.fake.Config.Handler.ServeHTTP(w, r)
	}))
	t.Cleanup(upstream.Close)
	e.patchServer(e.owner, e.server, map[string]any{"url": upstream.URL})
	e.refresh(e.owner, e.server)
	capID := e.capID(e.owner, e.server, "tool", "lookup")
	serverPath := toolsTeam + "/mcp-servers/" + e.server.Id.String()
	var sv apitypes.McpServer
	if c := e.owner.get(serverPath, &sv); c != 200 {
		t.Fatalf("server: %d", c)
	}
	c, ec := e.owner.call("PUT", serverPath+"/capabilities/"+capID+"/class", map[string]any{"toolClass": "destructive"}, nil, ifMatch(sv.Revision))
	mustCode(t, "classify governed tool via session", c, ec, 200, "")
	e.publish(e.owner, e.server)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "approvals")
	e.path = toolsTeam + "/gateways/" + gw.Id.String()
	e.mustSetCaps(e.owner, e.path, sel(capID))
	setCuration(t, e.gwEnv, e.owner, e.path, "lookup", map[string]any{"nameOverride": "reviewed_lookup", "constraints": map[string]any{"region": map[string]any{"fixed": "us"}}})
	e.ruleInput = approvals.RuleInput{Name: "Review destructive calls", TargetKind: "server", TargetID: e.server.Id, Classes: []string{"destructive"}, Enabled: true, PendingMinutes: 5, ValidMinutes: 1}
	c, ec = e.owner.call("POST", toolsTeam+"/approval-rules", e.ruleInput, &e.rule, nil)
	mustCode(t, "create approval rule via session", c, ec, 201, "")
	// All authority-changing setup precedes the request/epoch binding.
	e.key = newKey(t, e.member, "approval caller")
	e.otherKey = newKey(t, e.editor, "different principal")
	return e
}

func approvalArgs(note string) map[string]any { return map[string]any{"limit": 2, "note": note} }
func approvalParams(note string) map[string]any {
	return map[string]any{"name": "reviewed_lookup", "arguments": approvalArgs(note)}
}
func (e *approvalWire) call(t *testing.T, modern bool, key string, p, caps map[string]any) map[string]any {
	t.Helper()
	var c int
	var out map[string]any
	if modern {
		c, _, out = rawModern(t, e.app, "approvals", key, "tools/call", p, caps, map[string]string{"Mcp-Param-Limit": "2"})
	} else {
		c, _, out = rawMCP(t, e.app, "POST", "approvals", key, rpc(1, "tools/call", p), nil)
	}
	if c != 200 {
		t.Fatalf("MCP call: %d %v", c, out)
	}
	return out
}
func approvalDetail(t *testing.T, s *session, id uuid.UUID) approvals.Receipt {
	t.Helper()
	var out approvals.Receipt
	if c := s.get("/v1/approvals/"+id.String(), &out); c != 200 {
		t.Fatalf("approval detail: %d", c)
	}
	return out
}
func approvalList(t *testing.T, s *session, view string) []approvals.Receipt {
	t.Helper()
	var out struct {
		Items []approvals.Receipt `json:"items"`
	}
	if c := s.get("/v1/me/approvals?view="+view, &out); c != 200 {
		t.Fatalf("approval list: %d", c)
	}
	for _, r := range out.Items {
		if r.Preview != nil {
			t.Fatal("queue exposed preview")
		}
	}
	return out.Items
}
func soleApproval(t *testing.T, s *session) approvals.Receipt {
	t.Helper()
	rows := approvalList(t, s, "requested")
	if len(rows) != 1 {
		t.Fatalf("requested receipts = %+v", rows)
	}
	return approvalDetail(t, s, rows[0].ID)
}
func approvalDecide(t *testing.T, s *session, r approvals.Receipt, decision string) approvals.Receipt {
	t.Helper()
	var out approvals.Receipt
	c, ec := s.call("POST", "/v1/approvals/"+r.ID.String()+"/decision", map[string]any{"decision": decision, "expectedArgsDigest": r.ArgsDigest, "expectedReviewRevision": r.ReviewRevision}, &out, nil)
	mustCode(t, "exact browser decision", c, ec, 200, "")
	return out
}
func approvalState(t *testing.T, out map[string]any, id uuid.UUID, appURL string) string {
	t.Helper()
	r := resultOf(t, out)
	if r["resultType"] != "input_required" {
		t.Fatalf("modern approval shape: %v", out)
	}
	state, _ := r["requestState"].(string)
	if state == "" || strings.Contains(state, id.String()) {
		t.Fatalf("approval state is not opaque: %v", r)
	}
	inputs, _ := r["inputRequests"].(map[string]any)
	input, _ := inputs["approval_"+id.String()].(map[string]any)
	params, _ := input["params"].(map[string]any)
	if len(inputs) != 1 || input["method"] != "elicitation/create" || params["mode"] != "url" || params["url"] != appURL+"/approvals/"+id.String() {
		t.Fatalf("approval URL input: %v", r)
	}
	return state
}

func TestApprovalsHTTPMCPWireBothEras(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			e := newApprovalWire(t, era, nil)
			const private = "private-argument-sentinel-31"
			const secret = "Bearer approval-secret-sentinel-31"
			note := private + " " + secret
			legacy := e.call(t, false, e.key.Secret, approvalParams(note), nil)
			if rpcErrorCode(legacy) != -32042 || !strings.Contains(mustJSON(t, legacy), e.app.URL+"/approvals/") {
				t.Fatalf("legacy approval shape: %v", legacy)
			}
			r := soleApproval(t, e.member)
			if r.Status != approvals.Pending || r.ToolClass == nil || *r.ToolClass != "destructive" {
				t.Fatalf("receipt: %+v", r)
			}
			if r.Preview == nil || !strings.Contains(*r.Preview, private) || strings.Contains(*r.Preview, secret) || !r.PreviewRedacted || !strings.Contains(*r.Preview, `"region":"us"`) {
				t.Fatalf("redacted merged preview: %+v", r)
			}
			modern := e.call(t, true, e.key.Secret, approvalParams(note), urlCaps)
			state := approvalState(t, modern, r.ID, e.app.URL)
			noURL := e.call(t, true, e.key.Secret, approvalParams(note), nil)
			if v := resultOf(t, noURL); v["isError"] != true || v["inputRequests"] != nil || !strings.Contains(mustJSON(t, v), e.app.URL+"/approvals/"+r.ID.String()) {
				t.Fatalf("modern non-URL approval shape: %v", noURL)
			}
			// Curation runs before both digests: explicit fixed args reuse the receipt.
			p := approvalParams(note)
			p["arguments"].(map[string]any)["region"] = "us"
			e.call(t, true, e.key.Secret, p, urlCaps)
			again := soleApproval(t, e.member)
			if again.ID != r.ID || !again.ExpiresAt.Equal(r.ExpiresAt) || again.ArgsDigest != r.ArgsDigest {
				t.Fatal("pending dedup extended/rebound the request")
			}
			if e.posts.Load() != 0 {
				t.Fatal("a pending call reached upstream tools/call")
			}
			reviewer := approvalDetail(t, e.owner, r.ID)
			if reviewer.Preview == nil || !reviewer.CanDecide {
				t.Fatalf("eligible non-requester reviewer: %+v", reviewer)
			}
			for _, s := range []*session{e.admin, e.auditor} {
				if v := approvalDetail(t, s, r.ID); v.Preview != nil || v.CanDecide {
					t.Fatalf("oversight revealed preview/decision: %+v", v)
				}
			}
			if c, ec := e.outsider.call("GET", "/v1/approvals/"+r.ID.String(), nil, nil, nil); c != 404 || ec != "approval_not_found" {
				t.Fatalf("private receipt: %d %s", c, ec)
			}
			if len(approvalList(t, e.owner, "actionable")) != 1 {
				t.Fatal("reviewer queue missing receipt")
			}
			// Displayed digest and review revision are both mandatory bindings.
			for _, body := range []map[string]any{
				{"decision": "approve", "expectedArgsDigest": "wrong", "expectedReviewRevision": r.ReviewRevision},
				{"decision": "approve", "expectedArgsDigest": r.ArgsDigest, "expectedReviewRevision": r.ReviewRevision + 1},
			} {
				c, _ := e.owner.call("POST", "/v1/approvals/"+r.ID.String()+"/decision", body, nil, nil)
				if c != 409 {
					t.Fatalf("stale/digest mismatch decision: %d", c)
				}
			}
			// Sealed state does not become transferable or permit mutated arguments.
			for _, tc := range []struct {
				key string
				p   map[string]any
			}{
				{e.key.Secret, map[string]any{"name": "reviewed_lookup", "arguments": approvalArgs("changed"), "requestState": state}},
				{e.otherKey.Secret, map[string]any{"name": "reviewed_lookup", "arguments": approvalArgs(note), "requestState": state}},
				{e.key.Secret, map[string]any{"name": "reviewed_lookup", "arguments": approvalArgs(note), "requestState": state + "x"}},
			} {
				if out := e.call(t, true, tc.key, tc.p, urlCaps); rpcErrorCode(out) != -32602 {
					t.Fatalf("mutated approval continuation: %v", out)
				}
			}
			approvalDecide(t, e.owner, reviewer, "approve")
			// Negotiating the gateway does not spend an approval or contact upstream.
			cs := connectEra(t, e.app, "approvals", e.key.Secret, "", nil)
			toolNames(t, cs)
			if v := approvalDetail(t, e.member, r.ID); v.Status != approvals.Approved || e.posts.Load() != 0 {
				t.Fatal("discovery/list consumed approval")
			}
			p = approvalParams(note)
			p["requestState"] = state
			out := e.call(t, era == testutil.ProtocolModern, e.key.Secret, p, urlCaps)
			if out["error"] != nil || resultOf(t, out)["isError"] == true || e.posts.Load() != 1 {
				t.Fatalf("approved actual dispatch: posts=%d %v", e.posts.Load(), out)
			}
			used := approvalDetail(t, e.member, r.ID)
			if used.Status != approvals.Used || used.Preview != nil || used.UsedAt == nil {
				t.Fatalf("spent receipt: %+v", used)
			}
			calls := e.fake.ToolCalls()
			if len(calls) != 1 || !strings.Contains(string(calls[0].Arguments), `"region":"us"`) {
				t.Fatalf("forwarded merged args: %+v", calls)
			}
			e.call(t, true, e.key.Secret, approvalParams(note), urlCaps)
			if e.posts.Load() != 1 {
				t.Fatal("replay reused spent authorization")
			}
			// Public MCP/audit/log surfaces never include the private arguments.
			for _, out := range []map[string]any{legacy, modern, noURL} {
				for _, s := range []string{private, secret} {
					if strings.Contains(mustJSON(t, out), s) {
						t.Fatal("approval reply leaked argument")
					}
				}
			}
			var metadata string
			if err := e.app.Pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(metadata::text, ''),'') FROM audit_log`).Scan(&metadata); err != nil {
				t.Fatal(err)
			}
			for _, s := range []string{private, secret, state} {
				if strings.Contains(metadata, s) || strings.Contains(e.logs.String(), s) {
					t.Fatal("approval audit/log leaked private argument or sealed state")
				}
			}
			var needs, identified int
			if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*), count(identity_sent) FROM mcp_calls WHERE outcome='needs_approval'`).Scan(&needs, &identified); err != nil {
				t.Fatal(err)
			}
			if needs < 4 || identified != 0 {
				t.Fatalf("pretransport records: needs_approval=%d identity_sent=%d", needs, identified)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestApprovalsHTTPMCPConcurrentApprovedCallsDispatchAtMostOnce(t *testing.T) {
	entered, release := make(chan struct{}, 2), make(chan struct{})
	e := newApprovalWire(t, testutil.ProtocolModern, func(_ http.ResponseWriter, r *http.Request, msg map[string]any) bool {
		if msg["method"] == "tools/call" {
			entered <- struct{}{}
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		return false
	})
	// Ensure blocked upstream requests are released even if an assertion fails.
	defer close(release)
	e.call(t, true, e.key.Secret, approvalParams("concurrent"), urlCaps)
	r := soleApproval(t, e.member)
	approvalDecide(t, e.owner, r, "approve")
	first := make(chan map[string]any, 1)
	go func() { first <- e.call(t, true, e.key.Secret, approvalParams("concurrent"), nil) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("approved dispatch did not enter upstream")
	}
	// The first authorization is committed used while its network request blocks.
	if v := approvalDetail(t, e.member, r.ID); v.Status != approvals.Used {
		t.Fatalf("authorization not spent before I/O: %+v", v)
	}
	second := e.call(t, true, e.key.Secret, approvalParams("concurrent"), urlCaps)
	if e.posts.Load() != 1 {
		t.Fatalf("concurrent approved calls produced %d tool POSTs: %v", e.posts.Load(), second)
	}
	release <- struct{}{} // unblock exactly the one authorized dispatch
	select {
	case out := <-first:
		if out["error"] != nil || resultOf(t, out)["isError"] == true {
			t.Fatalf("first dispatch: %v", out)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first call did not complete")
	}
	if e.posts.Load() != 1 {
		t.Fatal("concurrent calls replayed upstream")
	}
}

func TestApprovalsHTTPMCPVerifiedDeclineCancelsOnlyBoundRequest(t *testing.T) {
	for _, action := range []string{"decline", "cancel"} {
		t.Run(action, func(t *testing.T) {
			e := newApprovalWire(t, testutil.ProtocolModern, nil)
			out := e.call(t, true, e.key.Secret, approvalParams("decline binding"), urlCaps)
			r := soleApproval(t, e.member)
			state := approvalState(t, out, r.ID, e.app.URL)
			p := approvalParams("decline binding")
			p["inputResponses"] = map[string]any{"approval_" + r.ID.String(): map[string]any{"action": action}}
			e.call(t, true, e.key.Secret, p, urlCaps)
			if v := approvalDetail(t, e.member, r.ID); v.Status != approvals.Pending {
				t.Fatal("unverified decline cancelled request")
			}
			p["requestState"] = state
			out = e.call(t, true, e.key.Secret, p, urlCaps)
			if resultOf(t, out)["isError"] != true || !strings.Contains(mustJSON(t, out), "authorization declined") {
				t.Fatalf("verified decline: %v", out)
			}
			if v := approvalDetail(t, e.member, r.ID); v.Status != approvals.Cancelled || v.Preview != nil {
				t.Fatalf("cancelled receipt: %+v", v)
			}
			if e.posts.Load() != 0 {
				t.Fatal("decline reached upstream")
			}
		})
	}
}

func TestApprovalsHTTPMCPDenialRequiresExplicitRenewalAndDoesNotExtendExpiry(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	now := time.Now().UTC()
	e.svc.SetClock(func() time.Time { return now })
	e.call(t, true, e.key.Secret, approvalParams("deny"), urlCaps)
	r := soleApproval(t, e.member)
	now = now.Add(time.Minute)
	e.call(t, true, e.key.Secret, approvalParams("deny"), urlCaps)
	if v := soleApproval(t, e.member); v.ID != r.ID || !v.ExpiresAt.Equal(r.ExpiresAt) {
		t.Fatal("pending retry extended expiration")
	}
	denied := approvalDecide(t, e.owner, r, "deny")
	out := e.call(t, true, e.key.Secret, approvalParams("deny"), urlCaps)
	if resultOf(t, out)["isError"] != true || soleApproval(t, e.member).ID != r.ID {
		t.Fatalf("denial was silently renewed: %v", out)
	}
	var renewed approvals.Receipt
	c, ec := e.member.call("POST", "/v1/approvals/"+r.ID.String()+"/renew", map[string]any{"expectedReviewRevision": denied.ReviewRevision}, &renewed, nil)
	mustCode(t, "explicit renewal", c, ec, 200, "")
	if renewed.ID == r.ID || renewed.Status != approvals.Pending {
		t.Fatalf("renewal: %+v", renewed)
	}
	now = renewed.ExpiresAt
	if v := approvalDetail(t, e.member, renewed.ID); v.Status != approvals.Expired || v.Preview != nil {
		t.Fatalf("synchronous expiry: %+v", v)
	}
	if e.posts.Load() != 0 {
		t.Fatal("denied/expired call reached upstream")
	}
}

func TestApprovalsHTTPMCPOldEpochChangeAndRevertCannotAuthorize(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	e.call(t, true, e.key.Secret, approvalParams("epoch"), urlCaps)
	r := soleApproval(t, e.member)
	approvalDecide(t, e.owner, r, "approve")
	changed := e.ruleInput
	changed.Name = "changed and reverted"
	var updated approvals.Rule
	c, ec := e.owner.call("PUT", toolsTeam+"/approval-rules/"+e.rule.ID.String(), changed, &updated, ifMatch(e.rule.Revision))
	mustCode(t, "change policy", c, ec, 200, "")
	c, ec = e.owner.call("PUT", toolsTeam+"/approval-rules/"+e.rule.ID.String(), e.ruleInput, nil, ifMatch(updated.Revision))
	mustCode(t, "revert policy", c, ec, 200, "")
	e.call(t, true, e.key.Secret, approvalParams("epoch"), urlCaps)
	if e.posts.Load() != 0 {
		t.Fatal("old epoch authorized after change and revert")
	}
	if v := approvalDetail(t, e.member, r.ID); v.Status == approvals.Used || !v.Stale {
		t.Fatalf("old approval resurrected: %+v", v)
	}
}

func TestApprovalsHTTPMCPSpentFailuresNeverReplay(t *testing.T) {
	for _, mode := range []string{"401", "lost response", "malicious input_required"} {
		t.Run(mode, func(t *testing.T) {
			e := newApprovalWire(t, testutil.ProtocolModern, func(w http.ResponseWriter, r *http.Request, msg map[string]any) bool {
				if msg["method"] != "tools/call" {
					return false
				}
				switch mode {
				case "401":
					http.Error(w, "upstream secret failure", http.StatusUnauthorized)
				case "lost response":
					conn, _, err := w.(http.Hijacker).Hijack()
					if err == nil {
						_ = conn.Close()
					}
				default:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": msg["id"], "result": map[string]any{"resultType": "input_required", "requestState": "malicious-upstream-state", "inputRequests": map[string]any{"evil": map[string]any{"method": "elicitation/create", "params": map[string]any{"mode": "url", "url": "https://attacker.invalid/continue", "message": "continue"}}}}})
				}
				return true
			})
			e.call(t, true, e.key.Secret, approvalParams("failure"), urlCaps)
			r := soleApproval(t, e.member)
			approvalDecide(t, e.owner, r, "approve")
			out := e.call(t, true, e.key.Secret, approvalParams("failure"), urlCaps)
			v := resultOf(t, out)
			if e.posts.Load() != 1 || v["isError"] != true || !strings.Contains(mustJSON(t, out), "may duplicate effects") || v["requestState"] != nil || v["inputRequests"] != nil {
				t.Fatalf("spent failure/replay: posts=%d %v", e.posts.Load(), out)
			}
			if v := approvalDetail(t, e.member, r.ID); v.Status != approvals.Used {
				t.Fatalf("failure restored authorization: %+v", v)
			}
			e.call(t, true, e.key.Secret, approvalParams("failure"), urlCaps)
			if e.posts.Load() != 1 {
				t.Fatal("retry replayed an unknown upstream effect")
			}
		})
	}
}
