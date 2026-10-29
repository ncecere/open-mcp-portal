package httpapi_test

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServerProtectionQuotaNeverSpendsApproval(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			e := newApprovalWire(t, era, nil)
			e.patchServer(e.owner, e.server, map[string]any{"rateLimitPerMinute": 1})
			freshWindow(t, e.app.Pool)
			e.call(t, era == testutil.ProtocolModern, e.key.Secret, approvalParams("quota-bound"), nil)
			r := soleApproval(t, e.member)
			if e.posts.Load() != 0 {
				t.Fatal("pending request dispatched")
			}
			approvalDecide(t, e.owner, r, "approve")
			bucket := "v:" + e.server.Id.String()
			if _, _, err := e.runtime.RateStore.Hit(context.Background(), []string{bucket}); err != nil {
				t.Fatal(err)
			}
			var code int
			var out map[string]any
			if era == testutil.ProtocolModern {
				code, _, out = rawModern(t, e.app, "approvals", e.key.Secret, "tools/call", approvalParams("quota-bound"), nil, map[string]string{"Mcp-Param-Limit": "2"})
			} else {
				code, _, out = rawMCP(t, e.app, "POST", "approvals", e.key.Secret, rpc(1, "tools/call", approvalParams("quota-bound")), nil)
			}
			if code != 429 || e.posts.Load() != 0 || approvalDetail(t, e.member, r.ID).Status != approvals.Approved {
				t.Fatalf("local quota spent or dispatched approval: %d %v posts=%d", code, out, e.posts.Load())
			}
			if _, err := e.app.Pool.Exec(context.Background(), `DELETE FROM rate_limit_counters WHERE bucket=$1`, bucket); err != nil {
				t.Fatal(err)
			}
			e.call(t, era == testutil.ProtocolModern, e.key.Secret, approvalParams("quota-bound"), nil)
			if e.posts.Load() != 1 || approvalDetail(t, e.member, r.ID).Status != approvals.Used {
				t.Fatal("unspent approval did not remain usable")
			}
		})
	}
}

func TestServerProtectionReadRetryRechecksAuthority(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			var e *approvalWire
			var failed atomic.Bool
			e = newApprovalWire(t, era, func(w http.ResponseWriter, r *http.Request, m map[string]any) bool {
				if m["method"] != "tools/call" || failed.Swap(true) {
					return false
				}
				// The callback runs at real upstream I/O, after all authority
				// transactions/connections have been released. Change authority
				// before answering the first retryable 503.
				if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET status='suspended' WHERE email='blair@localhost'`); err != nil {
					t.Error(err)
				}
				http.Error(w, "temporary outage", 503)
				return true
			})
			capID := e.capID(e.owner, e.server, "tool", "lookup")
			path := toolsTeam + "/mcp-servers/" + e.server.Id.String()
			var cur apitypes.McpServer
			e.owner.get(path, &cur)
			code, ec := e.owner.call("PUT", path+"/capabilities/"+capID+"/class", map[string]any{"toolClass": "read"}, nil, ifMatch(cur.Revision))
			mustCode(t, "classify read", code, ec, 200, "")
			code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(t, e.admin, e.server.Id.String()), nil, nil)
			mustCode(t, "review read classification", code, ec, 200, "")
			var out map[string]any
			if era == testutil.ProtocolModern {
				code, _, out = rawModern(t, e.app, "approvals", e.key.Secret, "tools/call", approvalParams("read"), nil, map[string]string{"Mcp-Param-Limit": "2"})
			} else {
				code, _, out = rawMCP(t, e.app, "POST", "approvals", e.key.Secret, rpc(1, "tools/call", approvalParams("read")), nil)
			}
			if code != 200 || rpcErrorCode(out) != -32010 || e.posts.Load() != 1 {
				t.Fatalf("retry crossed revoked authority: %d %v posts=%d", code, out, e.posts.Load())
			}
			waitCalls(t, e.app.Pool, 1)
			if got := e.scalar(`SELECT COALESCE(identity_sent::text,'null') FROM mcp_calls ORDER BY id DESC LIMIT 1`); got != "true" {
				t.Fatalf("retry refusal erased earlier identity dispatch: %s", got)
			}
		})
	}
}
