package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServerEndpointsMCPActualAudienceAndFreshAdmission(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		for _, boundary := range []string{"read-success", "revoked-before-fallback", "quota-before-fallback"} {
			t.Run(string(era)+"/"+boundary, func(t *testing.T) {
				var e *approvalWire
				e = newApprovalWire(t, era, func(w http.ResponseWriter, r *http.Request, m map[string]any) bool {
					if m["method"] != "tools/call" {
						return false
					}
					if boundary == "revoked-before-fallback" {
						if _, err := e.app.Pool.Exec(context.Background(), `UPDATE users SET status='suspended' WHERE email='blair@localhost'`); err != nil {
							t.Error(err)
						}
					}
					http.Error(w, "owned primary unavailable", 503)
					return true
				})
				secondary, h := testutil.NewFakeMCPHandler()
				secondary.EnableGatewayTools()
				secondary.EnableSchemaTools()
				secondary.SetProtocol(era)
				var requests atomic.Int32
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); h.ServeHTTP(w, r) }))
				defer ts.Close()
				secondary.SetJWKS(e.app.URL+"/.well-known/jwks.json", ts.URL)
				capID := e.capID(e.owner, e.server, "tool", "lookup")
				path := toolsTeam + "/mcp-servers/" + e.server.Id.String()
				var sv apitypes.McpServer
				e.owner.get(path, &sv)
				code, ec := e.owner.call("PUT", path+"/capabilities/"+capID+"/class", map[string]any{"toolClass": "read"}, nil, ifMatch(sv.Revision))
				mustCode(t, "trusted read", code, ec, 200, "")
				body := map[string]any{"endpoints": []any{map[string]any{"url": ts.URL}}}
				if boundary == "quota-before-fallback" {
					body["rateLimitPerMinute"] = 1
				}
				e.patchServer(e.owner, e.server, body)
				code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(t, e.admin, e.server.Id.String()), nil, nil)
				mustCode(t, "review actual replica", code, ec, 200, "")
				freshWindow(t, e.app.Pool)
				var out map[string]any
				if era == testutil.ProtocolModern {
					code, _, out = rawModern(t, e.app, "approvals", e.key.Secret, "tools/call", approvalParams("replica-read"), nil, map[string]string{"Mcp-Param-Limit": "2"})
				} else {
					code, _, out = rawMCP(t, e.app, "POST", "approvals", e.key.Secret, rpc(1, "tools/call", approvalParams("replica-read")), nil)
				}
				if e.posts.Load() != 1 {
					t.Fatalf("primary dispatch count=%d", e.posts.Load())
				}
				if boundary == "read-success" {
					if code != 200 || out["error"] != nil || out["result"] == nil || len(secondary.ToolCalls()) != 1 {
						t.Fatalf("read fallback failed: %d %v secondary=%d", code, out, len(secondary.ToolCalls()))
					}
					who := testutil.Whoami(context.Background(), secondary.ToolCalls()[0].Header, e.app.URL+"/.well-known/jwks.json", ts.URL)
					if !who.Verified || who.Claims["aud"] != ts.URL {
						t.Fatalf("identity not bound to actual endpoint: %+v", who)
					}
					if len(approvalList(t, e.member, "requested")) != 0 {
						t.Fatal("ordinary read manufactured approval")
					}
				} else {
					if requests.Load() != 0 || len(secondary.ToolCalls()) != 0 {
						t.Fatal("local admission refusal contacted extra endpoint")
					}
					if boundary == "revoked-before-fallback" && (code != 200 || rpcErrorCode(out) != -32010) {
						t.Fatalf("revocation: %d %v", code, out)
					}
					if boundary == "quota-before-fallback" && code != 429 {
						t.Fatalf("retry quota: %d %v", code, out)
					}
				}
			})
		}
	}
}

func TestServerEndpointsMCPGovernedCallPrimaryOnly(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			e := newApprovalWire(t, era, func(w http.ResponseWriter, r *http.Request, m map[string]any) bool {
				if m["method"] != "tools/call" {
					return false
				}
				http.Error(w, "primary unavailable", 503)
				return true
			})
			secondary, h := testutil.NewFakeMCPHandler()
			secondary.EnableGatewayTools()
			secondary.EnableSchemaTools()
			secondary.SetProtocol(era)
			var requests atomic.Int32
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); h.ServeHTTP(w, r) }))
			defer ts.Close()
			e.patchServer(e.owner, e.server, map[string]any{"endpoints": []any{map[string]any{"url": ts.URL}}})
			code, ec := e.admin.call("POST", "/v1/admin/mcp-servers/"+e.server.Id.String()+"/review", approveBody(t, e.admin, e.server.Id.String()), nil, nil)
			mustCode(t, "review replica", code, ec, 200, "")
			e.call(t, era == testutil.ProtocolModern, e.key.Secret, approvalParams("primary-only"), nil)
			r := soleApproval(t, e.member)
			approvalDecide(t, e.owner, r, "approve")
			e.call(t, era == testutil.ProtocolModern, e.key.Secret, approvalParams("primary-only"), nil)
			if e.posts.Load() != 1 || requests.Load() != 0 || approvalDetail(t, e.member, r.ID).Status != approvals.Used {
				t.Fatalf("spent approval routed or restored: primary=%d secondary=%d", e.posts.Load(), requests.Load())
			}
		})
	}
}
