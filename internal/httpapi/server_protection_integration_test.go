package httpapi_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func TestServerProtectionOwnerFieldsCeilingsAndPreservation(t *testing.T) {
	e := newRegistryEnv(t)
	base := toolsTeam + "/mcp-servers"
	body := map[string]any{"slug": "protected", "name": "Protected", "url": e.fake.URL(), "rateLimitPerMinute": 10, "maxConcurrent": 2}
	code, ec := e.editor.call("POST", base, body, nil, nil)
	mustCode(t, "editor cannot configure protection", code, ec, 403, "forbidden")
	var made apitypes.McpServerCreated
	code, ec = e.owner.call("POST", base, body, &made, nil)
	mustCode(t, "owner creates protected server", code, ec, 201, "")
	sv := made.Server
	if sv.RateLimitPerMinute == nil || *sv.RateLimitPerMinute != 10 || sv.MaxConcurrent == nil || *sv.MaxConcurrent != 2 {
		t.Fatalf("missing protected values: %+v", sv)
	}
	path := base + "/" + sv.Id.String()
	for _, who := range []*session{e.editor, e.member, e.admin} {
		code, ec = who.call("PATCH", path, map[string]any{"maxConcurrent": nil}, nil, ifMatch(sv.Revision))
		mustCode(t, "non-owner cannot clear cap", code, ec, 403, "forbidden")
	}
	for _, bad := range []any{0, -1, 10001} {
		code, ec = e.owner.call("PATCH", path, map[string]any{"maxConcurrent": bad}, nil, ifMatch(sv.Revision))
		mustCode(t, "bad concurrency", code, ec, 400, "invalid_concurrency")
	}
	// Unrelated editor updates keep nullable operational fields, rather than
	// clearing them through a zero-valued generated parameter.
	var updated apitypes.McpServer
	code, ec = e.editor.call("PATCH", path, map[string]any{"description": "editor metadata"}, &updated, ifMatch(sv.Revision))
	mustCode(t, "editor metadata", code, ec, 200, "")
	if updated.MaxConcurrent == nil || *updated.MaxConcurrent != 2 || updated.RateLimitPerMinute == nil || *updated.RateLimitPerMinute != 10 {
		t.Fatal("unrelated edit erased protection")
	}
	sv = updated
	var settings apitypes.LimitSettings
	e.admin.get("/v1/admin/settings/limits", &settings)
	code, ec = e.admin.call("PUT", "/v1/admin/settings/limits", map[string]any{"items": []any{limit("server_per_minute", 5, 5)}}, nil, ifMatch(settings.Revision))
	mustCode(t, "server ceiling", code, ec, 200, "")
	e.admin.get("/v1/admin/settings/limits", &settings)
	var capped int64
	for _, item := range settings.Items {
		if item.Key == "server_per_minute" && item.CappedServers != nil {
			capped = *item.CappedServers
		}
	}
	if capped != 1 {
		t.Fatalf("capped server overrides=%d", capped)
	}
	code, details := errDetails(t, e.owner, "PATCH", path, map[string]any{"rateLimitPerMinute": 6}, ifMatch(sv.Revision))
	if code != 422 || details["key"] != "server_per_minute" || details["reason"] != "above_ceiling" {
		t.Fatalf("ceiling: %d %v", code, details)
	}
	updated = apitypes.McpServer{} // Fresh response object: omitted nullable fields must not retain old decoded pointers.
	code, ec = e.owner.call("PATCH", path, map[string]any{"rateLimitPerMinute": nil, "maxConcurrent": nil}, &updated, ifMatch(sv.Revision))
	mustCode(t, "explicit inheritance/unlimited", code, ec, 200, "")
	if updated.RateLimitPerMinute != nil || updated.MaxConcurrent != nil {
		t.Fatal("null did not clear operational values")
	}
	code, ec = e.owner.call("PATCH", path, map[string]any{"maxConcurrent": 1}, nil, ifMatch(sv.Revision))
	mustCode(t, "stale protection update", code, ec, 412, "revision_conflict")
	var n int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action='mcp_server.update' AND after_state->>'maxConcurrent' IS NOT NULL`).Scan(&n); err != nil || n < 1 {
		t.Fatalf("protection audit=%d %v", n, err)
	}
}

func TestServerQuotaSharedAcrossGatewaysAndReplicas(t *testing.T) {
	e := newRuntimeEnv(t)
	e.patchServer(e.owner, e.server, map[string]any{"rateLimitPerMinute": 2})
	second := e.createServer(e.owner, "tools", "independent", e.otherFake.URL(), nil)
	e.publish(e.owner, second)
	g := e.createGateway(e.owner, toolsTeam+"/gateways", "independent")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+g.Id.String(), sel(e.capID(e.owner, second, "tool", "whoami")))
	other := replica(t, e.app.Pool, nil)
	freshWindow(t, e.app.Pool)
	code, _, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(1, "tools/call", map[string]any{"name": "status__whoami"}), nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("first: %d %v", code, out)
	}
	code, _, out = rawModern(t, other, "shared", e.key.Secret, "tools/call", map[string]any{"name": "status__whoami"}, nil, nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("second replica/gateway: %d %v", code, out)
	}
	before := len(e.fake.ToolCalls())
	// Initial local admission must finish BEFORE committing SSE headers.
	code, headers, out := rawMCP(t, e.app, "POST", "support", e.key.Secret, rpc(3, "tools/call", map[string]any{"name": "status__whoami", "_meta": map[string]any{"progressToken": "p"}}), map[string]string{"Accept": "application/json, text/event-stream"})
	if code != http.StatusTooManyRequests || headers.Get("Retry-After") == "" || strings.HasPrefix(headers.Get("Content-Type"), "text/event-stream") || rpcErrorCode(out) != -32029 {
		t.Fatalf("quota/stream: %d %v %v", code, headers, out)
	}
	errObj, _ := out["error"].(map[string]any)
	data, _ := errObj["data"].(map[string]any)
	if data["limit"] != "server_per_minute" || data["limitPerMinute"] != float64(2) || data["remaining"] != nil {
		t.Fatalf("shared usage exposed/wrong limit: %v", data)
	}
	if len(e.fake.ToolCalls()) != before {
		t.Fatal("quota-refused call reached upstream")
	}
	code, _, out = rawMCP(t, e.app, "POST", "independent", e.key.Secret, rpc(4, "tools/call", map[string]any{"name": "independent__whoami"}), nil)
	if code != 200 || out["error"] != nil {
		t.Fatalf("other server affected: %d %v", code, out)
	}
}
