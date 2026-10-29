package httpapi_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServerEndpointsOwnerOriginNullAndPreservation(t *testing.T) {
	e := newRegistryEnv(t)
	extra := testutil.NewFakeMCP(t)
	third := testutil.NewFakeMCP(t)
	primarySecret, extraSecret := "primary-private-value-6724", "extra-private-value-8391"
	part := func(value string) []any {
		return []any{map[string]any{"kind": "header", "name": "X-Key", "value": value}}
	}
	body := map[string]any{"slug": "endpoint-owner", "name": "Endpoint owner", "url": e.fake.URL(), "authMode": "static_header", "credentials": part(primarySecret), "endpoints": []any{map[string]any{"url": extra.URL(), "credentials": part(extraSecret)}}}
	code, ec := e.editor.call("POST", toolsTeam+"/mcp-servers", body, nil, nil)
	mustCode(t, "editor cannot create endpoints", code, ec, 403, "forbidden")
	var made apitypes.McpServerCreated
	code, ec = e.owner.call("POST", toolsTeam+"/mcp-servers", body, &made, nil)
	mustCode(t, "owner creates independent endpoint", code, ec, 201, "")
	sv := made.Server
	path := toolsTeam + "/mcp-servers/" + sv.Id.String()
	if sv.Endpoints == nil || len(*sv.Endpoints) != 1 {
		t.Fatal("missing endpoint view")
	}
	ep := (*sv.Endpoints)[0]
	if ep.Url != extra.URL() || ep.AuthMode != "static_header" || ep.Credentials[0].Hint != "8391" {
		t.Fatalf("public endpoint view: %+v", ep)
	}
	if code, raw := e.owner.raw("GET", path, nil, nil); code != 200 || strings.Contains(string(raw), primarySecret) || strings.Contains(string(raw), extraSecret) || strings.Contains(string(raw), "credentials_cipher") {
		t.Fatal("secret escaped endpoint view")
	}
	patch := func(s *session, body map[string]any, want int, errCode string) apitypes.McpServer {
		t.Helper()
		cur := e.server(e.owner, sv.Id.String())
		var out apitypes.McpServer
		code, ec := s.call("PATCH", path, body, &out, ifMatch(cur.Revision))
		mustCode(t, "endpoint patch", code, ec, want, errCode)
		return out
	}
	for _, s := range []*session{e.editor, e.member, e.admin} {
		patch(s, map[string]any{"endpoints": []any{}}, 403, "forbidden")
	}
	for _, v := range []any{nil, []any{nil}, []any{map[string]any{"url": extra.URL(), "credentials": nil}}, []any{map[string]any{"url": extra.URL(), "enabled": nil}}} {
		patch(e.owner, map[string]any{"endpoints": v}, 400, "invalid_endpoints")
	}
	patch(e.owner, map[string]any{"endpoints": []any{map[string]any{"url": e.fake.URL(), "credentials": part(extraSecret)}}}, 400, "duplicate_endpoint")
	patch(e.owner, map[string]any{"name": "Metadata keeps endpoints"}, 200, "")
	cur := e.server(e.owner, sv.Id.String())
	if cur.Endpoints == nil || (*cur.Endpoints)[0].Id != ep.Id {
		t.Fatal("metadata lost endpoint")
	}
	noOp := []any{map[string]any{"id": ep.Id.String(), "url": extra.URL()}}
	out := patch(e.owner, map[string]any{"endpoints": noOp}, 200, "")
	if out.Revision != cur.Revision {
		t.Fatal("retention needlessly changed revision")
	}
	patch(e.owner, map[string]any{"endpoints": []any{map[string]any{"id": ep.Id.String(), "url": third.URL()}}}, 422, "auth_value_required")
	patch(e.owner, map[string]any{"endpoints": []any{map[string]any{"id": ep.Id.String(), "url": third.URL(), "credentials": []any{map[string]any{"kind": "header", "name": "X-Key", "keep": true}}}}}, 422, "auth_value_required")
	newURL := third.URL() + "/private-endpoint-path"
	out = patch(e.owner, map[string]any{"endpoints": []any{map[string]any{"id": ep.Id.String(), "url": newURL, "credentials": part("reentered-private-secret-1842")}}}, 200, "")
	var origin, auditState string
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT after_state->'endpoints'->0->>'origin',after_state::text FROM audit_log WHERE target_id=$1 AND action='mcp_server.update' ORDER BY id DESC LIMIT 1`, sv.Id.String()).Scan(&origin, &auditState); err != nil {
		t.Fatal(err)
	}
	if origin != registry.OriginOf(newURL) || strings.Contains(auditState, "private-endpoint-path") || strings.Contains(auditState, "private-secret") {
		t.Fatal("endpoint audit leaked a path/value or lost origin")
	}
	code, ec = e.owner.call("PATCH", path, map[string]any{"endpoints": []any{}}, nil, ifMatch(cur.Revision))
	mustCode(t, "stale endpoint revision", code, ec, 412, "revision_conflict")
	out = patch(e.owner, map[string]any{"endpoints": []any{}}, 200, "")
	if out.Endpoints == nil || len(*out.Endpoints) != 0 {
		t.Fatal("empty list did not clear")
	}
}

func TestServerEndpointsReviewDigestAndUnsupportedMode(t *testing.T) {
	e := newGwEnv(t, nil)
	e.publish(e.owner, e.server)
	extra := testutil.NewFakeMCP(t)
	path := toolsTeam + "/mcp-servers/" + e.server.Id.String()
	var old apitypes.McpServer
	e.owner.get(path, &old)
	code, ec := e.owner.call("PATCH", path, map[string]any{"endpoints": []any{map[string]any{"url": extra.URL()}}}, nil, ifMatch(old.Revision))
	mustCode(t, "add reviewed destination", code, ec, 200, "")
	var cur apitypes.McpServer
	e.owner.get(path, &cur)
	if cur.PublishState != "pending" || cur.ReviewDigest == nil || old.ReviewDigest == nil || *cur.ReviewDigest == *old.ReviewDigest {
		t.Fatal("endpoint change did not invalidate catalog review")
	}
	code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+cur.Id.String()+"/review", map[string]any{"decision": "approve", "expectedDigest": *old.ReviewDigest}, nil, nil)
	mustCode(t, "old endpoint review", code, ec, 409, "changed_since_review")
	code, ec = e.admin.call("POST", "/v1/admin/mcp-servers/"+cur.Id.String()+"/review", approveBody(t, e.admin, cur.Id.String()), nil, nil)
	mustCode(t, "review endpoint", code, ec, 200, "")
	if reason := e.scalar(`SELECT metadata->>'reason' FROM audit_log WHERE action='mcp_server.publish_request' ORDER BY id DESC LIMIT 1`); reason != "endpoints_changed" {
		t.Fatalf("wrong review reason %s", reason)
	}
	for _, mode := range []string{"oauth", "machine_oauth"} {
		e.owner.get(path, &cur)
		body := map[string]any{"authMode": mode}
		if mode == "machine_oauth" {
			body["machineOAuth"] = map[string]any{"tokenUrl": extra.URL() + "/token", "clientId": "owned-fixture", "clientSecret": "not-for-another-endpoint"}
		}
		code, ec = e.owner.call("PATCH", path, body, nil, ifMatch(cur.Revision))
		mustCode(t, fmt.Sprintf("unsupported %s", mode), code, ec, 422, "failover_not_supported")
	}
}
