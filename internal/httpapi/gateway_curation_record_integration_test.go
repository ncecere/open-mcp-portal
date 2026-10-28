package httpapi_test

import (
	"fmt"
	"strings"
	"testing"
)

var curationRefreshCases = []struct {
	change   string
	identity bool
}{{"policy", true}, {"policy", false}, {"disabled", true}, {"disabled", false}}

func enableCurationCapture(t *testing.T, e *gwEnv, path string) {
	t.Helper()
	g := e.gateway(e.owner, path)
	code, ec := e.owner.call("PATCH", path, map[string]any{"capturePayloads": true}, nil, ifMatch(g.Revision))
	mustCode(t, "capture attempted call", code, ec, 200, "")
}

func curationLastCall(t *testing.T, e *gwEnv) int64 {
	t.Helper()
	var id int64
	if err := e.app.Pool.QueryRow(t.Context(), `SELECT coalesce(max(id),0) FROM mcp_calls`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertCurationRefusalRecord(t *testing.T, e *gwEnv, after int64, sent *bool, change string) {
	t.Helper()
	var count int
	if err := e.app.Pool.QueryRow(t.Context(), `SELECT count(*) FROM mcp_calls WHERE id>$1 AND method='tools/call'`, after).Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected one final refusal record, got %d: %v", count, err)
	}
	var identity *bool
	var outcome, class, requestID string
	var sameMetadata bool
	err := e.app.Pool.QueryRow(t.Context(), `SELECT identity_sent, outcome, error_class, request_id,
		(server_id, server_slug, server_name, server_team_id, capability_id, tool_class, exposed_name, provider_slug)
		IS NOT DISTINCT FROM (SELECT ROW(server_id, server_slug, server_name, server_team_id, capability_id, tool_class, exposed_name, provider_slug) FROM mcp_calls WHERE id=$1)
		FROM mcp_calls WHERE id>$1 AND method='tools/call'`, after).Scan(&identity, &outcome, &class, &requestID, &sameMetadata)
	if err != nil {
		t.Fatal(err)
	}
	wantClass := "curation_changed"
	if change == "disabled" {
		wantClass = "gateway_disabled"
	}
	if outcome != "denied" || class != wantClass || requestID == "" {
		t.Fatalf("refusal outcome/class/request: %q %q %q", outcome, class, requestID)
	}
	if (identity == nil) != (sent == nil) || (sent != nil && *identity != *sent) {
		t.Fatalf("identity_sent=%v, expected %v", identity, sent)
	}
	if sent != nil {
		if !sameMetadata {
			t.Fatal("post-transport refusal lost the attempted server/capability/class/provider metadata")
		}
		var id int64
		if err := e.app.Pool.QueryRow(t.Context(), `SELECT p.call_id FROM mcp_call_payloads p JOIN mcp_calls c ON c.id=p.call_id WHERE c.id>$1 AND c.method='tools/call'`, after).Scan(&id); err != nil {
			t.Fatalf("post-transport refusal lost its captured payload: %v", err)
		}
		code, raw := e.admin.raw("GET", fmt.Sprintf("/v1/admin/calls/%d/payload", id), nil, nil)
		if code != 200 || !strings.Contains(string(raw), "original") || strings.Contains(string(raw), "replacement") {
			t.Fatalf("captured arguments no longer describe the actual first attempt: %d %s", code, raw)
		}
	}
}
