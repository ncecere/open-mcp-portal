package httpapi_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServerEndpointsHealthUsesIndependentCredentialAndHistory(t *testing.T) {
	e := newRegistryEnv(t)
	secondary, handler := testutil.NewFakeMCPHandler()
	secondary.RequireHeader("X-Replica-Key", "independent-replica-private-7842")
	var wrongCredential atomic.Bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Replica-Key") != "independent-replica-private-7842" || r.Header.Get("X-Primary-Key") != "" {
			wrongCredential.Store(true)
		}
		handler.ServeHTTP(w, r)
	}))
	defer ts.Close()
	var made apitypes.McpServerCreated
	code, ec := e.owner.call("POST", toolsTeam+"/mcp-servers", map[string]any{
		"slug": "endpoint-health", "name": "Endpoint health", "url": e.fake.URL(), "authMode": "static_header",
		"credentials": []any{map[string]any{"kind": "header", "name": "X-Primary-Key", "value": "primary-private-3294"}},
		"endpoints":   []any{map[string]any{"url": ts.URL, "credentials": []any{map[string]any{"kind": "header", "name": "X-Replica-Key", "value": "independent-replica-private-7842"}}}},
	}, &made, nil)
	mustCode(t, "create health replicas", code, ec, 201, "")
	path := toolsTeam + "/mcp-servers/" + made.Server.Id.String()
	id := (*made.Server.Endpoints)[0].Id
	check := func() []apitypes.McpHealthCheck {
		t.Helper()
		c, ec := e.owner.call("POST", path+"/test", nil, nil, nil)
		mustCode(t, "test both endpoints", c, ec, 200, "")
		var rows []apitypes.McpHealthCheck
		if c := e.owner.get(path+"/health-checks", &rows); c != 200 {
			t.Fatal(c)
		}
		return rows
	}
	rows := check()
	var extra *apitypes.McpHealthCheck
	for i := range rows {
		if rows[i].EndpointId != nil && *rows[i].EndpointId == id {
			extra = &rows[i]
			break
		}
	}
	if extra == nil || !extra.Ok || extra.EndpointPosition == nil || *extra.EndpointPosition != 1 || wrongCredential.Load() {
		t.Fatalf("endpoint health identity/credential: %+v wrong=%v", extra, wrongCredential.Load())
	}
	secondary.SetDescription("check_outage", "Different advertised definition")
	rows = check()
	extra = nil
	for i := range rows {
		if rows[i].EndpointId != nil && *rows[i].EndpointId == id {
			extra = &rows[i]
			break
		}
	}
	if extra == nil || extra.Ok || extra.ErrorClass == nil || *extra.ErrorClass != "not_allowed" {
		t.Fatalf("mismatched replica health accepted: %+v", extra)
	}
	cur := e.server(e.owner, made.Server.Id.String())
	if cur.Health.Status != "healthy" {
		t.Fatal("extra mismatch overwrote canonical primary health")
	}
	code, ec = e.owner.call("PATCH", path, map[string]any{"endpoints": []any{}}, nil, ifMatch(cur.Revision))
	mustCode(t, "clear extra", code, ec, 200, "")
	// Deleting an endpoint preserves its check identity/position as history.
	var count int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM mcp_server_endpoints WHERE id=$1`, id).Scan(&count); err != nil || count != 0 {
		t.Fatalf("endpoint removal: %d %v", count, err)
	}
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM mcp_health_checks WHERE endpoint_id=$1 AND endpoint_position=1`, id).Scan(&count); err != nil || count < 2 {
		t.Fatalf("deleted endpoint lost historical checks: %d %v", count, err)
	}
}
