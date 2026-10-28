package httpapi_test

import (
	"context"
	"net/url"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestApprovalsHTTPRuleListMaximumPageAndContinuation(t *testing.T) {
	e := newApprovalWire(t, testutil.ProtocolModern, nil)
	gw := e.createGateway(e.admin, "/v1/admin/gateways", "approval-pagination")
	// Seed disabled policies through authenticated runtime SQL; this is a
	// pagination fixture, not a bypass of management-rule overlap validation.
	for _, tc := range []struct {
		scope, targetKind, targetID string
		s                           *session
	}{
		{toolsTeam, "server", e.server.Id.String(), e.owner},
		{"/v1/admin", "gateway", gw.Id.String(), e.admin},
	} {
		t.Run(tc.targetKind, func(t *testing.T) {
			var team any
			if tc.targetKind == "server" {
				if err := e.app.Pool.QueryRow(context.Background(), `SELECT team_id::text FROM mcp_servers WHERE id=$1`, e.server.Id).Scan(&team); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := e.app.Pool.Exec(context.Background(), `INSERT INTO approval_rules(name,team_id,target_kind,target_id,classes,enabled,created_by)
    SELECT 'Page rule '||n,$1::uuid,$2,$3::uuid,ARRAY['destructive'],false,$4::uuid FROM generate_series(1,201)n`, team, tc.targetKind, tc.targetID, e.userID("admin@localhost")); err != nil {
				t.Fatal(err)
			}
			path := tc.scope + "/approval-rules"
			type page struct {
				Items      []approvals.Rule `json:"items"`
				NextCursor *string          `json:"nextCursor"`
			}
			var first page
			if code, ec := tc.s.call("GET", path+"?limit=200", nil, &first, nil); code != 200 {
				t.Fatalf("valid maximum page rejected: %d %s", code, ec)
			}
			if len(first.Items) != 200 || first.NextCursor == nil {
				t.Fatalf("first page: n=%d cursor=%v", len(first.Items), first.NextCursor)
			}
			var next page
			if code, ec := tc.s.call("GET", path+"?limit=200&cursor="+url.QueryEscape(*first.NextCursor), nil, &next, nil); code != 200 {
				t.Fatalf("continuation rejected: %d %s", code, ec)
			}
			expected := 1
			if tc.targetKind == "server" {
				expected++
			} // the original enabled fixture rule
			if len(next.Items) != expected || next.NextCursor != nil {
				t.Fatalf("last page: n=%d cursor=%v", len(next.Items), next.NextCursor)
			}
			seen := map[string]bool{}
			for _, r := range first.Items {
				seen[r.ID.String()] = true
			}
			for _, r := range next.Items {
				if seen[r.ID.String()] {
					t.Fatal("duplicate across rule pages")
				}
			}
		})
	}
}
