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
			expected := 202 // original enabled fixture plus 201 disabled team rules
			if tc.targetKind == "gateway" {
				// Admin reads are portal-wide metadata oversight, so this also
				// includes the team rules seeded by the preceding subtest.
				expected += 201
			}
			seen := map[string]bool{}
			current := first
			for pages := 0; ; pages++ {
				if pages > 3 {
					t.Fatal("rule pagination did not terminate")
				}
				for _, r := range current.Items {
					if seen[r.ID.String()] {
						t.Fatal("duplicate across rule pages")
					}
					seen[r.ID.String()] = true
				}
				if current.NextCursor == nil {
					break
				}
				cursor := *current.NextCursor
				current = page{}
				if code, ec := tc.s.call("GET", path+"?limit=200&cursor="+url.QueryEscape(cursor), nil, &current, nil); code != 200 {
					t.Fatalf("continuation rejected: %d %s", code, ec)
				}
				if len(current.Items) < 1 || len(current.Items) > 200 {
					t.Fatalf("bad page size: %d", len(current.Items))
				}
			}
			if len(seen) != expected {
				t.Fatalf("rule pages lost rows: got %d want %d", len(seen), expected)
			}
		})
	}
}
