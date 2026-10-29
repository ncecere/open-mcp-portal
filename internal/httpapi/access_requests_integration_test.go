package httpapi_test

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

func accessSettingsPath(g apitypes.Gateway) string {
	return "/v1/admin/gateways/" + g.Id.String() + "/access-settings"
}
func accessPath(r gateways.AccessRequest) string { return "/v1/access-requests/" + r.ID.String() }

func enableAccessRequests(t *testing.T, e *gwEnv, g apitypes.Gateway, stewards ...uuid.UUID) {
	t.Helper()
	if stewards == nil {
		stewards = []uuid.UUID{}
	}
	cur := e.gateway(e.admin, "/v1/admin/gateways/"+g.Id.String())
	code, ec := e.admin.call("PUT", accessSettingsPath(g), map[string]any{"enabled": true, "stewardIds": stewards}, nil, ifMatch(cur.Revision))
	mustCode(t, "access settings", code, ec, 200, "")
}

func requestAccess(t *testing.T, s *session, g apitypes.Gateway, team *uuid.UUID) gateways.AccessRequest {
	t.Helper()
	body := map[string]any{"gatewayId": g.Id, "reason": "private-reason-sentinel"}
	if team != nil {
		body["teamId"] = *team
	}
	var r gateways.AccessRequest
	code, ec := s.call("POST", "/v1/me/access-requests", body, &r, nil)
	mustCode(t, "request access", code, ec, 201, "")
	return r
}

func TestAccessRequestsVisibilityLifecycleAndPrivacy(t *testing.T) {
	e := newGwEnv(t, nil)
	g := e.createGateway(e.admin, "/v1/admin/gateways", "requestable")
	var page apitypes.RequestableGatewayPage
	if code := e.member.get("/v1/gateways/requestable", &page); code != 200 || len(page.Items) != 0 {
		t.Fatalf("hidden: %d %+v", code, page)
	}
	code, ec := e.member.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "reason": "needed"}, nil, nil)
	mustCode(t, "hidden request", code, ec, 404, "gateway_not_found")
	enableAccessRequests(t, e, g, e.editor.me.User.Id)
	if code := e.member.get("/v1/gateways/requestable", &page); code != 200 || len(page.Items) != 1 || page.Items[0].Id != g.Id {
		t.Fatalf("requestable: %d %+v", code, page)
	}
	if code := e.member.get("/v1/me/gateways/"+g.Id.String(), nil); code != 404 {
		t.Fatalf("opt-in granted access: %d", code)
	}
	for _, reason := range []string{"", " ", strings.Repeat("x", 1001), "bad\x00text"} {
		code, ec = e.member.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "reason": reason}, nil, nil)
		mustCode(t, "invalid reason", code, ec, 400, "invalid_reason")
	}
	r := requestAccess(t, e.member, g, nil)
	code, ec = e.member.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "reason": "duplicate"}, nil, nil)
	mustCode(t, "duplicate", code, ec, 409, "request_pending")
	for _, s := range []*session{e.owner, e.outsider, e.auditor} {
		if code := s.get(accessPath(r), nil); code != 404 {
			t.Errorf("unauthorized private read = %d", code)
		}
		code, ec = s.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
		mustCode(t, "foreign decision", code, ec, 404, "access_request_not_found")
	}
	code, ec = e.member.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
	mustCode(t, "self decision", code, ec, 403, "")
	var review apitypes.AccessRequestPage
	if code := e.editor.get("/v1/me/access-requests?view=review&pendingOnly=true", &review); code != 200 || len(review.Items) != 1 || review.PendingReviewCount != 1 || !review.Items[0].CanDecide {
		t.Fatalf("steward review = %d %+v", code, review)
	}
	code, ec = e.editor.call("PATCH", "/v1/admin/gateways/"+g.Id.String(), map[string]any{"name": "steward cannot edit"}, nil, ifMatch(2))
	mustCode(t, "steward edit", code, ec, 403, "")
	code, ec = e.editor.call("POST", "/v1/admin/gateways/"+g.Id.String()+"/grants", map[string]any{"subjectKind": "group", "group": "everyone"}, nil, nil)
	mustCode(t, "steward direct grant", code, ec, 403, "")
	var decision gateways.AccessRequest
	code, ec = e.editor.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve", "expiresInDays": 2, "note": "private-note-sentinel"}, &decision, nil)
	mustCode(t, "approve", code, ec, 200, "")
	if decision.GrantID == nil || decision.GrantExpiresAt == nil || decision.Status != "approved" || decision.CanDecide {
		t.Fatalf("decision: %+v", decision)
	}
	if code := e.member.get("/v1/me/gateways/"+g.Id.String(), nil); code != 200 {
		t.Fatalf("approved access = %d", code)
	}
	code, ec = e.admin.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "deny"}, nil, nil)
	mustCode(t, "terminal decision", code, ec, 409, "request_decided")
	code, ec = e.member.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "reason": "already granted"}, nil, nil)
	mustCode(t, "already has access", code, ec, 409, "grant_exists")
	var leaked bool
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT EXISTS (SELECT 1 FROM audit_log WHERE row_to_json(audit_log)::text LIKE '%private-reason-sentinel%' OR row_to_json(audit_log)::text LIKE '%private-note-sentinel%') OR EXISTS (SELECT 1 FROM notification_events WHERE payload::text LIKE '%private-reason-sentinel%' OR payload::text LIKE '%private-note-sentinel%')`).Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("private text leaked to audit/notifications")
	}
	entries := auditPage(t, e.admin, "/v1/admin/audit", url.Values{"targetType": {"access_request"}})
	if len(entries.Items) != 2 {
		t.Fatalf("request audits: %+v", entries.Items)
	}
	for _, entry := range entries.Items {
		if entry.TargetLabel == nil || *entry.TargetLabel != g.Name || !entry.TargetExists {
			t.Fatalf("live request audit label: %+v", entry)
		}
	}
	code, ec = e.admin.call("DELETE", "/v1/admin/gateways/"+g.Id.String(), nil, nil, nil)
	mustCode(t, "remove gateway after auditing", code, ec, 200, "")
	entries = auditPage(t, e.admin, "/v1/admin/audit", url.Values{"targetType": {"access_request"}})
	for _, entry := range entries.Items {
		if entry.TargetLabel == nil || *entry.TargetLabel != g.Name || entry.TargetExists {
			t.Fatalf("historical request audit label: %+v", entry)
		}
	}
}

func TestAccessRequestsDenyWithdrawAndSelfAdmin(t *testing.T) {
	e := newGwEnv(t, nil)
	g := e.createGateway(e.admin, "/v1/admin/gateways", "request-decisions")
	enableAccessRequests(t, e, g)
	r := requestAccess(t, e.member, g, nil)
	code, ec := e.outsider.call("POST", accessPath(r)+"/withdraw", nil, nil, nil)
	mustCode(t, "foreign withdraw", code, ec, 404, "access_request_not_found")
	code, ec = e.member.call("POST", accessPath(r)+"/withdraw", nil, nil, nil)
	mustCode(t, "withdraw", code, ec, 200, "")
	r = requestAccess(t, e.member, g, nil)
	code, ec = e.admin.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "deny"}, nil, nil)
	mustCode(t, "deny", code, ec, 200, "")
	code, ec = e.member.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "reason": "again"}, nil, nil)
	mustCode(t, "denial cooldown", code, ec, 409, "request_cooldown")
	if _, ok := myGateways(t, e.member)[g.Slug]; ok {
		t.Fatal("denial granted access")
	}
	r = requestAccess(t, e.admin, g, nil)
	code, ec = e.admin.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
	mustCode(t, "admin self approval", code, ec, 403, "")
}

func TestAccessRequestsTeamAuthorityAndRevokedSteward(t *testing.T) {
	e := newGwEnv(t, nil)
	g := e.createGateway(e.admin, "/v1/admin/gateways", "team-request")
	enableAccessRequests(t, e, g, e.editor.me.User.Id)
	var team uuid.UUID
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT id FROM teams WHERE slug='tools'`).Scan(&team); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*session{e.member, e.editor, e.outsider} {
		code, _ := s.call("POST", "/v1/me/access-requests", map[string]any{"gatewayId": g.Id, "teamId": team, "reason": "request for team"}, nil, nil)
		if code != 403 && code != 404 {
			t.Fatalf("nonadmin team request = %d", code)
		}
	}
	r := requestAccess(t, e.owner, g, &team)
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE team_members SET role='member' WHERE team_id=$1 AND user_id=$2`, team, e.owner.me.User.Id); err != nil {
		t.Fatal(err)
	}
	code, ec := e.admin.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
	mustCode(t, "lost team authority", code, ec, 403, "")
	if _, err := e.app.Pool.Exec(context.Background(), `UPDATE team_members SET role='owner' WHERE team_id=$1 AND user_id=$2`, team, e.owner.me.User.Id); err != nil {
		t.Fatal(err)
	}
	enableAccessRequests(t, e, g)
	code, ec = e.editor.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
	mustCode(t, "removed steward", code, ec, 404, "access_request_not_found")
	code, ec = e.admin.call("POST", accessPath(r)+"/decision", map[string]any{"decision": "approve"}, nil, nil)
	mustCode(t, "team approve", code, ec, 200, "")
	for _, s := range []*session{e.owner, e.editor, e.member} {
		if _, ok := myGateways(t, s)[g.Slug]; !ok {
			t.Errorf("team member lacks approved access: %s", s.me.User.Id)
		}
	}
	var count int
	if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM gateway_grants WHERE gateway_id=$1 AND team_id=$2`, g.Id, team).Scan(&count); err != nil || count != 1 {
		t.Fatalf("team grants=%d err=%v", count, err)
	}
}

func TestGatewayGrantExpiryAllSubjectKindsWithoutCleanup(t *testing.T) {
	e := newGwEnv(t, nil)
	for _, kind := range []string{"user", "team", "group"} {
		t.Run(kind, func(t *testing.T) {
			g := e.createGateway(e.admin, "/v1/admin/gateways", "expires-"+kind)
			body := map[string]any{"subjectKind": kind, "expiresInDays": 1}
			switch kind {
			case "user":
				body["userEmail"] = "blair@localhost"
			case "team":
				body["team"] = "tools"
			case "group":
				body["group"] = "support"
			}
			var grant apitypes.GatewayGrant
			code, ec := e.admin.call("POST", fmt.Sprintf("/v1/admin/gateways/%s/grants", g.Id), body, &grant, nil)
			mustCode(t, "create expiring grant", code, ec, 201, "")
			if grant.ExpiresAt == nil {
				t.Fatal("expiry missing")
			}
			if _, ok := myGateways(t, e.member)[g.Slug]; !ok {
				t.Fatal("new grant is not effective")
			}
			if _, err := e.app.Pool.Exec(context.Background(), `UPDATE gateway_grants SET expires_at=clock_timestamp() WHERE id=$1`, grant.Id); err != nil {
				t.Fatal(err)
			}
			if _, ok := myGateways(t, e.member)[g.Slug]; ok {
				t.Fatal("expired grant is effective before cleanup")
			}
			if code := e.member.get("/v1/me/gateways/"+g.Id.String(), nil); code != 404 {
				t.Fatalf("expired detail=%d", code)
			}
			var count int
			if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM gateway_grants WHERE id=$1`, grant.Id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("test accidentally cleaned grant: %d %v", count, err)
			}
		})
	}
}
