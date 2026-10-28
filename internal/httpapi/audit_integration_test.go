package httpapi_test

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
)

// auditPage reads one page of an audit log with the given filters.
func auditPage(t *testing.T, s *session, path string, filters url.Values) apitypes.AuditPage {
	t.Helper()
	var page apitypes.AuditPage
	if code, e := s.call("GET", path+"?"+filters.Encode(), nil, &page, nil); code != 200 {
		t.Fatalf("GET %s?%s = %d %s", path, filters.Encode(), code, e)
	}
	return page
}

func auditActions(p apitypes.AuditPage) []string {
	out := make([]string, len(p.Items))
	for i, e := range p.Items {
		out[i] = e.Action
	}
	return out
}

func findAudit(t *testing.T, p apitypes.AuditPage, action, targetID string) apitypes.AuditEntry {
	t.Helper()
	for _, e := range p.Items {
		if e.Action == action && (targetID == "" || e.TargetId == targetID) {
			return e
		}
	}
	t.Fatalf("no %s entry for %q in %v", action, targetID, auditActions(p))
	return apitypes.AuditEntry{}
}

// Actors and target names are resolved when the log is read: renamed targets
// show their current name; the system's entries have no person.
func TestAuditActorsAndTargetLabels(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	user := app.signIn("user")
	created := createTeam(t, admin, "tools", "user@localhost")
	code, e := admin.call("PATCH", "/v1/admin/teams/tools", map[string]string{"name": "Platform Tools"}, nil, ifMatch(created.Team.Team.Revision))
	mustCode(t, "rename", code, e, 200, "")
	var added apitypes.MemberAddResult
	user.refresh()
	user.call("POST", "/v1/teams/tools/members", map[string]string{"email": "later@example.com", "role": "member"}, &added, nil)

	all := auditPage(t, admin, "/v1/admin/audit", url.Values{"limit": {"200"}})
	team := findAudit(t, all, "team.create", created.Team.Team.Id.String())
	if team.TargetLabel == nil || *team.TargetLabel != "Platform Tools" || !team.TargetExists {
		t.Errorf("renamed team label = %v exists=%v", team.TargetLabel, team.TargetExists)
	}
	if team.TeamSlug == nil || *team.TeamSlug != "tools" || team.TeamName == nil || *team.TeamName != "Platform Tools" {
		t.Errorf("team of entry = %v %v", team.TeamSlug, team.TeamName)
	}
	if team.Actor.Kind != "user" || team.Actor.Email == nil || *team.Actor.Email != "admin@localhost" ||
		team.Actor.DisplayName == nil || *team.Actor.DisplayName != "Dev Platform Admin" || team.Via == nil || team.Via.Kind != "session" {
		t.Errorf("actor = %+v via %+v", team.Actor, team.Via)
	}
	if team.ClientIp == nil || team.RequestId == "" {
		t.Errorf("platform log entry lacks client IP or request ID: %+v", team)
	}
	if team.After == nil {
		t.Errorf("team.create has no after-state")
	}
	inv := findAudit(t, all, "team.invite_create", added.Invite.Id.String())
	if inv.TargetLabel == nil || *inv.TargetLabel != "later@example.com" {
		t.Errorf("invite label = %v", inv.TargetLabel)
	}
	boot := findAudit(t, all, "platform.bootstrap_role", "")
	if boot.ActorKind != "system" || boot.Actor.UserId != nil || boot.Via != nil {
		t.Errorf("bootstrap entry = %+v", boot)
	}
	member := findAudit(t, all, "team.owner_assign", user.me.User.Id.String())
	if member.TargetLabel == nil || *member.TargetLabel != "Dev User" {
		t.Errorf("user label = %v", member.TargetLabel)
	}

	// A target that no longer exists keeps the last name the log recorded.
	ctx := context.Background()
	if _, err := app.Pool.Exec(ctx, "DELETE FROM teams WHERE slug = 'tools'"); err != nil {
		t.Fatal(err)
	}
	all = auditPage(t, admin, "/v1/admin/audit", url.Values{"limit": {"200"}})
	gone := findAudit(t, all, "team.create", created.Team.Team.Id.String())
	if gone.TargetExists || gone.TargetLabel == nil || *gone.TargetLabel != "Platform Tools" || gone.TeamName != nil {
		t.Errorf("deleted team = exists %v label %v team %v", gone.TargetExists, gone.TargetLabel, gone.TeamName)
	}
}

func TestAuditFilters(t *testing.T) {
	app := newTestApp(t, nil)
	admin := app.signIn("admin")
	owner := app.signIn("user")
	start := time.Now().UTC().Add(-time.Minute)
	createTeam(t, admin, "tools", "user@localhost")
	owner.refresh()
	base := "/v1/teams/tools"
	for _, email := range []string{"a@example.com", "b@example.com"} {
		code, e := owner.call("POST", base+"/members", map[string]string{"email": email, "role": "member"}, nil, nil)
		mustCode(t, "invite "+email, code, e, 201, "")
	}

	only := func(p apitypes.AuditPage, check func(apitypes.AuditEntry) bool, want int, what string) {
		t.Helper()
		if want >= 0 && len(p.Items) != want {
			t.Fatalf("%s: %d entries %v, want %d", what, len(p.Items), auditActions(p), want)
		}
		for _, e := range p.Items {
			if check != nil && !check(e) {
				t.Errorf("%s: unexpected %s on %s", what, e.Action, e.TargetType)
			}
		}
	}
	isAction := func(a string) func(apitypes.AuditEntry) bool {
		return func(e apitypes.AuditEntry) bool { return e.Action == a }
	}
	only(auditPage(t, owner, base+"/audit", url.Values{"action": {"team.invite_create"}}), isAction("team.invite_create"), 2, "exact action")
	only(auditPage(t, owner, base+"/audit", url.Values{"action": {"team."}}),
		func(e apitypes.AuditEntry) bool { return strings.HasPrefix(e.Action, "team.") }, 4, "action group")
	only(auditPage(t, owner, base+"/audit", url.Values{"targetType": {"team_invite"}}), isAction("team.invite_create"), 2, "target type")
	only(auditPage(t, owner, base+"/audit", url.Values{"actorUserId": {owner.me.User.Id.String()}}), isAction("team.invite_create"), 2, "actor")
	// The team was created by the platform admin, not the owner.
	byAdmin := auditPage(t, owner, base+"/audit", url.Values{"actorUserId": {admin.me.User.Id.String()}})
	findAudit(t, byAdmin, "team.create", "")
	only(byAdmin, func(e apitypes.AuditEntry) bool { return *e.Actor.UserId == admin.me.User.Id }, 2, "admin actor")
	// "_" in a prefix is literal, not a LIKE wildcard.
	only(auditPage(t, owner, base+"/audit", url.Values{"action": {"tea_."}}), nil, 0, "escaped prefix")

	// Time window: from is inclusive, to exclusive.
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	only(auditPage(t, owner, base+"/audit", url.Values{"from": {future}}), nil, 0, "from future")
	only(auditPage(t, owner, base+"/audit", url.Values{"to": {start.Add(-time.Hour).Format(time.RFC3339)}}), nil, 0, "to past")
	only(auditPage(t, owner, base+"/audit", url.Values{"action": {"team.invite_create"}, "from": {start.Format(time.RFC3339Nano)}, "to": {future}}),
		isAction("team.invite_create"), 2, "window")

	// Paging keeps the filters.
	first := auditPage(t, owner, base+"/audit", url.Values{"action": {"team."}, "limit": {"3"}})
	if len(first.Items) != 3 || first.NextCursor == nil {
		t.Fatalf("first page = %v %v", auditActions(first), first.NextCursor)
	}
	second := auditPage(t, owner, base+"/audit", url.Values{"action": {"team."}, "limit": {"3"}, "cursor": {*first.NextCursor}})
	only(second, func(e apitypes.AuditEntry) bool { return strings.HasPrefix(e.Action, "team.") }, 1, "second page")
	if second.NextCursor != nil {
		t.Errorf("last page has a cursor")
	}

	// excludeAction hides a group (the admin log hides sign-ins by default);
	// actorKind=system is the system's entries.
	only(auditPage(t, admin, "/v1/admin/audit", url.Values{"excludeAction": {"auth."}}),
		func(e apitypes.AuditEntry) bool { return !strings.HasPrefix(e.Action, "auth.") }, -1, "exclude sign-ins")
	if n := len(auditPage(t, admin, "/v1/admin/audit", url.Values{"action": {"auth."}}).Items); n == 0 {
		t.Error("expected sign-ins in the platform log")
	}
	only(auditPage(t, admin, "/v1/admin/audit", url.Values{"actorKind": {"system"}}),
		func(e apitypes.AuditEntry) bool {
			return e.Action == "platform.bootstrap_role" || e.Action == "agent_platform.retire"
		}, 2, "system entries")

	for _, bad := range []struct{ query, code string }{
		{"action=team", "invalid_action"},
		{"action=TEAM.create", "invalid_action"},
		{"excludeAction=auth.login", "invalid_action"},
		{"actorUserId=someone", "invalid_actor"},
		{"actorKind=group_mapping", "invalid_actor_kind"},
		{"targetType=Team-Invite", "invalid_target_type"},
		{"from=yesterday", "invalid_range"},
		{"from=" + future + "&to=" + future, "invalid_range"},
		{"cursor=bad", "invalid_cursor"},
	} {
		code, e := owner.call("GET", base+"/audit?"+strings.ReplaceAll(bad.query, "+", "%2B"), nil, nil, nil)
		mustCode(t, bad.query, code, e, 400, bad.code)
	}
}
