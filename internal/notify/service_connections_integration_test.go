package notify

import (
	"context"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func TestServiceConnectionRecipientsAreLiveTeamAdmins(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("shared")
	other := e.team("foreign")
	owner, admin, member, suspended, outsider := e.user("none"), e.user("none"), e.user("none"), e.user("none"), e.user("platform_admin")
	e.member(team, owner, "owner")
	e.member(team, admin, "admin")
	e.member(team, member, "member")
	e.member(team, suspended, "admin")
	e.member(other, outsider, "owner")
	id := uuid.New()
	e.svc.ServiceConnectionReconsent(context.Background(), e.q, id, team, "github", "GitHub", 1)
	e.svc.ServiceConnectionReconsent(context.Background(), e.q, id, team, "github", "GitHub", 1)
	if n := len(e.events(ConnectionNeedsReconsent)); n != 1 {
		t.Fatalf("dedup: %d", n)
	}
	var eventID int64
	if err := e.pool.QueryRow(context.Background(), `SELECT id FROM notification_events WHERE event=$1`, ConnectionNeedsReconsent).Scan(&eventID); err != nil {
		t.Fatal(err)
	}
	event, err := e.q.GetNotificationEvent(context.Background(), eventID)
	if err != nil {
		t.Fatal(err)
	}
	message := compose(event, &teamInfo{ID: team, Slug: "shared", Name: "Shared"})
	if message.Link == nil || message.Link.Type != LinkServiceConnections || message.Link.path() != "/teams/shared/service-accounts?tab=connections" || !strings.Contains(message.Body, "shared connection") || strings.Contains(message.Body, "Your connection") {
		t.Fatalf("shared event was composed as personal: %+v", message)
	}
	e.run(`UPDATE team_members SET role='member' WHERE user_id=$1`, admin)
	e.run(`UPDATE team_members SET role='admin' WHERE user_id=$1`, member)
	e.run(`UPDATE users SET status='suspended' WHERE id=$1`, suspended)
	e.fanOutAll()
	for u, want := range map[uuid.UUID]int{owner: 1, admin: 0, member: 1, suspended: 0, outsider: 0} {
		if n := e.inbox(u); n != want {
			t.Errorf("recipient %s: %d want %d", u, n, want)
		}
	}
	if n := e.count(`SELECT count(*) FROM notification_events WHERE subject_type='service_connection' AND recipient_user_id IS NOT NULL`); n != 0 {
		t.Fatal("shared event had a personal recipient")
	}
}
