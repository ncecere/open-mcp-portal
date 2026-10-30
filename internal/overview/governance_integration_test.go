package overview

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
)

func authActor(id uuid.UUID) authz.Actor { return authz.Actor{UserID: id} }

// A published server nobody is accountable for is an attention item: none
// named, or the owner left, lost their editor role, was suspended or deleted.
func TestOwnerlessServersAreAttention(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pa := f.user("platform_admin")
	team, other, archived := f.team("ops"), f.team("data"), f.team("old")
	person := func(tm any, role string) string {
		u := f.user("none")
		f.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)`, tm, u, role)
		return u.String()
	}
	owned := func(tm any, state, owner string) string {
		s := f.server(team, state, true)
		f.run(`UPDATE mcp_servers SET team_id = $2, owner_user_id = NULLIF($3, '')::uuid WHERE id = $1`, s, tm, owner)
		return s.String()
	}
	editor := person(team, "editor")
	good := owned(team, "published", editor)
	none := owned(team, "published", "")
	left := owned(team, "published", person(other, "owner")) // an owner of another team: not this team's
	demoted := person(team, "member")
	notEditor := owned(team, "published", demoted)
	gone := person(team, "editor")
	suspended := owned(team, "published", gone)
	f.run(`UPDATE users SET status = 'suspended' WHERE id = $1`, gone)
	removed := person(team, "admin")
	removedServer := owned(team, "published", removed)
	f.run(`DELETE FROM team_members WHERE user_id = $1`, removed)
	deleted := person(team, "editor")
	deletedServer := owned(team, "published", deleted)
	f.run(`DELETE FROM users WHERE id = $1`, deleted) // ON DELETE SET NULL
	private := owned(team, "private", "")
	archivedServer := owned(archived, "published", "")
	f.run(`UPDATE teams SET status = 'archived' WHERE id = $1`, archived)
	if f.exec(`SELECT (owner_user_id IS NULL)::text FROM mcp_servers WHERE id = $1::uuid`, deletedServer) != "true" {
		t.Fatal("a deleted owner did not clear the owner")
	}

	o, err := f.svc.Admin(ctx, admin(pa))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, it := range find(o.Attention, ServerOwnerless) {
		got[it.Subject.ID] = it
	}
	for name, id := range map[string]string{"none named": none, "another team's owner": left, "a member": notEditor, "suspended": suspended, "removed": removedServer, "deleted": deletedServer} {
		it, ok := got[id]
		if !ok || it.Severity != Warning || it.Link == nil || it.Link.Type != LinkServer || it.Link.TeamSlug != "ops" {
			t.Errorf("%s is not listed: %+v", name, it)
		}
	}
	for name, id := range map[string]string{"an editor owner": good, "a private server": private, "an archived team's": archivedServer} {
		if _, ok := got[id]; ok {
			t.Errorf("%s is listed", name)
		}
	}
	if o.Totals[ServerOwnerless] != 6 {
		t.Errorf("total = %d, want 6", o.Totals[ServerOwnerless])
	}
	// The team's card shows it to its members; another team's does not.
	tm, err := f.svc.Team(ctx, admin(pa), "ops")
	if err != nil || len(find(tm.Attention, ServerOwnerless)) != 6 {
		t.Errorf("team card: %d %v", len(find(tm.Attention, ServerOwnerless)), err)
	}
	if tm, _ = f.svc.Team(ctx, admin(pa), "data"); len(find(tm.Attention, ServerOwnerless)) != 0 {
		t.Error("another team's card lists them")
	}
	// Naming an owner clears it.
	f.run(`UPDATE mcp_servers SET owner_user_id = $2 WHERE id = $1::uuid`, none, editor)
	if o, _ = f.svc.Admin(ctx, admin(pa)); o.Totals[ServerOwnerless] != 5 {
		t.Errorf("after naming an owner: %d", o.Totals[ServerOwnerless])
	}
}

func TestReviewDueIsAttention(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pa := f.user("platform_admin")
	team := f.team("ops")
	late, soon, none, priv := f.server(team, "published", true), f.server(team, "published", true), f.server(team, "published", true), f.server(team, "private", true)
	f.run(`UPDATE mcp_servers SET review_due_at = now() - interval '3 days' WHERE id = $1`, late)
	f.run(`UPDATE mcp_servers SET review_due_at = now() + interval '3 days' WHERE id = $1`, soon)
	f.run(`UPDATE mcp_servers SET review_due_at = now() - interval '3 days' WHERE id = $1`, priv)
	_ = none
	o, err := f.svc.Admin(ctx, admin(pa))
	if err != nil {
		t.Fatal(err)
	}
	items := find(o.Attention, ReviewDue)
	if len(items) != 1 || items[0].Subject.ID != late.String() || items[0].Severity != Warning || items[0].At == nil || time.Since(*items[0].At) < 71*time.Hour || o.Totals[ReviewDue] != 1 {
		t.Fatalf("review due: %+v totals %v", items, o.Totals)
	}
	// The clock of the service decides what is due.
	f.svc.SetClock(func() time.Time { return time.Now().Add(7 * 24 * time.Hour) })
	if o, _ = f.svc.Admin(ctx, admin(pa)); o.Totals[ReviewDue] != 2 {
		t.Errorf("a week later: %d", o.Totals[ReviewDue])
	}
}

// Transfers waiting for a team are shown to its owners only.
func TestPendingTransfersAreForTheReceivingOwners(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	from, to := f.team("from"), f.team("to")
	owner, adminUser, editor := f.user("none"), f.user("none"), f.user("none")
	for u, role := range map[uuid.UUID]string{owner: "owner", adminUser: "admin", editor: "editor"} {
		f.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)`, to, u, role)
	}
	srv := f.server(from, "private", true)
	f.run(`INSERT INTO server_transfers (server_id, from_team_id, to_team_id, server_revision) VALUES ($1, $2, $3, 1)`, srv, from, to)
	for name, c := range map[string]struct {
		who  uuid.UUID
		want int
	}{"owner": {owner, 1}, "admin": {adminUser, 0}, "editor": {editor, 0}} {
		tm, err := f.svc.Team(ctx, authActor(c.who), "to")
		if err != nil || len(find(tm.Attention, ServerTransferPending)) != c.want {
			t.Errorf("%s: %d items, %v", name, len(find(tm.Attention, ServerTransferPending)), err)
		}
	}
	if tm, _ := f.svc.Team(ctx, admin(f.user("platform_admin")), "to"); len(find(tm.Attention, ServerTransferPending)) != 0 {
		t.Error("platform staff were asked to accept")
	}
	if tm, _ := f.svc.Team(ctx, authActor(owner), "from"); len(find(tm.Attention, ServerTransferPending)) != 0 {
		t.Error("the offering team was asked to accept")
	}
	f.run(`UPDATE server_transfers SET state = 'cancelled', decided_at = now()`)
	if tm, _ := f.svc.Team(ctx, authActor(owner), "to"); len(find(tm.Attention, ServerTransferPending)) != 0 {
		t.Error("a closed transfer is listed")
	}
}
