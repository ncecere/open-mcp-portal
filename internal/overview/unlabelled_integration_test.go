package overview

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
)

// A published server whose sensitivity label nobody confirmed is an attention
// item: `internal` is only the column's default until a team's owner or admin
// sends a label (even that one). A confirmed internal label is legitimate and
// is not listed. Informational: it blocks and unpublishes nothing.
func TestUnlabelledPublishedServersAreAttention(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pa := f.user("platform_admin")
	ops, data, old := f.team("ops"), f.team("data"), f.team("old")
	member := f.user("none")
	f.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'member')`, ops, member)

	unlabelled := f.server(ops, "published", true)
	otherTeam := f.server(data, "published", true)
	disabled := f.server(ops, "published", false) // still published: still unlabelled
	confirmedInternal := f.server(ops, "published", true)
	f.run(`UPDATE mcp_servers SET sensitivity_confirmed_at = now() WHERE id = $1`, confirmedInternal)
	confirmedOther := f.server(ops, "published", true)
	f.run(`UPDATE mcp_servers SET sensitivity = 'restricted', sensitivity_confirmed_at = now() WHERE id = $1`, confirmedOther)
	private := f.server(ops, "private", true)
	pending := f.server(ops, "pending", true)
	archived := f.server(old, "published", true)
	f.run(`UPDATE teams SET status = 'archived' WHERE id = $1`, old)

	state := func() string {
		return f.exec(`SELECT coalesce(string_agg(id::text || publish_state || enabled::text || revision::text, ',' ORDER BY id), '') FROM mcp_servers`)
	}
	before := state()
	o, err := f.svc.Admin(ctx, admin(pa))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Item{}
	for _, it := range find(o.Attention, ServerUnlabelled) {
		got[it.Subject.ID] = it
	}
	for name, id := range map[string]uuid.UUID{"an unconfirmed published server": unlabelled, "another team's": otherTeam, "a disabled one": disabled} {
		it, ok := got[id.String()]
		if !ok || it.Severity != Info || it.At != nil || it.Link == nil || it.Link.Type != LinkServer || it.Link.ID != id.String() || it.Link.TeamSlug == "" ||
			it.Team == nil || it.Subject.Slug == "" || !strings.Contains(it.Summary, it.Subject.Name) || !strings.Contains(it.Summary, `"internal"`) || !strings.Contains(it.Summary, "nobody has confirmed") {
			t.Errorf("%s: %+v", name, it)
		}
	}
	for name, id := range map[string]uuid.UUID{"a confirmed internal label": confirmedInternal, "a confirmed other label": confirmedOther, "a private server": private,
		"a pending server": pending, "an archived team's": archived} {
		if _, ok := got[id.String()]; ok {
			t.Errorf("%s is listed", name)
		}
	}
	if o.Totals[ServerUnlabelled] != 3 || len(got) != 3 || o.Truncated {
		t.Errorf("total = %d, listed %d, truncated %v", o.Totals[ServerUnlabelled], len(got), o.Truncated)
	}

	// A team's card lists its own servers, for its members as well; a team of
	// nobody's lists none, and a person outside the team gets no card.
	for name, who := range map[string]struct {
		actor authz.Actor
		slug  string
		want  int
	}{"platform staff": {admin(pa), "ops", 2}, "a member": {authActor(member), "ops", 2}, "another team": {admin(pa), "data", 1}} {
		tm, err := f.svc.Team(ctx, who.actor, who.slug)
		if err != nil || len(find(tm.Attention, ServerUnlabelled)) != who.want || tm.Totals[ServerUnlabelled] != int64(who.want) {
			t.Errorf("%s: %d items, total %d, %v", name, len(find(tm.Attention, ServerUnlabelled)), tm.Totals[ServerUnlabelled], err)
		}
	}
	if _, err := f.svc.Team(ctx, authActor(f.user("none")), "ops"); err == nil {
		t.Error("an outsider saw the team's card")
	}

	// Nothing was blocked, unpublished or changed by being listed.
	if state() != before {
		t.Error("listing the servers changed them")
	}

	// Confirming one clears exactly that one; the rest stay.
	f.run(`UPDATE mcp_servers SET sensitivity_confirmed_at = now() WHERE id = $1`, unlabelled)
	if o, _ = f.svc.Admin(ctx, admin(pa)); o.Totals[ServerUnlabelled] != 2 {
		t.Errorf("after confirming one: %d", o.Totals[ServerUnlabelled])
	}
	for _, it := range find(o.Attention, ServerUnlabelled) {
		if it.Subject.ID == unlabelled.String() {
			t.Error("a confirmed server is still listed")
		}
	}
	// Unpublishing clears it too (only published servers are in the catalog).
	f.run(`UPDATE mcp_servers SET publish_state = 'private', published_at = NULL WHERE id = $1`, otherTeam)
	if o, _ = f.svc.Admin(ctx, admin(pa)); o.Totals[ServerUnlabelled] != 1 {
		t.Errorf("after unpublishing one: %d", o.Totals[ServerUnlabelled])
	}
}

// Totals are exact and the list is bounded: more unconfirmed servers than the
// page marks the response truncated and still counts them all.
func TestUnlabelledAttentionIsBoundedWithExactTotals(t *testing.T) {
	f := newFx(t)
	ctx := context.Background()
	pa := f.user("platform_admin")
	team := f.team("ops")
	const n = PerKind + 7
	for i := 0; i < n; i++ {
		f.server(team, "published", true)
	}
	confirmed := f.server(team, "published", true)
	f.run(`UPDATE mcp_servers SET sensitivity_confirmed_at = now() WHERE id = $1`, confirmed)

	o, err := f.svc.Admin(ctx, admin(pa))
	if err != nil {
		t.Fatal(err)
	}
	if items := find(o.Attention, ServerUnlabelled); len(items) != PerKind || o.Totals[ServerUnlabelled] != n || !o.Truncated {
		t.Errorf("admin: %d listed, total %d, truncated %v", len(items), o.Totals[ServerUnlabelled], o.Truncated)
	}
	tm, err := f.svc.Team(ctx, admin(pa), "ops")
	if err != nil {
		t.Fatal(err)
	}
	if items := find(tm.Attention, ServerUnlabelled); len(items) != PerKind || tm.Totals[ServerUnlabelled] != n || !tm.Truncated {
		t.Errorf("team: %d listed, total %d, truncated %v", len(items), tm.Totals[ServerUnlabelled], tm.Truncated)
	}
	seen := map[string]bool{}
	for _, it := range find(o.Attention, ServerUnlabelled) {
		if seen[it.Subject.ID] || it.Subject.ID == confirmed.String() {
			t.Errorf("duplicate or confirmed item %s", it.Subject.ID)
		}
		seen[it.Subject.ID] = true
	}
}
