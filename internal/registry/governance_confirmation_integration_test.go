package registry

import (
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// A server's label is `internal` until someone says otherwise, and the column
// cannot tell a default nobody looked at from a label a team chose. The
// confirmation marker (migration 50) records the second: only an explicit
// sensitivity sent by the team's owner or admin sets it, even with the value
// the server already has. Everything else leaves it alone. It is bookkeeping:
// nothing here, in the gateways' tests or in the approval journal's reads it.

func (e *govEnv) confirmedAt(server uuid.UUID) *time.Time {
	e.t.Helper()
	var at *time.Time
	if err := e.s.pool.QueryRow(e.ctx, `SELECT sensitivity_confirmed_at FROM mcp_servers WHERE id = $1`, server).Scan(&at); err != nil {
		e.t.Fatal(err)
	}
	return at
}

func (e *govEnv) governanceAudits(server uuid.UUID) int {
	e.t.Helper()
	return e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.governance_update' AND target_id = $1`, server.String())
}

func (e *govEnv) confirmedView(server uuid.UUID) bool {
	e.t.Helper()
	v, err := e.s.view(e.ctx, e.s.q, server)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.Governance.SensitivityConfirmed
}

// Existing and new servers start unconfirmed (nothing before the marker
// recorded that anyone checked the label), whoever creates them.
func TestSensitivityStartsUnconfirmed(t *testing.T) {
	e := newGovEnv(t)
	for _, state := range []string{"private", "published"} {
		srv := e.server("start-"+state, state)
		if e.confirmedAt(srv) != nil || e.confirmedView(srv) {
			t.Errorf("%s: a server nobody confirmed reads as confirmed", state)
		}
		if _, s, _ := e.row(srv); s != "internal" {
			t.Errorf("%s: default label = %s", state, s)
		}
	}
	// Registering a server, as a person or as a token, confirms nothing.
	token := authz.Actor{Kind: authz.KindAutomationToken, TokenID: uuid.New(), TokenName: "t", TokenKind: authz.TokenTeamPublisher, TokenTeamID: e.team,
		TokenScopes: []string{authz.ScopeServersWrite, authz.ScopeServersRead}}
	fake := testutil.NewFakeMCP(t)
	for name, who := range map[string]authz.Actor{"person": e.actor(e.admin), "token": token} {
		created, err := e.s.Create(e.ctx, who, "gov", CreateInput{Slug: "made-by-" + name, Name: name, URL: fake.URL(), Enabled: false})
		if err != nil {
			t.Fatalf("%s create: %v", name, err)
		}
		if e.confirmedAt(created.View.Server.ID) != nil || e.confirmedView(created.View.Server.ID) {
			t.Errorf("a server registered by a %s is confirmed", name)
		}
	}
}

// Sending the label the server already has confirms it, in one revision and one
// audit entry, without touching its state; sending it again changes nothing.
func TestExplicitSameLabelConfirms(t *testing.T) {
	for _, who := range []string{"admin", "owner"} {
		for _, state := range []string{"private", "published"} {
			t.Run(who+"/"+state, func(t *testing.T) {
				e := newGovEnv(t)
				srv := e.server("same", state)
				person := map[string]uuid.UUID{"admin": e.admin, "owner": e.owner}[who]
				rev := e.rev(srv)
				v, err := e.govern(person, srv, GovernanceInput{Sensitivity: str("internal")})
				if err != nil {
					t.Fatal(err)
				}
				if !v.Governance.SensitivityConfirmed || v.Governance.Sensitivity != "internal" || !e.confirmedView(srv) {
					t.Fatalf("not confirmed: %+v", v.Governance)
				}
				if st, s, _ := e.row(srv); st != state || s != "internal" {
					t.Errorf("state/label moved: %s %s", st, s)
				}
				if e.rev(srv) != rev+1 {
					t.Errorf("revision %d -> %d, want one bump", rev, e.rev(srv))
				}
				if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.governance_update' AND target_id = $1 AND actor_user_id = $2
					AND before_state->>'sensitivity' = 'internal' AND after_state->>'sensitivity' = 'internal'
					AND before_state->>'sensitivityConfirmed' = 'false' AND after_state->>'sensitivityConfirmed' = 'true'
					AND metadata->>'sensitivityConfirmed' = 'true' AND metadata->>'sensitivityRaised' = 'false'`, srv.String(), person); n != 1 {
					t.Errorf("confirmation audit entries = %d", n)
				}
				if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.publish_request' AND target_id = $1`, srv.String()); n != 0 {
					t.Errorf("confirming sent the server to review (%d requests)", n)
				}
				at := e.confirmedAt(srv)
				if at == nil || at.After(time.Now().Add(time.Minute)) {
					t.Fatalf("confirmed at %v", at)
				}

				// Confirming again is not a mutation: no revision, no audit entry,
				// the first date is kept (the revision may even be the current one).
				rev = e.rev(srv)
				for i := 0; i < 2; i++ {
					if _, err := e.govern(person, srv, GovernanceInput{Sensitivity: str("internal")}); err != nil {
						t.Fatal(err)
					}
				}
				if e.rev(srv) != rev || e.governanceAudits(srv) != 1 || !e.confirmedAt(srv).Equal(*at) {
					t.Errorf("a repeated confirmation mutated: revision %d -> %d, audits %d", rev, e.rev(srv), e.governanceAudits(srv))
				}
			})
		}
	}
}

// A label that differs confirms too, in either direction; later edits of any
// kind keep the first confirmation (it is never cleared or moved).
func TestLabelEditsConfirmAndKeepConfirmation(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("label", "private")
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("confidential")}); err != nil {
		t.Fatal(err)
	}
	at := e.confirmedAt(srv)
	if at == nil || !e.confirmedView(srv) {
		t.Fatal("a new label did not confirm")
	}
	steps := map[string]GovernanceInput{
		"lowering":      {Sensitivity: str("public")},
		"raising":       {Sensitivity: str("restricted")},
		"the same":      {Sensitivity: str("restricted")},
		"the owner":     {SetOwner: true, OwnerUserID: &e.editor},
		"the on-call":   {SetOncall: true, OncallContact: str("#gov")},
		"the lifecycle": {Lifecycle: str("deprecated")},
	}
	for _, name := range []string{"lowering", "raising", "the same", "the owner", "the on-call", "the lifecycle"} {
		if _, err := e.govern(e.admin, srv, steps[name]); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := e.confirmedAt(srv); got == nil || !got.Equal(*at) {
			t.Errorf("%s moved the confirmation: %v -> %v", name, at, got)
		}
	}
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, UpdateInput{Description: str("more")}, e.rev(srv)); err != nil {
		t.Fatal(err)
	}
	if got := e.confirmedAt(srv); got == nil || !got.Equal(*at) {
		t.Errorf("an ordinary edit moved the confirmation: %v -> %v", at, got)
	}
}

// Only an explicit sensitivity confirms. Nothing else does: not another
// governance field, not an empty governance object, not an ordinary edit, not
// publication, health or a refresh, and not a person who may not govern or a
// token.
func TestNothingButAnExplicitLabelConfirms(t *testing.T) {
	e := newGovEnv(t)
	fake := testutil.NewFakeMCP(t)
	srv := e.server("quiet", "published")
	e.run(`UPDATE mcp_servers SET url = $2 WHERE id = $1`, srv, fake.URL())
	unconfirmed := func(what string) {
		t.Helper()
		if e.confirmedAt(srv) != nil || e.confirmedView(srv) {
			t.Fatalf("%s confirmed the label", what)
		}
		if _, s, _ := e.row(srv); s != "internal" {
			t.Fatalf("%s changed the label to %s", what, s)
		}
	}
	editGov := func(what string, g GovernanceInput) {
		t.Helper()
		if _, err := e.govern(e.admin, srv, g); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		unconfirmed(what)
	}
	editGov("an empty governance object", GovernanceInput{})
	editGov("naming an owner", GovernanceInput{SetOwner: true, OwnerUserID: &e.editor})
	editGov("clearing the owner", GovernanceInput{SetOwner: true})
	editGov("the on-call contact", GovernanceInput{SetOncall: true, OncallContact: str("oncall@example.com")})
	editGov("deprecating", GovernanceInput{Lifecycle: str("deprecated"), SetSunsetAt: true, SunsetAt: ptrTime(time.Now().Add(48 * time.Hour))})
	editGov("going active", GovernanceInput{Lifecycle: str("active")})

	update := func(what string, in UpdateInput) {
		t.Helper()
		if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, in, e.rev(srv)); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		unconfirmed(what)
	}
	update("the description", UpdateInput{Description: str("hello")})
	update("the name", UpdateInput{Name: str("Renamed")})
	update("the timeout", UpdateInput{TimeoutSeconds: ptrInt32(12)})
	off := false
	update("disabling", UpdateInput{Enabled: &off})
	on := true
	update("enabling", UpdateInput{Enabled: &on})

	// Publication: unpublish, and publish again (self_publish approves at once).
	e.run(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1`, e.team)
	if _, err := e.s.Unpublish(e.ctx, e.actor(e.admin), "gov", srv); err != nil {
		t.Fatal(err)
	}
	unconfirmed("unpublishing")
	if _, err := e.s.Publish(e.ctx, e.actor(e.admin), "gov", srv, nil, nil); err != nil {
		t.Fatal(err)
	}
	unconfirmed("publishing")
	// Refresh and a health result.
	if _, err := e.s.Refresh(e.ctx, e.actor(e.admin), "gov", srv); err != nil {
		t.Fatal(err)
	}
	unconfirmed("refreshing")
	if _, err := e.s.Test(e.ctx, e.actor(e.admin), "gov", srv); err != nil {
		t.Fatal(err)
	}
	unconfirmed("testing")

	// Nobody who may not govern: refused, nothing stored.
	for name, c := range map[string]struct {
		who  uuid.UUID
		want string
	}{"an editor": {e.editor, "governance_role"}, "a member": {e.member, "forbidden"}, "an outsider": {e.outsider, "team_not_found"}} {
		if _, err := e.govern(c.who, srv, GovernanceInput{Sensitivity: str("internal")}); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
		unconfirmed(name)
	}
	if _, err := e.govern(e.platform, srv, GovernanceInput{Sensitivity: str("internal")}); err == nil {
		t.Error("a platform admin outside the team confirmed the label")
	}
	unconfirmed("a platform admin outside the team")

	// A token neither confirms nor edits governance; its ordinary edits leave
	// the marker alone.
	token := authz.Actor{Kind: authz.KindAutomationToken, TokenID: uuid.New(), TokenName: "t", TokenKind: authz.TokenTeamPublisher, TokenTeamID: e.team,
		TokenScopes: []string{authz.ScopeServersWrite, authz.ScopeServersRead}}
	for name, g := range map[string]GovernanceInput{"the same label": {Sensitivity: str("internal")}, "another": {Sensitivity: str("public")}, "an empty object": {}} {
		if _, err := e.s.Update(e.ctx, token, "gov", srv, UpdateInput{Governance: &g}, e.rev(srv)); code(err) != "token_not_allowed" {
			t.Errorf("a token sending %s: %v", name, err)
		}
		unconfirmed("a token sending " + name)
	}
	if _, err := e.s.Update(e.ctx, token, "gov", srv, UpdateInput{Description: str("by token")}, e.rev(srv)); err != nil {
		t.Fatalf("a token's ordinary edit: %v", err)
	}
	unconfirmed("a token's ordinary edit")
	// Reaching the same row from the other direction: a direct write of the
	// marker is the only thing that moves it, and then it reads as confirmed.
	e.run(`UPDATE mcp_servers SET sensitivity_confirmed_at = now() WHERE id = $1`, srv)
	if !e.confirmedView(srv) {
		t.Error("a stored marker does not read as confirmed")
	}
}

// A stale revision is refused and stores nothing; a confirmation is one atomic
// change with its revision and audit entry, also when it travels with other
// edits, and concurrent identical requests land exactly once.
func TestConfirmationIsAtomicAndRevisionBound(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("atomic", "published")
	rev := e.rev(srv)

	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, UpdateInput{Governance: &GovernanceInput{Sensitivity: str("internal")}}, rev-1); code(err) != apperr.Stale().Code {
		t.Fatalf("a stale confirmation: %v", err)
	}
	if e.confirmedAt(srv) != nil || e.rev(srv) != rev || e.governanceAudits(srv) != 0 {
		t.Fatal("a stale confirmation wrote something")
	}

	// Refused as a whole: the bad owner stores neither the label nor the revision.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("internal"), SetOwner: true, OwnerUserID: &e.outsider}); code(err) != "invalid_owner" {
		t.Fatalf("combined: %v", err)
	}
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, UpdateInput{Description: str("nope"),
		Governance: &GovernanceInput{Sensitivity: str("internal"), Lifecycle: str("sunset"), SetSunsetAt: true}}, e.rev(srv)); err == nil {
		t.Fatal("an invalid lifecycle was accepted")
	}
	if e.confirmedAt(srv) != nil || e.rev(srv) != rev || e.governanceAudits(srv) != 0 || e.str(`SELECT description FROM mcp_servers WHERE id = $1::uuid`, srv) == "nope" {
		t.Fatal("a refused request wrote something")
	}

	// Together with another edit: one revision bump, both audit entries, atomically.
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, UpdateInput{Description: str("both"), Governance: &GovernanceInput{Sensitivity: str("internal")}}, rev); err != nil {
		t.Fatal(err)
	}
	if e.confirmedAt(srv) == nil || e.rev(srv) != rev+1 || e.governanceAudits(srv) != 1 ||
		e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.update' AND target_id = $1`, srv.String()) != 1 {
		t.Errorf("combined update: confirmed %v, revision %d -> %d, audits %d", e.confirmedAt(srv), rev, e.rev(srv), e.governanceAudits(srv))
	}

	// Concurrent identical confirmations: exactly one lands (the others read a
	// revision that moved), however they interleave.
	other := e.server("racing", "private")
	rev = e.rev(other)
	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.s.Update(e.ctx, e.actor(e.admin), "gov", other, UpdateInput{Governance: &GovernanceInput{Sensitivity: str("internal")}}, rev)
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case code(err) != apperr.Stale().Code:
			t.Errorf("a racing confirmation: %v", err)
		}
	}
	if ok != 1 || e.rev(other) != rev+1 || e.governanceAudits(other) != 1 || e.confirmedAt(other) == nil {
		t.Errorf("racing confirmations: %d succeeded, revision %d -> %d, audits %d", ok, rev, e.rev(other), e.governanceAudits(other))
	}
}
