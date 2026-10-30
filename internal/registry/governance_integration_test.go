package registry

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
)

// govEnv is one team with every role, a platform admin and servers in any state.
type govEnv struct {
	t   *testing.T
	s   *Service
	ctx context.Context
	run func(sql string, args ...any)
	id  func(sql string, args ...any) uuid.UUID
	str func(sql string, args ...any) string
	// team is the team "gov"; the people are its members by role.
	team                                   uuid.UUID
	owner, admin, editor, member, outsider uuid.UUID
	platform                               uuid.UUID
}

func newGovEnv(t *testing.T) *govEnv {
	t.Helper()
	s, scalar := testService(t)
	e := &govEnv{t: t, s: s, ctx: context.Background()}
	e.str = scalar
	e.id = func(sql string, args ...any) uuid.UUID { return uuid.MustParse(scalar(sql+"::text", args...)) }
	e.run = func(sql string, args ...any) {
		t.Helper()
		if _, err := s.pool.Exec(e.ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	e.team = e.mustID(`INSERT INTO teams (slug, name) VALUES ('gov', 'Gov') RETURNING id`)
	person := func(name, role string) uuid.UUID {
		u := e.mustID(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('t', $1, $1 || '@example.invalid', $1) RETURNING id`, name)
		if role != "" {
			e.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)`, e.team, u, role)
		}
		return u
	}
	e.owner, e.admin, e.editor, e.member, e.outsider = person("owner", "owner"), person("admin", "admin"), person("editor", "editor"), person("member", "member"), person("outsider", "")
	e.platform = person("platform", "")
	e.run(`UPDATE users SET platform_role = 'platform_admin' WHERE id = $1`, e.platform)
	return e
}

func (e *govEnv) mustID(sql string, args ...any) uuid.UUID {
	e.t.Helper()
	var out uuid.UUID
	if err := e.s.pool.QueryRow(e.ctx, sql, args...).Scan(&out); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

func (e *govEnv) actor(u uuid.UUID) authz.Actor {
	a := authz.Actor{UserID: u}
	if u == e.platform {
		a.PlatformRole = authz.PlatformAdmin
	}
	return a
}

// server is a server of the team in a publish state, with one tool approved when published.
func (e *govEnv) server(slug, state string) uuid.UUID {
	e.t.Helper()
	id := e.mustID(`INSERT INTO mcp_servers (team_id, slug, name, url, publish_state, refreshed_at, published_at, last_reviewed_at)
		VALUES ($1, $2, $2, 'https://x.example.com/mcp', $3, now(), CASE WHEN $3 = 'published' THEN now() END, CASE WHEN $3 = 'published' THEN now() END) RETURNING id`,
		e.team, slug, state)
	fp := strings.Repeat("a", 64)
	e.run(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint) VALUES ($1, 'tool', 'ping', '{}', $2, $3)`,
		id, fp, map[bool]*string{true: &fp, false: nil}[state == "published"])
	return id
}

func (e *govEnv) rev(server uuid.UUID) int64 {
	e.t.Helper()
	var r int64
	if err := e.s.pool.QueryRow(e.ctx, `SELECT revision FROM mcp_servers WHERE id = $1`, server).Scan(&r); err != nil {
		e.t.Fatal(err)
	}
	return r
}

func (e *govEnv) row(server uuid.UUID) (state, sens, life string) {
	e.t.Helper()
	if err := e.s.pool.QueryRow(e.ctx, `SELECT publish_state, sensitivity, lifecycle FROM mcp_servers WHERE id = $1`, server).Scan(&state, &sens, &life); err != nil {
		e.t.Fatal(err)
	}
	return
}

func (e *govEnv) count(sql string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.s.pool.QueryRow(e.ctx, sql, args...).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return n
}

func (e *govEnv) govern(u uuid.UUID, server uuid.UUID, g GovernanceInput) (ServerView, error) {
	e.t.Helper()
	return e.s.Update(e.ctx, e.actor(u), "gov", server, UpdateInput{Governance: &g}, e.rev(server))
}

func str(s string) *string { return &s }

// Who may change governance and what it must be.
func TestGovernanceUpdateRules(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("rules", "private")

	// Owners and admins; never an editor, a member, an outsider or a token.
	for name, c := range map[string]struct {
		who  uuid.UUID
		want string
	}{"editor": {e.editor, "governance_role"}, "member": {e.member, "forbidden"}, "outsider": {e.outsider, "team_not_found"}} {
		if _, err := e.govern(c.who, srv, GovernanceInput{Sensitivity: str("restricted")}); code(err) != c.want {
			t.Errorf("%s: %v", name, err)
		}
	}
	token := authz.Actor{Kind: authz.KindAutomationToken, TokenID: uuid.New(), TokenName: "t", TokenKind: authz.TokenTeamPublisher, TokenTeamID: e.team,
		TokenScopes: []string{authz.ScopeServersWrite}}
	if _, err := e.s.Update(e.ctx, token, "gov", srv, UpdateInput{Governance: &GovernanceInput{Sensitivity: str("restricted")}}, e.rev(srv)); code(err) != "token_not_allowed" {
		t.Errorf("a token changed governance: %v", err)
	}
	if _, s, _ := e.row(srv); s != "internal" {
		t.Fatalf("a refused change was stored: %s", s)
	}

	// An admin names an editor as owner, a contact and a label.
	v, err := e.govern(e.admin, srv, GovernanceInput{SetOwner: true, OwnerUserID: &e.editor, SetOncall: true, OncallContact: str("#gov-oncall"), Sensitivity: str("confidential")})
	if err != nil {
		t.Fatal(err)
	}
	g := v.Governance
	if g.OwnerUserID.UUID != e.editor || g.OwnerName != "editor" || g.Ownerless || g.OncallContact == nil || *g.OncallContact != "#gov-oncall" || g.Sensitivity != "confidential" {
		t.Fatalf("governance = %+v", g)
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.governance_update' AND target_id = $1 AND actor_user_id = $2
		AND before_state->>'sensitivity' = 'internal' AND after_state->>'sensitivity' = 'confidential'`, srv.String(), e.admin); n != 1 {
		t.Errorf("governance audit entries = %d", n)
	}
	// Nothing changed: no new revision and no audit entry.
	rev := e.rev(srv)
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("confidential"), SetOncall: true, OncallContact: str("#gov-oncall")}); err != nil {
		t.Fatal(err)
	}
	if e.rev(srv) != rev || e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.governance_update'`) != 1 {
		t.Error("a request that changed nothing wrote something")
	}
	// A stale revision is refused and writes nothing.
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", srv, UpdateInput{Governance: &GovernanceInput{Sensitivity: str("public")}}, rev-1); code(err) != "revision_conflict" && code(err) != "stale_revision" && err == nil {
		t.Errorf("stale revision: %v", err)
	}
	if _, s, _ := e.row(srv); s != "confidential" {
		t.Errorf("a stale update changed the label to %s", s)
	}
	// Clearing the owner and the contact.
	v, err = e.govern(e.owner, srv, GovernanceInput{SetOwner: true, SetOncall: true})
	if err != nil || !v.Governance.Ownerless || v.Governance.OncallContact != nil {
		t.Fatalf("cleared: %+v %v", v.Governance, err)
	}
	// An invalid label.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("secret")}); code(err) != "invalid_sensitivity" {
		t.Errorf("label: %v", err)
	}
}

func TestGovernanceOwnerMustBeAnActiveEditor(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("owner", "private")
	suspended := e.mustID(`INSERT INTO users (oidc_issuer, oidc_subject, email, status) VALUES ('t', 'sus', 'sus@example.invalid', 'suspended') RETURNING id`)
	e.run(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, 'editor')`, e.team, suspended)
	for name, who := range map[string]uuid.UUID{"a member": e.member, "a stranger": e.outsider, "a suspended editor": suspended, "nobody": uuid.New()} {
		if _, err := e.govern(e.admin, srv, GovernanceInput{SetOwner: true, OwnerUserID: &who}); code(err) != "invalid_owner" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, who := range map[string]uuid.UUID{"an editor": e.editor, "an admin": e.admin, "an owner": e.owner} {
		if _, err := e.govern(e.admin, srv, GovernanceInput{SetOwner: true, OwnerUserID: &who}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Registering a server names its creator; a token names nobody.
	if got := creatorOwner(e.actor(e.editor)); !got.Valid || got.UUID != e.editor {
		t.Errorf("creator owner = %v", got)
	}
	if got := creatorOwner(authz.Actor{Kind: authz.KindAutomationToken}); got.Valid {
		t.Error("a token became an owner")
	}
}

func TestNormalizeOncall(t *testing.T) {
	for _, ok := range []string{"oncall@example.com", "#team-oncall", "@platform", "https://pager.example.com/team/7", "http://pager.example.com", "tel:+15551234567"} {
		if v, err := NormalizeOncall("  " + ok + " "); err != nil || v == nil || *v != ok {
			t.Errorf("%q: %v %v", ok, v, err)
		}
	}
	if v, err := NormalizeOncall("   "); err != nil || v != nil {
		t.Errorf("blank: %v %v", v, err)
	}
	for _, bad := range []string{"javascript:alert(1)", "ftp://x.example.com", "mailto:a@b.com", "https://user:pw@pager.example.com", "https://", "not a contact",
		"Oncall <a@b.com>", "a@b", "#", "line\nbreak@example.com", "tel:call me", strings.Repeat("a", 190) + "@example.com", "data:text/html,x", "//evil.example.com"} {
		if v, err := NormalizeOncall(bad); err == nil {
			t.Errorf("%q accepted as %q", bad, *v)
		}
	}
}

// A published server returns to review when its sensitivity is raised, and not
// when it is lowered; under self_publish the team approves its own change.
func TestGovernanceSensitivityReviewTrigger(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("raise", "published")
	// Lowering does not.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("public")}); err != nil {
		t.Fatal(err)
	}
	if st, s, _ := e.row(srv); st != "published" || s != "public" {
		t.Fatalf("lowered: %s %s", st, s)
	}
	// Raising does, whichever label it was.
	for _, label := range []string{"internal", "restricted"} {
		e.run(`UPDATE mcp_servers SET publish_state = 'published', published_at = coalesce(published_at, now()) WHERE id = $1`, srv)
		if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str(label)}); err != nil {
			t.Fatal(err)
		}
		if st, s, _ := e.row(srv); st != "pending" || s != label {
			t.Fatalf("raised to %s: %s %s", label, st, s)
		}
	}
	if n := e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.publish_request' AND target_id = $1 AND metadata->>'reason' = 'sensitivity_raised'`, srv.String()); n != 2 {
		t.Errorf("review requests for the raise = %d", n)
	}
	// Re-submitting the same label asks for nothing.
	e.run(`UPDATE mcp_servers SET publish_state = 'published', published_at = coalesce(published_at, now()) WHERE id = $1`, srv)
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("restricted")}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.row(srv); st != "published" {
		t.Errorf("an unchanged label sent it to %s", st)
	}
	// Private servers have nothing to review; self_publish teams approve themselves.
	priv := e.server("raise-private", "private")
	if _, err := e.govern(e.admin, priv, GovernanceInput{Sensitivity: str("restricted")}); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.row(priv); st != "private" {
		t.Errorf("private server became %s", st)
	}
	e.run(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1`, e.team)
	self := e.server("raise-self", "published")
	if _, err := e.govern(e.admin, self, GovernanceInput{Sensitivity: str("restricted")}); err != nil {
		t.Fatal(err)
	}
	if st, s, _ := e.row(self); st != "published" || s != "restricted" {
		t.Errorf("self_publish: %s %s", st, s)
	}
	// A raise alongside another change is one transaction: an invalid owner
	// rolls the description back too.
	e.run(`UPDATE teams SET publish_policy_override = NULL WHERE id = $1`, e.team)
	both := e.server("raise-both", "published")
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", both, UpdateInput{Description: str("changed"),
		Governance: &GovernanceInput{Sensitivity: str("restricted"), SetOwner: true, OwnerUserID: &e.outsider}}, e.rev(both)); code(err) != "invalid_owner" {
		t.Fatalf("combined: %v", err)
	}
	if e.str(`SELECT description FROM mcp_servers WHERE id = $1::uuid`, both) == "changed" {
		t.Error("the description was stored although the governance was refused")
	}
	if _, err := e.s.Update(e.ctx, e.actor(e.admin), "gov", both, UpdateInput{Description: str("changed"), Governance: &GovernanceInput{Sensitivity: str("restricted")}}, e.rev(both)); err != nil {
		t.Fatal(err)
	}
	if st, s, _ := e.row(both); st != "pending" || s != "restricted" || e.str(`SELECT description FROM mcp_servers WHERE id = $1::uuid`, both) != "changed" {
		t.Errorf("combined update: %s %s", st, s)
	}
}

// The review digest covers sensitivity and lifecycle, not the bookkeeping, so an
// approval made before a change is refused (F-2).
func TestGovernanceInReviewDigest(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("digest", "pending")
	digest := func() string {
		v, err := e.s.AdminGet(e.ctx, e.actor(e.platform), srv)
		if err != nil {
			t.Fatal(err)
		}
		return v.ReviewDigest
	}
	base := digest()
	steps := []struct {
		name  string
		in    GovernanceInput
		moves bool
	}{
		{"owner", GovernanceInput{SetOwner: true, OwnerUserID: &e.editor}, false},
		{"on-call contact", GovernanceInput{SetOncall: true, OncallContact: str("#x")}, false},
		{"sensitivity", GovernanceInput{Sensitivity: str("confidential")}, true},
		{"deprecating", GovernanceInput{Lifecycle: str("deprecated")}, true},
		{"a sunset date", GovernanceInput{SetSunsetAt: true, SunsetAt: ptrTime(time.Now().Add(48 * time.Hour))}, false},
		{"sunset", GovernanceInput{Lifecycle: str("sunset")}, true},
		{"active again", GovernanceInput{Lifecycle: str("active")}, true},
	}
	prev := base
	for _, st := range steps {
		if _, err := e.govern(e.admin, srv, st.in); err != nil {
			t.Fatalf("%s: %v", st.name, err)
		}
		cur := digest()
		if (cur != prev) != st.moves {
			t.Errorf("%s moved the digest = %v, want %v", st.name, cur != prev, st.moves)
		}
		prev = cur
	}
	// Approving with the digest read before the label was raised: refused, nothing approved.
	stale := digest()
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("restricted")}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.Review(e.ctx, e.actor(e.platform), srv, DecisionApprove, nil, stale); code(err) != "changed_since_review" {
		t.Fatalf("approval with a stale digest: %v", err)
	}
	if st, _, _ := e.row(srv); st != "pending" {
		t.Errorf("state after a refused approval: %s", st)
	}
	if _, err := e.s.Review(e.ctx, e.actor(e.platform), srv, DecisionApprove, nil, digest()); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.row(srv); st != "published" {
		t.Errorf("state after approval: %s", st)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

func TestGovernanceLifecycle(t *testing.T) {
	e := newGovEnv(t)
	srv := e.server("life", "published")
	other := e.server("life-successor", "published")
	private := e.server("life-private", "private")
	future := ptrTime(time.Now().Add(72 * time.Hour).Truncate(time.Microsecond))

	// Dates and replacements belong to a retiring server.
	for name, in := range map[string]GovernanceInput{
		"a sunset date": {SetSunsetAt: true, SunsetAt: future}, "a replacement": {SetReplacement: true, ReplacementServerID: &other}} {
		if _, err := e.govern(e.admin, srv, in); code(err) != "lifecycle_active" {
			t.Errorf("%s on an active server: %v", name, err)
		}
	}
	if _, err := e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("retired")}); code(err) != "invalid_lifecycle" {
		t.Errorf("unknown lifecycle: %v", err)
	}
	// A sunset date must lie ahead.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("deprecated"), SetSunsetAt: true, SunsetAt: ptrTime(time.Now().Add(-time.Minute))}); code(err) != "sunset_in_past" {
		t.Errorf("a past sunset date: %v", err)
	}
	// Deprecating stamps the date and keeps what was sent.
	v, err := e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("deprecated"), SetSunsetAt: true, SunsetAt: future, SetReplacement: true, ReplacementServerID: &other})
	if err != nil {
		t.Fatal(err)
	}
	g := v.Governance
	if g.Lifecycle != "deprecated" || g.DeprecatedAt == nil || g.SunsetAt == nil || !g.SunsetAt.Equal(*future) || g.Replacement == nil || g.Replacement.ID != other {
		t.Fatalf("deprecated: %+v", g)
	}
	if st, _, _ := e.row(srv); st != "published" {
		t.Errorf("deprecating changed the publish state to %s", st)
	}
	// The effective lifecycle follows the clock: a passed date is sunset.
	e.run(`UPDATE mcp_servers SET sunset_at = now() - interval '1 second' WHERE id = $1`, srv)
	if v, err := e.s.AdminGet(e.ctx, e.actor(e.platform), srv); err != nil || v.Governance.Lifecycle != "sunset" {
		t.Fatalf("effective lifecycle after the date: %+v %v", v.Governance.Lifecycle, err)
	}
	// Other edits of a server past its date are not blocked by it.
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetOncall: true, OncallContact: str("#late")}); err != nil {
		t.Errorf("an unrelated edit of a server past its sunset: %v", err)
	}
	// Coming back from sunset: no date unless one is sent.
	e.run(`UPDATE mcp_servers SET lifecycle = 'sunset' WHERE id = $1`, srv)
	if v, err = e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("deprecated")}); err != nil || v.Governance.SunsetAt != nil || v.Governance.Lifecycle != "deprecated" {
		t.Fatalf("back to deprecated: %+v %v", v.Governance, err)
	}
	// Sunset without a date is now; clearing the date of a sunset is refused.
	if v, err = e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("sunset")}); err != nil || v.Governance.SunsetAt == nil || v.Governance.Lifecycle != "sunset" {
		t.Fatalf("sunset now: %+v %v", v.Governance, err)
	}
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetSunsetAt: true}); code(err) != "sunset_required" {
		t.Errorf("clearing a sunset's date: %v", err)
	}
	// Active again clears dates and replacement.
	if v, err = e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("active")}); err != nil || v.Governance.Lifecycle != "active" || v.Governance.DeprecatedAt != nil ||
		v.Governance.SunsetAt != nil || v.Governance.Replacement != nil {
		t.Fatalf("active again: %+v %v", v.Governance, err)
	}

	// Replacements: another published (or this team's) server that is not
	// retired, does not lead back here and exists.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Lifecycle: str("deprecated")}); err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string]GovernanceInput{
		"itself": {SetReplacement: true, ReplacementServerID: &srv}, "nothing": {SetReplacement: true, ReplacementServerID: ptrUUID(uuid.New())}} {
		if _, err := e.govern(e.admin, srv, in); code(err) != "invalid_replacement" {
			t.Errorf("replacement %s: %v", name, err)
		}
	}
	// A private server of another team is not offered.
	foreign := e.mustID(`INSERT INTO teams (slug, name) VALUES ('foreign', 'Foreign') RETURNING id`)
	hidden := e.mustID(`INSERT INTO mcp_servers (team_id, slug, name, url) VALUES ($1, 'hidden', 'Hidden', 'https://h.example.com/mcp') RETURNING id`, foreign)
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetReplacement: true, ReplacementServerID: &hidden}); code(err) != "invalid_replacement" {
		t.Errorf("another team's private server: %v", err)
	}
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetReplacement: true, ReplacementServerID: &private}); err != nil {
		t.Errorf("the team's own private server: %v", err)
	}
	// A cycle: other would point back at srv.
	if _, err := e.govern(e.admin, other, GovernanceInput{Lifecycle: str("deprecated"), SetReplacement: true, ReplacementServerID: &srv}); err != nil {
		t.Fatalf("other -> srv (srv replaced by private): %v", err)
	}
	e.run(`UPDATE mcp_servers SET replacement_server_id = $2 WHERE id = $1`, srv, other)
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetReplacement: true, ReplacementServerID: &other}); code(err) != "invalid_replacement" {
		t.Errorf("a replacement that points back: %v", err)
	}
	// A retired replacement is not one.
	e.run(`UPDATE mcp_servers SET lifecycle = 'sunset', deprecated_at = now(), sunset_at = now() WHERE id = $1`, other)
	e.run(`UPDATE mcp_servers SET replacement_server_id = NULL WHERE id = $1`, srv)
	e.run(`UPDATE mcp_servers SET replacement_server_id = NULL WHERE id = $1`, other)
	if _, err := e.govern(e.admin, srv, GovernanceInput{SetReplacement: true, ReplacementServerID: &other}); code(err) != "invalid_replacement" {
		t.Errorf("a sunset replacement: %v", err)
	}
	// Deleting the replacement clears the pointer, not the server.
	e.run(`UPDATE mcp_servers SET replacement_server_id = $2 WHERE id = $1`, srv, private)
	e.run(`DELETE FROM mcp_servers WHERE id = $1`, private)
	if e.count(`SELECT count(*) FROM mcp_servers WHERE id = $1 AND replacement_server_id IS NULL`, srv) != 1 {
		t.Error("the pointer to a deleted replacement stayed")
	}
}

func ptrUUID(u uuid.UUID) *uuid.UUID { return &u }

// The re-review: a published server's due date follows its approval and the
// platform's interval for its sensitivity; asking again is publishing it.
func TestReviewDueStampAndRereview(t *testing.T) {
	e := newGovEnv(t)
	admin := e.actor(e.platform)
	days := int32(10)
	if _, err := e.s.UpdateGovernanceSettings(e.ctx, e.actor(e.admin), GovernanceSettingsInput{Internal: &days}, 1); code(err) != "forbidden" {
		t.Fatalf("a team admin changed the settings: %v", err)
	}
	if _, err := e.s.UpdateGovernanceSettings(e.ctx, admin, GovernanceSettingsInput{Internal: ptrInt32(4000)}, 1); code(err) != "invalid_interval" {
		t.Fatalf("a 4000-day interval: %v", err)
	}
	if _, err := e.s.UpdateGovernanceSettings(e.ctx, admin, GovernanceSettingsInput{Internal: &days}, 7); code(err) != "stale_revision" && code(err) != "revision_conflict" && err == nil {
		t.Fatalf("a stale settings revision: %v", err)
	}
	st, err := e.s.UpdateGovernanceSettings(e.ctx, admin, GovernanceSettingsInput{Internal: &days}, 1)
	if err != nil || st.GovernanceRevision != 2 || st.ReviewIntervalDaysInternal != 10 || st.ReviewIntervalDaysRestricted != 90 || st.GovernanceReturnOverdue {
		t.Fatalf("settings = %+v %v", st, err)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'settings.governance_update' AND actor_user_id = $1`, e.platform) != 1 {
		t.Error("the settings change was not audited")
	}
	// Approval stamps the due date from the interval of the label.
	srv := e.server("due", "pending")
	if _, err := e.s.Review(e.ctx, admin, srv, DecisionApprove, nil, e.digestOf(srv)); err != nil {
		t.Fatal(err)
	}
	due := func() *time.Time {
		var d *time.Time
		if err := e.s.pool.QueryRow(e.ctx, `SELECT review_due_at FROM mcp_servers WHERE id = $1`, srv).Scan(&d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := due(); d == nil || d.Before(time.Now().Add(9*24*time.Hour)) || d.After(time.Now().Add(10*24*time.Hour+time.Minute)) {
		t.Fatalf("due after approval = %v", d)
	}
	// A new interval is counted again from the approval; zero means none.
	zero := int32(0)
	if _, err := e.s.UpdateGovernanceSettings(e.ctx, admin, GovernanceSettingsInput{Internal: &zero}, 2); err != nil {
		t.Fatal(err)
	}
	if due() != nil {
		t.Error("a zero interval left a due date")
	}
	short := int32(1)
	if _, err := e.s.UpdateGovernanceSettings(e.ctx, admin, GovernanceSettingsInput{Internal: &short}, 3); err != nil {
		t.Fatal(err)
	}
	// Changing the label counts the new interval from the same approval.
	if _, err := e.govern(e.admin, srv, GovernanceInput{Sensitivity: str("public")}); err != nil {
		t.Fatal(err)
	}
	if due() != nil {
		t.Error("public has no interval, yet the server has a due date")
	}
	e.run(`UPDATE mcp_servers SET sensitivity = 'internal' WHERE id = $1`, srv)
	e.run(`UPDATE mcp_servers SET last_reviewed_at = now() - interval '3 days' WHERE id = $1`, srv)
	if _, err := e.s.q.RecomputeMCPServerReviewDue(e.ctx, uuid.NullUUID{UUID: srv, Valid: true}); err != nil {
		t.Fatal(err)
	}
	if d := due(); d == nil || !d.Before(time.Now()) {
		t.Fatalf("due = %v, want a date in the past", d)
	}
	// Overdue: not already_published; the team asks again.
	if _, err := e.s.Publish(e.ctx, e.actor(e.editor), "gov", srv, nil, nil); code(err) != "forbidden" {
		t.Errorf("an editor asked for a review: %v", err)
	}
	tok := authz.Actor{Kind: authz.KindAutomationToken, TokenKind: authz.TokenTeamPublisher, TokenTeamID: e.team, TokenScopes: []string{authz.ScopeServersWrite}}
	if _, err := e.s.Publish(e.ctx, tok, "gov", srv, nil, nil); code(err) != "token_not_allowed" {
		t.Errorf("a token asked for a review: %v", err)
	}
	v, err := e.s.Publish(e.ctx, e.actor(e.admin), "gov", srv, str("still in use"), nil)
	if err != nil || v.Server.PublishState != StatePending {
		t.Fatalf("asked again: %v %v", v.Server.PublishState, err)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.publish_request' AND metadata->>'reason' = 'review_due'`) != 1 {
		t.Error("the request was not audited with its reason")
	}
	if due() != nil {
		t.Error("a pending server kept a due date")
	}
	if _, err := e.s.Review(e.ctx, admin, srv, DecisionApprove, nil, e.digestOf(srv)); err != nil {
		t.Fatal(err)
	}
	if d := due(); d == nil || !d.After(time.Now()) {
		t.Fatalf("due after the second approval = %v", d)
	}
	if _, err := e.s.Publish(e.ctx, e.actor(e.admin), "gov", srv, nil, nil); code(err) != "already_published" {
		t.Errorf("publishing a server whose review is not due: %v", err)
	}

	// Under self_publish the team confirms in place; a platform admin may too.
	e.run(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1`, e.team)
	e.run(`UPDATE mcp_servers SET last_reviewed_at = now() - interval '3 days', review_due_at = now() - interval '1 day' WHERE id = $1`, srv)
	v, err = e.s.Publish(e.ctx, e.actor(e.admin), "gov", srv, nil, nil)
	if err != nil || v.Server.PublishState != StatePublished || v.Governance.ReviewOverdue {
		t.Fatalf("confirmed in place: %v %+v %v", v.Server.PublishState, v.Governance, err)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.review_confirm'`) != 1 {
		t.Error("the confirmation was not audited")
	}
	e.run(`UPDATE teams SET publish_policy_override = NULL WHERE id = $1`, e.team)
	e.run(`UPDATE mcp_servers SET review_due_at = now() - interval '1 day' WHERE id = $1`, srv)
	if _, err := e.s.Review(e.ctx, admin, srv, DecisionApprove, nil, e.digestOf(srv)); err != nil {
		t.Fatalf("approving in place: %v", err)
	}
	if d := due(); d == nil || !d.After(time.Now()) {
		t.Errorf("due after approving in place = %v", d)
	}
	if e.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.publish' AND metadata->>'rereview' = 'true'`) != 1 {
		t.Error("the in-place approval was not audited as a re-review")
	}
	// Not overdue: approve is still only for pending servers.
	if _, err := e.s.Review(e.ctx, admin, srv, DecisionApprove, nil, e.digestOf(srv)); code(err) != "invalid_state" {
		t.Errorf("approving a published server that is not due: %v", err)
	}
	// Unpublishing clears the date.
	if _, err := e.s.Unpublish(e.ctx, e.actor(e.admin), "gov", srv); err != nil {
		t.Fatal(err)
	}
	e.run(`UPDATE mcp_servers SET publish_state = 'private' WHERE id = $1`, srv)
	if _, err := e.s.q.RecomputeMCPServerReviewDue(e.ctx, uuid.NullUUID{}); err != nil || due() != nil {
		t.Errorf("a private server has a due date: %v %v", due(), err)
	}
}

func ptrInt32(v int32) *int32 { return &v }

func (e *govEnv) digestOf(srv uuid.UUID) string {
	e.t.Helper()
	v, err := e.s.AdminGet(e.ctx, e.actor(e.platform), srv)
	if err != nil {
		e.t.Fatal(err)
	}
	return v.ReviewDigest
}
