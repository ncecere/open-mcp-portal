package notify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// fakeClock is the shared time of the loop, the notifier and the test.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// govLoop is the governance loop on two "replicas" (two registry services over
// one database) with a notifier and a fake clock.
type govLoop struct {
	*tenv
	clock  *fakeClock
	r1, r2 *registry.Service
	leader []bool
	// T: the server's team; U: a team with a gateway selecting it.
	tOwner, tAdmin, tEditor, tMember, tNamed uuid.UUID // tNamed: an editor named as the owner
	uOwner, uAdmin, uEditor, uMember         uuid.UUID
	platform                                 uuid.UUID
	tm, u                                    uuid.UUID
}

func newGovLoop(t *testing.T) *govLoop {
	e := newEnv(t, nil)
	g := &govLoop{tenv: e, clock: &fakeClock{t: time.Now().UTC().Truncate(time.Second)}}
	mk := func() *registry.Service {
		r := registry.New(e.pool, testBox(t), &upstream.Client{AllowPrivate: true, Log: testutil.Logger()}, testutil.Logger())
		r.SetNotifier(e.svc)
		r.SetClock(g.clock.now)
		return r
	}
	g.r1, g.r2 = mk(), mk()
	g.r1.ObserveLeader = func(l bool) { g.leader = append(g.leader, l) }
	e.svc.SetClock(g.clock.now)
	g.tm, g.u = e.team("t"), e.team("u")
	person := func(team uuid.UUID, role string) uuid.UUID {
		u := e.user("none")
		e.member(team, u, role)
		return u
	}
	g.tOwner, g.tAdmin, g.tEditor, g.tMember, g.tNamed = person(g.tm, "owner"), person(g.tm, "admin"), person(g.tm, "editor"), person(g.tm, "member"), person(g.tm, "editor")
	g.uOwner, g.uAdmin, g.uEditor, g.uMember = person(g.u, "owner"), person(g.u, "admin"), person(g.u, "editor"), person(g.u, "member")
	g.platform = e.user("platform_admin")
	return g
}

func (g *govLoop) overdue(team uuid.UUID, name string) uuid.UUID {
	srv := g.server(team, "published")
	g.run(`UPDATE mcp_servers SET name = $2, slug = $2, sensitivity = 'confidential', last_reviewed_at = $3, review_due_at = $4 WHERE id = $1`,
		srv, name, g.clock.now().Add(-200*24*time.Hour), g.clock.now().Add(-time.Hour))
	return srv
}

func (g *govLoop) govern(r *registry.Service) registry.GovernanceSummary {
	g.t.Helper()
	sum, err := r.RunGovernance(context.Background())
	if err != nil {
		g.t.Fatal(err)
	}
	return sum
}

func (g *govLoop) gateway(slug, kind string, team uuid.UUID, selecting ...uuid.UUID) uuid.UUID {
	var id uuid.UUID
	if kind == "team" {
		id = uuid.MustParse(g.exec(`INSERT INTO gateways (slug, name, owner_kind, team_id) VALUES ($1, $2, 'team', $3) RETURNING id::text`, slug, "GW "+slug, team))
	} else {
		id = uuid.MustParse(g.exec(`INSERT INTO gateways (slug, name, owner_kind) VALUES ($1, $2, 'platform') RETURNING id::text`, slug, "GW "+slug))
	}
	for _, s := range selecting {
		g.run(`INSERT INTO gateway_capabilities (gateway_id, capability_id) VALUES ($1, (SELECT id FROM mcp_capabilities WHERE server_id = $2))`, id, s)
	}
	return id
}

func (g *govLoop) withTool(srv uuid.UUID) uuid.UUID {
	fp := strings.Repeat("b", 64)
	g.run(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint) VALUES ($1, 'tool', 'ping', '{}', $2, $2)`, srv, fp)
	return srv
}

func TestGovernanceLoopReviewDueNotifiesOnceAcrossReplicas(t *testing.T) {
	g := newGovLoop(t)
	srv := g.overdue(g.tm, "overdue")
	g.run(`UPDATE mcp_servers SET owner_user_id = $2 WHERE id = $1`, srv, g.tNamed)

	// Two replicas race for the lock: one leads, the other is told so.
	var wg sync.WaitGroup
	sums := make([]registry.GovernanceSummary, 2)
	for i, r := range []*registry.Service{g.r1, g.r2} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sums[i], _ = r.RunGovernance(context.Background())
		}()
	}
	wg.Wait()
	if sums[0].ReviewDueTold+sums[1].ReviewDueTold != 1 {
		t.Fatalf("told %d times by two replicas: %+v", sums[0].ReviewDueTold+sums[1].ReviewDueTold, sums)
	}
	// Another replica holds the lock: skipped, and the leader gauge says so.
	release, ok, err := store.TryAdvisoryLockText(context.Background(), g.pool, "omp.governance")
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	g.leader = nil
	if sum := g.govern(g.r1); !sum.Skipped || len(g.leader) != 1 || g.leader[0] {
		t.Errorf("under a held lock: %+v leader %v", sum, g.leader)
	}
	release()
	if sum := g.govern(g.r1); sum.Skipped || sum.ReviewDueTold != 0 || !g.leader[len(g.leader)-1] {
		t.Errorf("a repeat told again: %+v", sum)
	}
	if got := g.events(ServerReviewDue); len(got) != 1 || !strings.HasPrefix(got[0], "server.review_due:"+srv.String()+":") {
		t.Fatalf("events = %v", got)
	}
	g.fanOutAll()
	for name, c := range map[string]struct {
		who  uuid.UUID
		want int
	}{"owner": {g.tOwner, 1}, "admin": {g.tAdmin, 1}, "the named owner (an editor)": {g.tNamed, 1}, "another editor": {g.tEditor, 0}, "member": {g.tMember, 0},
		"another team's owner": {g.uOwner, 0}, "platform admin": {g.platform, 0}} {
		if n := g.inbox(c.who); n != c.want {
			t.Errorf("%s has %d notices, want %d", name, n, c.want)
		}
	}
	// A purged event does not make the loop tell them again: the loop keeps its own record.
	g.run(`DELETE FROM notification_events`)
	if sum := g.govern(g.r2); sum.ReviewDueTold != 0 || len(g.events(ServerReviewDue)) != 0 {
		t.Errorf("told again after the events were purged: %+v", sum)
	}
	// A new due date is a new notice; a date that is not due yet is not one.
	g.run(`UPDATE mcp_servers SET review_due_at = $2 WHERE id = $1`, srv, g.clock.now().Add(48*time.Hour))
	if sum := g.govern(g.r1); sum.ReviewDueTold != 0 {
		t.Errorf("told before the date: %+v", sum)
	}
	g.clock.add(72 * time.Hour)
	if sum := g.govern(g.r1); sum.ReviewDueTold != 1 || len(g.events(ServerReviewDue)) != 1 {
		t.Errorf("a new due date: %+v", sum)
	}
	// What was told: the server, its label and the date; nothing else.
	var payload string
	if err := g.pool.QueryRow(context.Background(), `SELECT payload::text FROM notification_events WHERE event = 'server.review_due'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"confidential"`, `"returnedToReview": false`} {
		if !strings.Contains(strings.ReplaceAll(payload, `":false`, `": false`), want) {
			t.Errorf("payload %s lacks %s", payload, want)
		}
	}
}

func TestGovernanceLoopReturnsOverdueToReviewOnlyWhenAsked(t *testing.T) {
	g := newGovLoop(t)
	srv := g.overdue(g.tm, "late")
	self := g.overdue(g.u, "late-self")
	g.run(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1`, g.u)
	state := func(id uuid.UUID) string { return g.exec(`SELECT publish_state FROM mcp_servers WHERE id = $1`, id) }

	// Off by default: told, left published.
	if sum := g.govern(g.r1); sum.ReviewDueTold != 2 || sum.ReturnedToReview != 0 || state(srv) != "published" || state(self) != "published" {
		t.Fatalf("setting off: %+v %s %s", sum, state(srv), state(self))
	}
	// On: the approval_required team's server goes back to review, the self_publish team's stays.
	g.run(`UPDATE platform_settings SET governance_return_overdue = true`)
	if sum := g.govern(g.r2); sum.ReturnedToReview != 1 || state(srv) != "pending" || state(self) != "published" {
		t.Fatalf("setting on: %+v %s %s", sum, state(srv), state(self))
	}
	if g.count(`SELECT count(*) FROM audit_log WHERE action = 'mcp_server.publish_request' AND actor_kind = 'system' AND actor_user_id IS NULL
		AND target_id = $1 AND metadata->>'reason' = 'review_due'`, srv.String()) != 1 {
		t.Error("the return to review was not audited as the system's")
	}
	var by string
	if err := g.pool.QueryRow(context.Background(), `SELECT payload->'requestedBy'->>'kind' FROM notification_events WHERE event = 'publish.requested'`).Scan(&by); err != nil || by != "system" {
		t.Errorf("publish.requested names %q: %v", by, err)
	}
	if g.count(`SELECT count(*) FROM notification_events WHERE event = 'publish.requested' AND payload->>'reason' = 'review_due'`) != 1 {
		t.Error("platform admins were not told that a review was requested")
	}
	// Nothing is ever unpublished, disabled or deleted by the loop.
	if g.count(`SELECT count(*) FROM mcp_servers WHERE enabled`) != 2 {
		t.Error("a server was disabled")
	}
	if sum := g.govern(g.r1); sum.ReturnedToReview != 0 || sum.ReviewDueTold != 0 {
		t.Errorf("a repeat: %+v", sum)
	}
}

func TestGovernanceLoopSunsetAndDeprecationNotices(t *testing.T) {
	g := newGovLoop(t)
	srv := g.withTool(g.server(g.tm, "published"))
	g.run(`UPDATE mcp_servers SET owner_user_id = $2, oncall_contact = '#secret-oncall', name = 'Legacy', slug = 'legacy' WHERE id = $1`, srv, g.tNamed)
	successor := g.server(g.tm, "published")
	platformGW := g.gateway("plat", "platform", uuid.Nil, srv)
	uGW := g.gateway("ugw", "team", g.u, srv)
	tGW := g.gateway("tgw", "team", g.tm, srv)
	off := g.gateway("off", "team", g.u, srv)
	g.run(`UPDATE gateways SET enabled = false WHERE id = $1`, off)
	privateServer := g.withTool(g.server(g.tm, "private"))
	g.run(`UPDATE mcp_servers SET lifecycle = 'deprecated', deprecated_at = now(), sunset_at = $2 WHERE id = $1`, privateServer, g.clock.now().Add(5*24*time.Hour))
	g.gateway("ugw2", "team", g.u, privateServer)
	_ = platformGW
	_ = uGW
	_ = tGW

	// Deprecating through the API tells the owners of the selecting gateways in its own transaction.
	sunset := g.clock.now().Add(30 * 24 * time.Hour)
	admin := authz.Actor{UserID: g.tAdmin}
	var rev int64
	if err := g.pool.QueryRow(context.Background(), `SELECT revision FROM mcp_servers WHERE id = $1`, srv).Scan(&rev); err != nil {
		t.Fatal(err)
	}
	if _, err := g.r1.Update(context.Background(), admin, "t", srv, registry.UpdateInput{Governance: &registry.GovernanceInput{Lifecycle: ptr("deprecated"),
		SetSunsetAt: true, SunsetAt: &sunset, SetReplacement: true, ReplacementServerID: &successor}}, rev); err != nil {
		t.Fatal(err)
	}
	if got := g.events(ServerDeprecated); len(got) != 3 {
		t.Fatalf("deprecated notices = %v (platform, u and t gateways: not the disabled one, not the private server's)", got)
	}
	// The loop adds none for the same deprecation, and none while the sunset is far.
	// (The private server's own team is told its sunset is near: five days.)
	sum := g.govern(g.r2)
	if sum.DeprecatedTold != 0 || sum.SunsetSoonTold != 1 || len(g.events(ServerDeprecated)) != 3 || len(g.events(ServerSunsetSoon)) != 1 {
		t.Fatalf("first run: %+v", sum)
	}
	// A gateway that selects it later is told by the loop, once.
	late := g.gateway("late", "team", g.u, srv)
	_ = late
	if sum := g.govern(g.r1); sum.DeprecatedTold != 1 || len(g.events(ServerDeprecated)) != 4 {
		t.Fatalf("late gateway: %+v", sum)
	}
	if sum := g.govern(g.r2); sum.DeprecatedTold != 0 {
		t.Fatalf("late gateway again: %+v", sum)
	}
	// Sunset inside the window: the server's team and every selecting gateway's owners, once.
	g.clock.add(17 * 24 * time.Hour) // 13 days left
	if sum := g.govern(g.r1); sum.SunsetSoonTold != 1+4 {
		t.Fatalf("sunset soon: %+v", sum)
	}
	if sum := g.govern(g.r2); sum.SunsetSoonTold != 0 {
		t.Fatalf("sunset soon again: %+v", sum)
	}
	// At the sunset it is no longer soon.
	g.clock.add(14 * 24 * time.Hour)
	if sum := g.govern(g.r1); sum.SunsetSoonTold != 0 || sum.DeprecatedTold != 0 {
		t.Fatalf("after the sunset: %+v", sum)
	}

	g.fanOutAll()
	inbox := func(who uuid.UUID, event string) int {
		return g.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1 AND event = $2`, who, event)
	}
	// The server's team: its owner, admins and named owner hear that the sunset is near; nobody else.
	for name, c := range map[string]struct {
		who  uuid.UUID
		want int
	}{"T owner": {g.tOwner, 3}, "T admin": {g.tAdmin, 3}, "named owner": {g.tNamed, 1}, "T editor": {g.tEditor, 0}, "T member": {g.tMember, 0}} {
		// Its own gateway and the private server are two more for its owners and admins.
		if got := inbox(c.who, ServerSunsetSoon); got != c.want {
			t.Errorf("%s: %d sunset notices, want %d", name, got, c.want)
		}
	}
	// Owners and admins of U's gateways (three of them selected it: ugw, late; not the disabled one).
	for name, c := range map[string]struct {
		who  uuid.UUID
		want int
	}{"U owner": {g.uOwner, 2}, "U admin": {g.uAdmin, 2}, "U editor": {g.uEditor, 0}, "U member": {g.uMember, 0}, "platform admin": {g.platform, 1}} {
		if got := inbox(c.who, ServerDeprecated); got != c.want {
			t.Errorf("%s: %d deprecation notices, want %d", name, got, c.want)
		}
	}
	if inbox(g.uOwner, ServerSunsetSoon) != 2 || inbox(g.platform, ServerSunsetSoon) != 1 {
		t.Errorf("sunset notices of U owner %d, platform admin %d", inbox(g.uOwner, ServerSunsetSoon), inbox(g.platform, ServerSunsetSoon))
	}

	// Privacy. A gateway's notice belongs to the gateway's team and says nothing of
	// the server team's people or contact; the other team's gateways are not named.
	rows, err := g.pool.Query(context.Background(), `SELECT event, coalesce(team_id::text, ''), subject_type, payload::text FROM notification_events WHERE subject_type = 'gateway'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var event, team, subject, payload string
		_ = rows.Scan(&event, &team, &subject, &payload)
		n++
		for _, leak := range []string{"secret-oncall", "owner_user_id", "ownerUserId", "@example.com", "User ", "Team t", `"slug":"t"`} {
			if strings.Contains(payload, leak) {
				t.Errorf("%s payload leaks %q: %s", event, leak, payload)
			}
		}
		if strings.Count(payload, `"gateway"`) != 1 {
			t.Errorf("%s payload names more than one gateway: %s", event, payload)
		}
		if team != g.tm.String() && team != g.u.String() && team != "" {
			t.Errorf("%s belongs to team %s", event, team)
		}
	}
	if n < 8 {
		t.Errorf("gateway-level events = %d", n)
	}
	for _, event := range []string{ServerReviewDue, ServerSunsetSoon, ServerDeprecated} {
		if a, b, c := webhookRoute(dbRow(event)); a || b || c {
			t.Errorf("%s routes to webhooks", event)
		}
		if IsTeamEvent(event) {
			t.Errorf("%s is a team event for platform webhooks", event)
		}
	}
}

func TestGovernanceEmailIsCheckedAgainAtDelivery(t *testing.T) {
	g := newGovLoop(t)
	g.overdue(g.tm, "mail")
	g.govern(g.r1)
	g.fanOutAll()
	// The admin left the team's admins between fan-out and delivery.
	g.run(`UPDATE team_members SET role = 'member' WHERE user_id = $1`, g.tAdmin)
	g.runOnce()
	var to []string
	for _, m := range g.mail.mails() {
		to = append(to, m.To)
	}
	var adminMail, ownerMail string
	adminMail = g.exec(`SELECT email FROM users WHERE id = $1`, g.tAdmin)
	ownerMail = g.exec(`SELECT email FROM users WHERE id = $1`, g.tOwner)
	got := strings.Join(to, ",")
	if strings.Contains(got, adminMail) || !strings.Contains(got, ownerMail) {
		t.Errorf("mail went to %v: the demoted admin must not get it and the owner must", to)
	}
}

func TestGovernanceLoopIsBounded(t *testing.T) {
	g := newGovLoop(t)
	for i := 0; i < registry.GovernanceBatch+7; i++ {
		g.overdue(g.tm, fmt.Sprintf("bulk-%02d", i))
	}
	if sum := g.govern(g.r1); sum.ReviewDueTold != registry.GovernanceBatch {
		t.Fatalf("first run told %d, want the batch of %d", sum.ReviewDueTold, registry.GovernanceBatch)
	}
	if sum := g.govern(g.r2); sum.ReviewDueTold != 7 {
		t.Fatalf("second run told %d, want 7", sum.ReviewDueTold)
	}
	if sum := g.govern(g.r1); sum.ReviewDueTold != 0 || len(g.events(ServerReviewDue)) != registry.GovernanceBatch+7 {
		t.Fatalf("third run: %+v, %d events", sum, len(g.events(ServerReviewDue)))
	}
}

func dbRow(event string) dbgen.NotificationEvent { return dbgen.NotificationEvent{Event: event} }
