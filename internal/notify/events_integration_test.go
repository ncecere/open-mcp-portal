package notify

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	testutilpromtest "github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func unhealthy(server uuid.UUID, name string) apitypes.ServerUnhealthyData {
	return apitypes.ServerUnhealthyData{Server: serverRef(server, "srv", name), Since: time.Now(), ConsecutiveFailures: 3}
}

// Recipients come from live roles at fan-out: editors and above for server
// events, owners and admins for decisions, platform admins for review
// requests, the person for personal events; never suspended people, members,
// archived teams or the person who caused the event.
func TestFanOutRecipientsByRole(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	owner, admin, editor, member, suspended, platform, outsider := e.user("none"), e.user("none"), e.user("none"), e.user("none"), e.user("none"), e.user("platform_admin"), e.user("none")
	e.member(team, owner, "owner")
	e.member(team, admin, "admin")
	e.member(team, editor, "editor")
	e.member(team, member, "member")
	e.member(team, suspended, "editor")
	e.run(`UPDATE users SET status = 'suspended' WHERE id = $1`, suspended)
	srv := e.server(team, "published")

	e.emit(ServerUnhealthy, team, "k1", unhealthy(srv, "S"))
	e.emit(PublishDecided, team, "k2", apitypes.PublishDecidedData{Server: serverRef(srv, "srv", "S"), Decision: "approved"})
	e.emit(PublishRequested, team, "k3", apitypes.PublishRequestedData{Server: serverRef(srv, "srv", "S"), Reason: "new"})
	e.emit(ConnectionNeedsReconsent, uuid.Nil, "k4", apitypes.ConnectionNeedsReconsentData{Reason: "refresh_failed"}, func(ev *Event) { ev.Recipient = member })
	e.fanOutAll()

	has := func(u uuid.UUID, event string) bool {
		return e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1 AND event = $2`, u, event) == 1
	}
	for who, want := range map[string]map[uuid.UUID]bool{
		ServerUnhealthy:          {owner: true, admin: true, editor: true, member: false, suspended: false, platform: false, outsider: false},
		PublishDecided:           {owner: true, admin: true, editor: false, member: false, suspended: false, platform: false, outsider: false},
		PublishRequested:         {owner: false, admin: false, editor: false, member: false, platform: true, outsider: false},
		ConnectionNeedsReconsent: {owner: false, editor: false, member: true, platform: false},
	} {
		for u, w := range want {
			if has(u, who) != w {
				t.Errorf("%s: %s inbox = %v, want %v", who, u, has(u, who), w)
			}
		}
	}

	// The person who caused it is skipped.
	e.emit(ServerUnhealthy, team, "k5", unhealthy(srv, "S"), func(ev *Event) { ev.Actor = editor })
	e.fanOutAll()
	if e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1 AND event_id = (SELECT id FROM notification_events WHERE dedup_key = 'k5')`, editor) != 0 {
		t.Error("the actor was told about their own action")
	}

	// A role change between emit and fan-out is honoured: roles are live.
	e.emit(ServerUnhealthy, team, "k6", unhealthy(srv, "S"))
	e.run(`UPDATE team_members SET role = 'member' WHERE user_id = $1`, editor)
	e.run(`UPDATE users SET status = 'suspended' WHERE id = $1`, admin)
	e.fanOutAll()
	for _, u := range []uuid.UUID{editor, admin} {
		if e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1 AND event_id = (SELECT id FROM notification_events WHERE dedup_key = 'k6')`, u) != 0 {
			t.Errorf("%s was told although they lost standing before fan-out", u)
		}
	}
	if e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1 AND event_id = (SELECT id FROM notification_events WHERE dedup_key = 'k6')`, owner) != 1 {
		t.Error("the owner should still be told")
	}

	// An archived team gets nothing.
	e.run(`UPDATE teams SET status = 'archived' WHERE id = $1`, team)
	e.emit(ServerUnhealthy, team, "k7", unhealthy(srv, "S"))
	e.fanOutAll()
	if e.count(`SELECT count(*) FROM notification_inbox WHERE event_id = (SELECT id FROM notification_events WHERE dedup_key = 'k7')`) != 0 {
		t.Error("an archived team was notified")
	}
}

func TestEmitDedupAndFanOutIdempotence(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	owner := e.user("none")
	e.member(team, owner, "owner")
	srv := e.server(team, "published")
	e.emit(ServerUnhealthy, team, "same", unhealthy(srv, "S"))
	if Emit(context.Background(), e.q, Event{Type: ServerUnhealthy, DedupKey: "same", TeamID: team, Data: unhealthy(srv, "S")}) {
		t.Error("the same dedup key was stored twice")
	}
	e.fanOutAll()
	e.fanOutAll()
	if e.inbox(owner) != 1 || len(e.events(ServerUnhealthy)) != 1 {
		t.Errorf("inbox %d, events %d", e.inbox(owner), len(e.events(ServerUnhealthy)))
	}
	// Fanning the same event out again (a crash between fan-out and the mark)
	// adds nothing: unique (user, event) and the outbox's dedup keys.
	e.run(`UPDATE notification_events SET fanned_out_at = NULL`)
	e.fanOutAll()
	if e.inbox(owner) != 1 || e.count(`SELECT count(*) FROM notification_outbox`) != 1 {
		t.Errorf("a repeated fan-out duplicated: inbox %d, outbox %d", e.inbox(owner), e.count(`SELECT count(*) FROM notification_outbox`))
	}
}

func TestPreferencesDecideTheChannels(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	a, b, c := e.user("none"), e.user("none"), e.user("none")
	for _, u := range []uuid.UUID{a, b, c} {
		e.member(team, u, "editor")
	}
	srv := e.server(team, "published")
	f, tr := false, true
	if _, err := e.svc.UpdatePreferences(context.Background(), personActor(a), []Change{{Event: ServerUnhealthy, InApp: &f}}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.UpdatePreferences(context.Background(), personActor(b), []Change{{Event: ServerUnhealthy, Email: &f}}); err != nil {
		t.Fatal(err)
	}
	e.emit(ServerUnhealthy, team, "p1", unhealthy(srv, "S"))
	e.runOnce()
	emailed := func(u uuid.UUID) int {
		return e.count(`SELECT count(*) FROM notification_outbox WHERE user_id = $1 AND channel = 'email'`, u)
	}
	if e.inbox(a) != 0 || emailed(a) != 1 {
		t.Errorf("a turned in-app off: inbox %d email %d", e.inbox(a), emailed(a))
	}
	if e.inbox(b) != 1 || emailed(b) != 0 {
		t.Errorf("b turned email off: inbox %d email %d", e.inbox(b), emailed(b))
	}
	if e.inbox(c) != 1 || emailed(c) != 1 {
		t.Errorf("c kept the defaults: inbox %d email %d", e.inbox(c), emailed(c))
	}
	// Back to the default stores no row.
	if _, err := e.svc.UpdatePreferences(context.Background(), personActor(a), []Change{{Event: ServerUnhealthy, InApp: &tr}}); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM notification_preferences WHERE user_id = $1`, a) != 0 {
		t.Error("a default choice is stored")
	}
	// Only receivable events can be chosen: an editor can't take publish.requested.
	if _, err := e.svc.UpdatePreferences(context.Background(), personActor(a), []Change{{Event: PublishRequested, InApp: &f}}); err == nil || !strings.Contains(err.Error(), "not_receivable") {
		t.Errorf("err = %v, want not_receivable", err)
	}
	if _, err := e.svc.UpdatePreferences(context.Background(), personActor(a), []Change{{Event: "nope", InApp: &f}}); err == nil || !strings.Contains(err.Error(), "invalid_event") {
		t.Errorf("err = %v, want invalid_event", err)
	}
	p, err := e.svc.GetPreferences(context.Background(), personActor(a))
	if err != nil || !p.EmailAvailable || p.EmailAddress == "" {
		t.Fatalf("%+v %v", p, err)
	}
	var names []string
	for _, it := range p.Items {
		names = append(names, it.Event)
	}
	if got := strings.Join(names, ","); got != "server.unhealthy,server.recovered,capability.changed,connection.needs_reconsent,upstream_signin.lapsed,key.expiring,approval.requested,approval.decided,access.requested,access.decided,server.review_due,server.sunset_soon" {
		t.Errorf("an editor can receive: %s", got)
	}
}

// Email goes only to verified addresses of active people, and at most 30 an
// hour per person (the rest are skipped; the inbox still has them).
func TestEmailRecipientsAndHourlyCap(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	verified, unverified := e.user("none"), e.user("none")
	e.member(team, verified, "owner")
	e.member(team, unverified, "owner")
	e.run(`UPDATE users SET email_verified = false WHERE id = $1`, unverified)
	srv := e.server(team, "published")
	e.emit(ServerUnhealthy, team, "v1", unhealthy(srv, "S"))
	e.runOnce()
	if got := e.mail.mails(); len(got) != 1 || !strings.Contains(got[0].To, "user") {
		t.Fatalf("mail = %+v", got)
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE user_id = $1`, unverified) != 0 {
		t.Error("an unverified address was queued")
	}
	if e.inbox(unverified) != 1 {
		t.Error("the inbox doesn't depend on the address")
	}
	// The address is read at send time: one that became unverified or
	// suspended meanwhile is skipped.
	e.emit(ServerUnhealthy, team, "v2", unhealthy(srv, "S"))
	e.fanOutAll()
	e.run(`UPDATE users SET email_verified = false WHERE id = $1`, verified)
	e.runOnce()
	if len(e.mail.mails()) != 1 || e.count(`SELECT count(*) FROM notification_outbox WHERE state = 'skipped'`) != 1 {
		t.Errorf("mail %d, skipped %d", len(e.mail.mails()), e.count(`SELECT count(*) FROM notification_outbox WHERE state = 'skipped'`))
	}

	// The hourly cap.
	e.run(`UPDATE users SET email_verified = true WHERE id = $1`, verified)
	for i := 0; i < EmailsPerHour+5; i++ {
		e.emit(ServerUnhealthy, team, fmt.Sprintf("cap-%d", i), unhealthy(srv, "S"))
	}
	e.fanOutAll()
	pending := e.count(`SELECT count(*) FROM notification_outbox WHERE user_id = $1 AND state = 'pending'`, verified)
	skipped := e.count(`SELECT count(*) FROM notification_outbox WHERE user_id = $1 AND state = 'skipped' AND created_at > now() - interval '1 minute'`, verified)
	// One sent earlier counts against the hour, and the skipped v2 row doesn't.
	if pending != EmailsPerHour-1 || skipped != 7 {
		t.Errorf("pending %d (want %d), skipped %d (want 7: the 6 over the cap and the earlier one)", pending, EmailsPerHour-1, skipped)
	}
	if e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1`, verified) < EmailsPerHour+5 {
		t.Error("the inbox keeps what email skipped")
	}
}

// A notification failure never fails the change it reports on: Emit works
// under a savepoint, so a rejected event leaves the caller's transaction
// usable.
func TestEmitSavepoint(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	srv := e.server(team, "published")
	ctx := context.Background()
	failedBefore := testutilpromtest.ToFloat64(observability.NotificationEmitErrors)
	err := store.InTx(ctx, e.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.InsertMCPHealthCheck(ctx, dbgen.InsertMCPHealthCheckParams{ServerID: srv, Ok: true, Trigger: "manual"}); err != nil {
			return err
		}
		// A database error inside Emit (a team that doesn't exist: a foreign key
		// violation) rolls back to the savepoint only.
		if Emit(ctx, q, Event{Type: ServerUnhealthy, DedupKey: "bad-fk", TeamID: uuid.New(), Data: unhealthy(srv, "S")}) {
			t.Error("an event for a missing team was stored")
		}
		if Emit(ctx, q, Event{Type: "bogus", DedupKey: "bad-type", Data: 1}) {
			t.Error("a bogus event was stored")
		}
		if !Emit(ctx, q, Event{Type: ServerUnhealthy, DedupKey: "good", TeamID: team, Data: unhealthy(srv, "S")}) {
			t.Error("a valid event after a failed one was lost")
		}
		_, err := q.InsertMCPHealthCheck(ctx, dbgen.InsertMCPHealthCheckParams{ServerID: srv, Ok: true, Trigger: "manual"})
		return err
	})
	if err != nil {
		t.Fatalf("the caller's transaction failed: %v", err)
	}
	if e.count(`SELECT count(*) FROM mcp_health_checks WHERE server_id = $1`, srv) != 2 || len(e.events(ServerUnhealthy)) != 1 {
		t.Error("the change and the good event should both be committed")
	}
	if got := testutilpromtest.ToFloat64(observability.NotificationEmitErrors) - failedBefore; got != 2 {
		t.Errorf("failed emissions counted: %v, want 2", got)
	}
	// And a change that rolls back takes its events with it.
	_ = store.InTx(ctx, e.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		Emit(ctx, q, Event{Type: ServerUnhealthy, DedupKey: "rolled-back", TeamID: team, Data: unhealthy(srv, "S")})
		return fmt.Errorf("the change failed")
	})
	if len(e.events(ServerUnhealthy)) != 1 {
		t.Error("an event of a rolled-back change survived")
	}
}

func TestHealthTransitions(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	srv := e.server(team, "published")
	ctx := context.Background()
	step := func(ok bool) {
		e.check(srv, ok)
		e.svc.ServerChecked(ctx, e.q, srv)
	}
	step(true)
	step(false)
	step(false)
	if len(e.events(ServerUnhealthy)) != 0 {
		t.Fatal("two failures are not an incident")
	}
	step(false)
	if got := e.events(ServerUnhealthy); len(got) != 1 || !strings.HasSuffix(got[0], ":0") {
		t.Fatalf("three failures in a row: %v", got)
	}
	step(false)
	step(false)
	if len(e.events(ServerUnhealthy)) != 1 {
		t.Fatal("one event per incident")
	}
	// A manual check counts like a scheduled one; still the same incident.
	e.run(`UPDATE mcp_health_checks SET trigger = 'manual' WHERE id = (SELECT max(id) FROM mcp_health_checks)`)

	// A reminder every 24 hours while it still fails.
	e.svc.SetClock(func() time.Time { return time.Now().Add(25 * time.Hour) })
	step(false)
	if got := e.events(ServerUnhealthy); len(got) != 2 || !strings.HasSuffix(got[1], ":1") {
		t.Fatalf("a reminder after 24 hours: %v", got)
	}
	payload := e.exec(`SELECT payload->>'reminder' FROM notification_events WHERE dedup_key LIKE '%:1'`)
	if payload != "true" {
		t.Errorf("reminder flag = %s", payload)
	}
	step(false)
	if len(e.events(ServerUnhealthy)) != 2 {
		t.Fatal("one reminder a day")
	}

	// Recovery: the first ok check after an incident that had an event.
	e.svc.SetClock(time.Now)
	step(true)
	rec := e.events(ServerRecovered)
	if len(rec) != 1 {
		t.Fatalf("recovered: %v", rec)
	}
	step(true)
	if len(e.events(ServerRecovered)) != 1 {
		t.Fatal("recovered once")
	}
	// A short blip (fewer than 3 failures) that recovers is not an incident.
	step(false)
	step(false)
	step(true)
	if len(e.events(ServerRecovered)) != 1 || len(e.events(ServerUnhealthy)) != 2 {
		t.Fatalf("a blip must not notify: unhealthy %v recovered %v", e.events(ServerUnhealthy), e.events(ServerRecovered))
	}
	// A new incident is a new event.
	step(false)
	step(false)
	step(false)
	if len(e.events(ServerUnhealthy)) != 3 {
		t.Fatalf("a new incident: %v", e.events(ServerUnhealthy))
	}
	// Payloads name the server and the error class, nothing else.
	raw := e.exec(`SELECT payload::text FROM notification_events WHERE event = 'server.unhealthy' ORDER BY id LIMIT 1`)
	for _, k := range []string{`"server"`, `"since"`, `"consecutiveFailures"`, `"errorClass"`, `"reminder"`} {
		if !strings.Contains(raw, k) {
			t.Errorf("payload lacks %s: %s", k, raw)
		}
	}
	if strings.Contains(raw, "message") || strings.Contains(raw, "mcp.example.com") {
		t.Errorf("the payload carries a health message or a URL: %s", raw)
	}
}

func TestCapabilityChangedOncePerHeldSet(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	pub, priv := e.server(team, "published"), e.server(team, "private")
	ctx := context.Background()
	addCap := func(srv uuid.UUID, name, fp string, approved *string) {
		e.run(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint)
			VALUES ($1, 'tool', $2, '{"name":"x"}', $3, $4)`, srv, name, fp, approved)
	}
	a, old := strings.Repeat("a", 64), strings.Repeat("b", 64)
	addCap(pub, "approved_tool", a, &a)
	e.svc.CapabilitiesRefreshed(ctx, e.q, pub)
	if len(e.events(CapabilityChanged)) != 0 {
		t.Fatal("nothing is held")
	}
	addCap(pub, "changed_tool", a, &old)
	addCap(pub, "new_tool", a, nil)
	e.svc.CapabilitiesRefreshed(ctx, e.q, pub)
	e.svc.CapabilitiesRefreshed(ctx, e.q, pub)
	if len(e.events(CapabilityChanged)) != 1 {
		t.Fatalf("the same held set is one event: %v", e.events(CapabilityChanged))
	}
	if got := e.exec(`SELECT (payload->>'changedCount') || '/' || (payload->>'newCount') || '/' || (payload->>'held') FROM notification_events WHERE event = 'capability.changed'`); got != "1/1/true" {
		t.Errorf("changed/new/held = %s", got)
	}
	addCap(pub, "another_new", a, nil)
	e.svc.CapabilitiesRefreshed(ctx, e.q, pub)
	if len(e.events(CapabilityChanged)) != 2 {
		t.Fatal("a different held set is a new event")
	}
	// A private server's capabilities are the team's business: no event.
	addCap(priv, "new_tool", a, nil)
	e.svc.CapabilitiesRefreshed(ctx, e.q, priv)
	if len(e.events(CapabilityChanged)) != 2 {
		t.Fatal("an unpublished server held nothing back from the catalog")
	}
}

func TestPublishEvents(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	owner, admin, editor, requester := e.user("none"), e.user("none"), e.user("none"), e.user("none")
	pa := e.user("platform_admin")
	e.member(team, owner, "owner")
	e.member(team, admin, "admin")
	e.member(team, editor, "editor")
	e.member(team, requester, "admin")
	srv := e.server(team, "pending")
	e.run(`UPDATE mcp_servers SET publish_requested_at = now(), publish_request_note = $2 WHERE id = $1`, srv, "please\r\n<!channel> look "+strings.Repeat("n", 500))
	ctx := context.Background()
	e.svc.PublishRequested(ctx, e.q, srv, "new", personActor(requester))
	e.svc.PublishRequested(ctx, e.q, srv, "new", personActor(requester))
	if len(e.events(PublishRequested)) != 1 {
		t.Fatalf("one event per request: %v", e.events(PublishRequested))
	}
	if got := e.exec(`SELECT (payload->>'reason') || '/' || (payload->'requestedBy'->>'kind') || '/' || length(payload->>'note') FROM notification_events WHERE event = 'publish.requested'`); got != "new/user/300" {
		t.Errorf("reason/requestedBy/note length = %s (the note is clipped to 300 characters on one line)", got)
	}
	if strings.ContainsAny(e.exec(`SELECT payload->>'note' FROM notification_events WHERE event = 'publish.requested'`), "\r\n") {
		t.Error("a note keeps its line breaks")
	}
	e.fanOutAll()
	if e.inbox(pa) != 1 || e.inbox(owner) != 0 || e.inbox(editor) != 0 {
		t.Errorf("review requests go to platform admins: pa %d owner %d", e.inbox(pa), e.inbox(owner))
	}
	// A token that requests publication is named as a token.
	e.run(`UPDATE mcp_servers SET publish_requested_at = now() + interval '1 second' WHERE id = $1`, srv)
	tok := authz.Actor{Kind: authz.KindAutomationToken, TokenID: uuid.New(), TokenName: "ci publisher", TokenKind: authz.TokenTeamPublisher}
	e.svc.PublishRequested(ctx, e.q, srv, "url_changed", tok)
	if got := e.exec(`SELECT payload->'requestedBy'->>'kind' || '/' || (payload->'requestedBy'->>'name') FROM notification_events WHERE event = 'publish.requested' ORDER BY id DESC LIMIT 1`); got != "automation_token/ci publisher" {
		t.Errorf("requestedBy = %s", got)
	}

	// The decision goes to the team's owners and admins; the platform admin
	// who decided isn't in the team.
	e.run(`UPDATE mcp_servers SET publish_state = 'published', published_at = now(), publish_reviewed_at = now(), publish_review_note = 'ok' WHERE id = $1`, srv)
	e.svc.PublishDecided(ctx, e.q, srv, true, adminActor(pa))
	e.svc.PublishDecided(ctx, e.q, srv, true, adminActor(pa))
	if len(e.events(PublishDecided)) != 1 {
		t.Fatalf("one decision: %v", e.events(PublishDecided))
	}
	e.fanOutAll()
	if e.count(`SELECT count(*) FROM notification_inbox WHERE event = 'publish.decided' AND user_id = ANY($1)`, []uuid.UUID{owner, admin, requester}) != 3 ||
		e.count(`SELECT count(*) FROM notification_inbox WHERE event = 'publish.decided' AND user_id = $1`, editor) != 0 {
		t.Error("decisions go to owners and admins")
	}
}

func TestConnectionAndSigninLapse(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	editor, other := e.user("none"), e.user("none")
	e.member(team, editor, "editor")
	e.member(team, other, "editor")
	srv := e.server(team, "published")
	e.run(`UPDATE mcp_servers SET auth_mode = 'oauth', oauth_setup_user_id = $2, oauth_setup_at = now() WHERE id = $1`, srv, editor)
	mkProvider := func(serverID *uuid.UUID, slug string) string {
		if serverID != nil {
			return e.exec(`INSERT INTO auth_providers (slug, name, kind, client_id, token_auth_method, pkce, authorization_url, token_url, server_id,
				registration, resource, issuer, authorization_server, resource_metadata_url, default_scopes)
				VALUES ($1, $1, 'mcp_server', 'c', 'none', true, 'https://auth.example.com/a', 'https://auth.example.com/t', $2, 'manual',
				'https://mcp.example.com/mcp', 'https://auth.example.com', 'https://auth.example.com',
				'https://mcp.example.com/.well-known/oauth-protected-resource/mcp', '{repo}') RETURNING id::text`, slug, *serverID)
		}
		return e.exec(`INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url)
			VALUES ($1, $1, 'c', 'none', true, 'https://auth.example.com/a', 'https://auth.example.com/t') RETURNING id::text`, slug)
	}
	conn := func(user uuid.UUID, provider string) uuid.UUID {
		return uuid.MustParse(e.exec(`INSERT INTO provider_connections (user_id, provider_id, status, access_token_cipher) VALUES ($1, $2, 'active', '\x00') RETURNING id::text`, user, provider))
	}
	ctx := context.Background()
	setup := conn(editor, mkProvider(&srv, "mcp-"+srv.String()[:8]))
	e.svc.ConnectionReconsent(ctx, e.q, setup, "invalid_grant")
	if len(e.events(UpstreamSigninLapsed)) != 1 || len(e.events(ConnectionNeedsReconsent)) != 0 {
		t.Fatalf("the setup sign-in is upstream_signin.lapsed, not a personal event: %v %v", e.events(UpstreamSigninLapsed), e.events(ConnectionNeedsReconsent))
	}
	e.svc.ConnectionReconsent(ctx, e.q, setup, "invalid_grant")
	if len(e.events(UpstreamSigninLapsed)) != 1 {
		t.Fatal("once per lapse")
	}
	personal := conn(other, mkProvider(nil, "github"))
	e.svc.ConnectionReconsent(ctx, e.q, personal, "upstream_rejected")
	// A person's own connection to the server's provider isn't the setup sign-in.
	ownServer := conn(other, e.exec(`SELECT id::text FROM auth_providers WHERE server_id = $1`, srv))
	e.svc.ConnectionReconsent(ctx, e.q, ownServer, "expired")
	if len(e.events(ConnectionNeedsReconsent)) != 2 {
		t.Fatalf("personal events: %v", e.events(ConnectionNeedsReconsent))
	}
	e.fanOutAll()
	if e.inbox(editor) != 1 || e.inbox(other) != 3 {
		t.Errorf("editor %d (want 1: the lapse), other %d (want 3: the lapse and two connections)", e.inbox(editor), e.inbox(other))
	}
	// Personal events never reach a webhook, even a platform destination that
	// takes every event: there is no route for them.
	for _, ev := range []string{ConnectionNeedsReconsent} {
		if team, platform, _ := webhookRoute(dbgen.NotificationEvent{Event: ev}); team || platform {
			t.Errorf("%s has a webhook route", ev)
		}
	}
	if team, platform, _ := webhookRoute(dbgen.NotificationEvent{Event: KeyExpiring, Payload: []byte(`{"keyKind":"personal"}`)}); team || platform {
		t.Error("a personal key's expiry has a webhook route")
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE channel = 'webhook'`) != 0 {
		t.Error("a personal event was queued for a webhook")
	}
}

func TestKeyExpiryScan(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	person, owner, admin, editor := e.user("none"), e.user("none"), e.user("none"), e.user("none")
	pa := e.user("platform_admin")
	e.member(team, owner, "owner")
	e.member(team, admin, "admin")
	e.member(team, editor, "editor")
	// Personal keys: expiring in 3 days and made 90 days ago (a warning); made
	// 5 days ago for 8 (made for more than 7 days, but 8-5=3 left: warns too);
	// made for 5 days (never warned); expiring in 10 days; revoked; expired.
	key := func(name string, created, expires string, revoked bool) {
		e.run(`INSERT INTO api_keys (user_id, name, prefix, digest, created_at, expires_at, revoked_at)
			VALUES ($1, $2::text, 'omp_xxxxxxxx', encode(sha256($2::text::bytea), 'hex'), now() - $3::interval, now() + $4::interval, CASE WHEN $5::bool THEN now() END)`, person, name, created, expires, revoked)
	}
	key("soon", "87 days", "3 days", false)
	key("short-lived", "1 day", "4 days", false) // made for 5 days
	key("later", "10 days", "10 days", false)
	key("revoked", "87 days", "3 days", true)
	key("expired", "91 days", "-1 day", false)
	sa := e.exec(`INSERT INTO service_accounts (team_id, name) VALUES ($1, 'bot') RETURNING id::text`, team)
	e.run(`INSERT INTO service_account_keys (service_account_id, name, prefix, digest, created_at, expires_at)
		VALUES ($1, 'sa-key', 'omp_sa_xxxxxxxx', encode(sha256('sa'::bytea), 'hex'), now() - interval '80 days', now() + interval '6 days')`, sa)
	tok := func(kind string, teamID *uuid.UUID, prefix, name string) {
		scopes := "{platform:read}"
		if kind == "team_publisher" {
			scopes = "{servers:read}"
		}
		e.run(`INSERT INTO automation_tokens (kind, team_id, name, prefix, digest, scopes, created_by, created_at, expires_at)
			VALUES ($1, $2, $3::text, $4, encode(sha256($3::text::bytea), 'hex'), $5::text[], $6, now() - interval '80 days', now() + interval '5 days')`, kind, teamID, name, prefix, scopes, pa)
	}
	tok("team_publisher", &team, "omppub_xxxxxxxx", "ci")
	tok("platform_admin", nil, "ompadm_xxxxxxxx", "monitoring")
	n, err := e.svc.ScanKeys(context.Background())
	if err != nil || n != 4 {
		t.Fatalf("scan: %d events, %v (want personal soon, service account key, two tokens)", n, err)
	}
	if n, _ := e.svc.ScanKeys(context.Background()); n != 0 {
		t.Fatalf("a second scan found %d new events", n)
	}
	e.fanOutAll()
	if got := e.count(`SELECT count(*) FROM notification_inbox WHERE user_id = $1`, person); got != 1 {
		t.Errorf("the person is told once, of the key expiring in 3 days: %d", got)
	}
	// Service account keys and publisher tokens go to the team's owners and
	// admins; platform tokens to platform admins; editors get none of them.
	for u, want := range map[uuid.UUID]int{owner: 2, admin: 2, editor: 0, pa: 1} {
		if got := e.inbox(u); got != want {
			t.Errorf("%s inbox = %d, want %d", u, got, want)
		}
	}
	for _, raw := range []string{e.exec(`SELECT string_agg(payload::text, ' ') FROM notification_events`)} {
		if strings.Contains(raw, "omp_") || strings.Contains(raw, "ompadm_") || strings.Contains(raw, "omppub_") || strings.Contains(raw, "xxxxxxx") {
			t.Errorf("a prefix reached a payload: %s", raw)
		}
	}
	if !strings.Contains(e.exec(`SELECT payload::text FROM notification_events WHERE dedup_key LIKE 'key.expiring:service_account:%'`), `"serviceAccount"`) {
		t.Error("a service account key's payload names its service account")
	}
}

// A server's mTLS client certificate that expires within 14 days is told as
// key.expiring (keyKind server_certificate) to the team's owners, admins and
// editors, once per certificate: not to members, not for a disabled server,
// not for one that has already expired, not for a certificate further off,
// and a renewed certificate warns again when its turn comes (decision 74).
func TestServerCertificateExpiryScan(t *testing.T) {
	e := newEnv(t, nil)
	team := e.team("ops")
	owner, admin, editor, member := e.user("none"), e.user("none"), e.user("none"), e.user("none")
	e.member(team, owner, "owner")
	e.member(team, admin, "admin")
	e.member(team, editor, "editor")
	e.member(team, member, "member")
	cert := func(slug string, enabled bool, left string, sha string) uuid.UUID {
		id := uuid.MustParse(e.exec(`INSERT INTO mcp_servers (team_id, slug, name, url, enabled) VALUES ($1, $2::text, $2::text, 'https://x.example/mcp', $3) RETURNING id::text`, team, slug, enabled))
		e.run(`INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_key_cipher, client_cert_sha256, client_not_after)
			VALUES ($1, 'x', '\x00', $2, now() + $3::interval)`, id, strings.Repeat(sha, 64), left)
		return id
	}
	soon := cert("soon", true, "10 days", "a")
	cert("off", false, "3 days", "b")
	cert("expired", true, "-1 hour", "c")
	cert("later", true, "30 days", "d")
	n, err := e.svc.ScanKeys(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("scan: %d events, %v (want only the enabled server expiring in 10 days)", n, err)
	}
	if n, _ := e.svc.ScanKeys(context.Background()); n != 0 {
		t.Fatalf("a second scan found %d new events", n)
	}
	e.fanOutAll()
	for u, want := range map[uuid.UUID]int{owner: 1, admin: 1, editor: 1, member: 0} {
		if got := e.inbox(u); got != want {
			t.Errorf("%s inbox = %d, want %d", u, got, want)
		}
	}
	payload := e.exec(`SELECT payload::text FROM notification_events WHERE dedup_key LIKE 'key.expiring:server_certificate:%'`)
	for _, want := range []string{`"keyKind": "server_certificate"`, soon.String(), `"daysLeft": 10`} {
		if !strings.Contains(payload, want) {
			t.Errorf("payload %s lacks %s", payload, want)
		}
	}
	if strings.Contains(payload, "PRIVATE") || strings.Contains(payload, "BEGIN") {
		t.Errorf("a certificate reached the payload: %s", payload)
	}
	// A renewed certificate (another fingerprint) that is itself close to expiry
	// warns again; the same one doesn't.
	e.run(`UPDATE mcp_server_tls SET client_cert_sha256 = $2, client_not_after = now() + interval '12 days' WHERE server_id = $1`, soon, strings.Repeat("e", 64))
	if n, _ := e.svc.ScanKeys(context.Background()); n != 1 {
		t.Fatalf("the renewed certificate: %d new events", n)
	}
	// Webhooks: a team destination and a platform one (with team events) get it.
	route := dbgen.NotificationEvent{Event: KeyExpiring, Payload: []byte(`{"keyKind":"server_certificate"}`)}
	if team, platform, needs := webhookRoute(route); !team || !platform || !needs {
		t.Errorf("webhook route = %v %v %v", team, platform, needs)
	}
	// The wording names the server and where to renew.
	m := compose(dbgen.NotificationEvent{Event: KeyExpiring, Payload: []byte(payload)}, &teamInfo{ID: team, Slug: "ops", Name: "Ops"})
	if !strings.Contains(m.Title, "soon") || !strings.Contains(m.Body, "TLS settings") || m.Link == nil || m.Link.Type != LinkServer || m.Link.ID != soon.String() {
		t.Errorf("message = %+v", m)
	}
}
