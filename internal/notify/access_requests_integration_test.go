package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestAccessNoticesPrivateLiveRecipientsAndFailureIsolation(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	requester, steward, admin := e.user("none"), e.user("none"), e.user("platform_admin")
	g := uuid.MustParse(e.exec(`INSERT INTO gateways(slug,name,owner_kind,access_requests_enabled) VALUES('requestable','Requestable','platform',true) RETURNING id::text`))
	e.run(`INSERT INTO gateway_stewards(gateway_id,user_id) VALUES($1,$2)`, g, steward)
	svc := gateways.New(e.pool, "https://portal.example.com", testutil.Logger())
	svc.AccessNotice = AccessNotice
	r, err := svc.CreateAccessRequest(ctx, personActor(requester), g, nil, "PRIVATE_ACCESS_REASON_SENTINEL")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateAccessRequest(ctx, personActor(requester), g, nil, "duplicate"); err == nil {
		t.Fatal("duplicate request accepted")
	}
	if len(e.events(AccessRequested)) != 1 {
		t.Fatal("duplicate notice emitted")
	}
	e.fanOutAll()
	if e.inbox(steward) != 1 || e.inbox(admin) != 1 || e.inbox(requester) != 0 {
		t.Fatal("requested audience is not current nonrequester reviewers")
	}
	// Remove stewardship after fan-out: its queued email must now be skipped.
	e.run(`DELETE FROM gateway_stewards WHERE gateway_id=$1 AND user_id=$2`, g, steward)
	e.runOnce()
	if len(e.mail.mails()) != 1 {
		t.Fatalf("revoked steward got email: %+v", e.mail.mails())
	}
	_, err = svc.DecideAccessRequest(ctx, personActor(admin), r.ID, gateways.AccessDecision{Decision: "approve", Note: "PRIVATE_ACCESS_NOTE_SENTINEL"})
	if err != nil {
		t.Fatal(err)
	}
	e.runOnce()
	if e.inbox(requester) != 1 || len(e.mail.mails()) != 2 {
		t.Fatal("decision notice did not reach requester only")
	}
	if e.count(`SELECT count(*) FROM notification_outbox WHERE channel='webhook'`) != 0 {
		t.Fatal("access notice escaped to webhook")
	}
	raw := e.exec(`SELECT string_agg(payload::text,' ') FROM notification_events WHERE event LIKE 'access.%'`) + e.exec(`SELECT string_agg(row_to_json(i)::text,' ') FROM notification_inbox i`)
	for _, m := range e.mail.mails() {
		raw += m.Subject + m.Text + m.HTML
	}
	for _, forbidden := range []string{"PRIVATE_ACCESS_REASON_SENTINEL", "PRIVATE_ACCESS_NOTE_SENTINEL", "requesterId", "grantId", "reason", "decisionNote"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("private value %q in notifications", forbidden)
		}
	}
	if !strings.Contains(raw, "https://portal.example.com/access-requests/") {
		t.Fatal("private request link missing")
	}

	// Emit's savepoint must isolate best-effort notification failure from the
	// authoritative request/grant/audit transaction, including under split roles.
	owner := testutil.OwnerPool(t, e.pool)
	if _, err := owner.Exec(ctx, `ALTER TABLE notification_events ADD CONSTRAINT reject_access_events CHECK(event NOT LIKE 'access.%') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	g2 := uuid.MustParse(e.exec(`INSERT INTO gateways(slug,name,owner_kind,access_requests_enabled) VALUES('failure','Failure','platform',true) RETURNING id::text`))
	r2, err := svc.CreateAccessRequest(ctx, personActor(requester), g2, nil, "notification failure")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DecideAccessRequest(ctx, personActor(admin), r2.ID, gateways.AccessDecision{Decision: "approve"}); err != nil {
		t.Fatal(err)
	}
	if e.count(`SELECT count(*) FROM gateway_grants WHERE gateway_id=$1`, g2) != 1 || e.count(`SELECT count(*) FROM audit_log WHERE action='access_request.approve'`) != 2 {
		t.Fatal("notification failure rolled back grant/audit")
	}
}
