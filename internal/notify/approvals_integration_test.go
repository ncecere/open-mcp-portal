package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type approvalEnv struct {
	*tenv
	approval                      *approvals.Service
	requester, reviewer, observer uuid.UUID
	input                         approvals.BeginInput
}

func newApprovalEnv(t *testing.T) *approvalEnv {
	t.Helper()
	e := newEnv(t, nil)
	a := &approvalEnv{tenv: e, requester: e.user("none"), reviewer: e.user("none"), observer: e.user("platform_admin")}
	team := e.team("sensitive")
	e.member(team, a.reviewer, "owner")
	server := e.server(team, "published")
	cap := uuid.MustParse(e.exec(`INSERT INTO mcp_capabilities(server_id,kind,name,definition,fingerprint,approved_fingerprint,tool_class)
		VALUES ($1,'tool','delete','{}',repeat('a',64),repeat('a',64),'destructive') RETURNING id::text`, server))
	gateway := uuid.MustParse(e.exec(`INSERT INTO gateways(slug,name,owner_kind) VALUES ('sensitive','Sensitive','platform') RETURNING id::text`))
	e.run(`INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES ($1,$2)`, gateway, cap)
	e.run(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2)`, gateway, a.requester)
	var err error
	a.approval, err = approvals.New(e.pool, testBox(t), nil, "https://portal.example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.approval.CreateRule(context.Background(), personActor(a.reviewer), team.String(), approvals.RuleInput{
		Name: "Sensitive", TargetKind: "server", TargetID: server, Classes: []string{"destructive"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := a.approval.Epoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	class := "destructive"
	slug := e.exec(`SELECT slug FROM mcp_servers WHERE id=$1`, server)
	a.input = approvals.BeginInput{Binding: approvals.Binding{Epoch: epoch, RequesterKind: "user", RequesterID: a.requester,
		GatewayID: gateway, ServerID: server, CapabilityID: cap, ExposedName: slug + "__delete", ToolClass: &class,
		CapabilityFingerprint: strings.Repeat("a", 64), ServerOrigin: "https://mcp.example.com"},
		Arguments: json.RawMessage(`{"privateArg":"ARGUMENT-SENTINEL-814","note":"NOTE-SENTINEL-815"}`), CredentialExpiresAt: time.Now().Add(time.Hour)}
	a.approval.EmitNotice = ApprovalNotice
	e.svc.ApprovalRecipients = a.approval.NotificationRecipients
	return a
}

func (a *approvalEnv) begin() approvals.Plan {
	a.t.Helper()
	p, err := a.approval.Begin(context.Background(), a.input)
	if err != nil {
		a.t.Fatal(err)
	}
	return p
}

func (a *approvalEnv) decide(p approvals.Plan, decision string) approvals.Receipt {
	a.t.Helper()
	r, err := a.approval.Decide(context.Background(), personActor(a.reviewer), p.Receipt.ID, approvals.Decision{
		Decision: decision, ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	if err != nil {
		a.t.Fatal(err)
	}
	return r
}

func TestApprovalNoticesDedupRenewAndPrivateChannels(t *testing.T) {
	a := newApprovalEnv(t)
	ctx := context.Background()
	p := a.begin()
	second := a.begin()
	if p.Receipt.ID != second.Receipt.ID || !p.Receipt.ExpiresAt.Equal(second.Receipt.ExpiresAt) || len(a.events(ApprovalRequested)) != 1 {
		t.Fatal("binding dedup repeated the notice or extended the deadline")
	}
	a.runOnce()
	if a.inbox(a.reviewer) != 1 || a.inbox(a.requester) != 0 || a.inbox(a.observer) != 0 || len(a.mail.mails()) != 1 {
		t.Fatal("requested audience is not exactly the live reviewer")
	}
	denied := a.decide(p, "deny")
	a.runOnce()
	if a.inbox(a.requester) != 1 || a.inbox(a.observer) != 0 || len(a.mail.mails()) != 2 {
		t.Fatal("decision did not go privately to the requester")
	}
	if got := a.begin(); got.Receipt.ID != denied.ID || len(a.events(ApprovalRequested)) != 1 || len(a.events(ApprovalDecided)) != 1 {
		t.Fatal("ordinary denied retry emitted or renewed")
	}
	renewed, err := a.approval.Renew(ctx, personActor(a.requester), denied.ID, denied.ReviewRevision)
	if err != nil {
		t.Fatal(err)
	}
	if renewed.ID == denied.ID || len(a.events(ApprovalRequested)) != 2 {
		t.Fatal("explicit renewal did not emit once for a new receipt")
	}
	a.runOnce()
	if a.count(`SELECT count(*) FROM notification_outbox WHERE channel='webhook'`) != 0 {
		t.Fatal("private approval routed to a webhook")
	}
	// Inspect the real event and outbox/inbox rows, and both rendered email
	// variants. No whole receipt serialization, digests, notes or args.
	raw := a.exec(`SELECT string_agg(payload::text,' ') FROM notification_events WHERE event LIKE 'approval.%'`) +
		a.exec(`SELECT string_agg(row_to_json(i)::text,' ') FROM notification_inbox i`) +
		a.exec(`SELECT string_agg(row_to_json(o)::text,' ') FROM notification_outbox o`)
	for _, m := range a.mail.mails() {
		raw += m.Subject + m.Text + m.HTML
	}
	for _, forbidden := range []string{"ARGUMENT-SENTINEL-814", "NOTE-SENTINEL-815", p.Receipt.ArgsDigest, "argsDigest", "bindingDigest", "preview", "privateArg", "serverOrigin", "requesterId"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("private value %q reached notifications", forbidden)
		}
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(a.exec(`SELECT payload::text FROM notification_events ORDER BY id LIMIT 1`)), &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 3 || data["approvalId"] != p.Receipt.ID.String() || data["status"] != "pending" {
		t.Fatalf("payload allowlist: %#v", data)
	}
	for _, m := range a.mail.mails() {
		if !strings.Contains(m.Text, "https://portal.example.com/approvals/") {
			t.Fatal("receipt deep link missing")
		}
	}
}

func TestApprovalNoticeFailureCannotRollbackApprovalAndAudit(t *testing.T) {
	a := newApprovalEnv(t)
	// DDL only through the scratch database's owner. Both split-role and
	// legacy service operations continue on their genuine application pool.
	owner := testutil.OwnerPool(t, a.pool)
	if _, err := owner.Exec(context.Background(), `ALTER TABLE notification_events ADD CONSTRAINT reject_approval_notices CHECK(event NOT LIKE 'approval.%')`); err != nil {
		t.Fatal(err)
	}
	p := a.begin()
	if a.count(`SELECT count(*) FROM approval_requests WHERE id=$1`, p.Receipt.ID) != 1 ||
		a.count(`SELECT count(*) FROM audit_log WHERE target_id=$1 AND action='approval_request.requested'`, p.Receipt.ID.String()) != 1 {
		t.Fatal("failed emission rolled back the approval or its audit")
	}
	r := a.decide(p, "approve")
	if r.Status != approvals.Approved || a.count(`SELECT count(*) FROM audit_log WHERE target_id=$1 AND action='approval_request.approved'`, p.Receipt.ID.String()) != 1 {
		t.Fatal("failed emission rolled back the decision or its audit")
	}
	if a.count(`SELECT count(*) FROM notification_events WHERE event LIKE 'approval.%'`) != 0 {
		t.Fatal("rejected notice survived")
	}
}

func TestApprovalFanOutFailClosedAndEmailRechecks(t *testing.T) {
	a := newApprovalEnv(t)
	p := a.begin()
	a.svc.ApprovalRecipients = nil
	a.runOnce()
	if a.count(`SELECT count(*) FROM notification_inbox`)+a.count(`SELECT count(*) FROM notification_outbox`) != 0 {
		t.Fatal("nil live resolver sent a private event")
	}
	// Retry fan-out with the real resolver, then revoke eligibility before
	// email delivery. Re-resolution at send time must suppress the email.
	a.svc.ApprovalRecipients = a.approval.NotificationRecipients
	a.run(`UPDATE notification_events SET fanned_out_at=NULL WHERE subject_id=$1`, p.Receipt.ID.String())
	a.fanOutAll()
	if a.inbox(a.reviewer) != 1 {
		t.Fatal("wired live resolver did not fan out")
	}
	a.run(`UPDATE users SET groups=ARRAY['changed']::text[] WHERE id=$1`, a.reviewer)
	a.runOnce()
	if len(a.mail.mails()) != 0 || a.count(`SELECT count(*) FROM notification_outbox WHERE state='skipped'`) != 1 {
		t.Fatal("stale approval metadata escaped a delayed email")
	}
}

func TestApprovalPreferencesEnumerateAndApply(t *testing.T) {
	a := newApprovalEnv(t)
	for _, u := range []uuid.UUID{a.requester, a.reviewer, a.observer} {
		p, err := a.svc.GetPreferences(context.Background(), personActor(u))
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range []string{ApprovalRequested, ApprovalDecided} {
			n := 0
			for _, it := range p.Items {
				if it.Event == event {
					n++
					if !it.InApp || !it.Email || it.Custom {
						t.Fatal("approval default is not in-app/email on")
					}
				}
			}
			if n != 1 {
				t.Fatalf("%s missing/duplicated for %s", event, u)
			}
		}
	}
	off := false
	_, err := a.svc.UpdatePreferences(context.Background(), personActor(a.reviewer), []Change{{Event: ApprovalRequested, InApp: &off, Email: &off}})
	if err != nil {
		t.Fatal(err)
	}
	a.begin()
	a.runOnce()
	if a.inbox(a.reviewer) != 0 || len(a.mail.mails()) != 0 {
		t.Fatal("approval channel preferences ignored")
	}
}

func TestApprovalWebhookSubscriptionsRejected(t *testing.T) {
	e := newEnv(t, nil)
	owner, admin := e.user("none"), e.user("platform_admin")
	team := e.team("ops")
	e.member(team, owner, "owner")
	for _, event := range []string{ApprovalRequested, ApprovalDecided} {
		for _, platform := range []bool{false, true} {
			sc, actor := Scope{TeamRef: team.String()}, personActor(owner)
			if platform {
				sc, actor = Scope{}, adminActor(admin)
			}
			name, raw := "Private "+event, "https://hooks.example.com/path"
			events := []string{event}
			on := true
			_, _, err := e.svc.Create(context.Background(), actor, sc, Input{Name: &name, Format: "json", URL: &raw, Events: &events, TeamEvents: &on})
			if code(err) != "invalid_events" {
				t.Fatalf("private subscription %s platform=%v: %v", event, platform, err)
			}
		}
		ev := dbgen.NotificationEvent{Event: event}
		if team, platform, _ := webhookRoute(ev); team || platform {
			t.Fatal("private webhook route")
		}
		// Even an erroneous pre-existing outbox row must never send.
		if got := e.svc.deliverWebhook(context.Background(), dbgen.NotificationOutbox{}, ev, nil, Message{}); got.Class != "skipped" {
			t.Fatal(fmt.Sprint(got))
		}
	}
}
