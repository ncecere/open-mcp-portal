package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

type serviceFixture struct {
	s                                                      *Service
	db, owner                                              *pgxpool.Pool
	q                                                      *dbgen.Queries
	requester, reviewer, saOwner, admin, auditor, outsider authz.Actor
	team, saTeam, server, cap, gateway, sa                 uuid.UUID
	rule                                                   Rule
	input                                                  BeginInput
}

func newServiceFixture(t *testing.T) *serviceFixture {
	t.Helper()
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	db, _ := testutil.NewDB(t)
	f := &serviceFixture{db: db, owner: testutil.OwnerPool(t, db), q: dbgen.New(db), team: uuid.New(), saTeam: uuid.New(), server: uuid.New(), cap: uuid.New(), gateway: uuid.New(), sa: uuid.New()}
	users := []*authz.Actor{&f.requester, &f.reviewer, &f.saOwner, &f.admin, &f.auditor, &f.outsider}
	for i, a := range users {
		a.UserID = uuid.New()
		a.PlatformRole = authz.PlatformNone
		if i == 3 {
			a.PlatformRole = authz.PlatformAdmin
		}
		if i == 4 {
			a.PlatformRole = authz.PlatformAuditor
		}
		execFixture(t, db, `INSERT INTO users(id,oidc_issuer,oidc_subject,email,platform_role) VALUES ($1,'test',$2,$3,$4)`, a.UserID, fmt.Sprint(i), fmt.Sprintf("u%d@test.invalid", i), a.PlatformRole)
	}
	execFixture(t, db, `INSERT INTO teams(id,slug,name) VALUES ($1,'server-team','Servers'),($2,'account-team','Accounts')`, f.team, f.saTeam)
	execFixture(t, db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'owner'),($3,$4,'owner'),($3,$5,'member')`, f.team, f.reviewer.UserID, f.saTeam, f.saOwner.UserID, f.requester.UserID)
	execFixture(t, db, `INSERT INTO mcp_servers(id,team_id,slug,name,url,publish_state,published_at,enabled) VALUES ($1,$2,'server','Server','https://server.test/mcp','published',now(),true)`, f.server, f.team)
	execFixture(t, db, `INSERT INTO mcp_capabilities(id,server_id,kind,name,definition,fingerprint,approved_fingerprint,tool_class) VALUES ($1,$2,'tool','delete','{}',repeat('a',64),repeat('a',64),'destructive')`, f.cap, f.server)
	execFixture(t, db, `INSERT INTO gateways(id,slug,name,owner_kind,enabled) VALUES ($1,'platform','Platform','platform',true)`, f.gateway)
	execFixture(t, db, `INSERT INTO gateway_capabilities(gateway_id,capability_id) VALUES ($1,$2)`, f.gateway, f.cap)
	execFixture(t, db, `INSERT INTO gateway_grants(gateway_id,subject_kind,team_id,user_id) VALUES ($1,'team',$2,NULL),($1,'user',NULL,$3),($1,'user',NULL,$4)`, f.gateway, f.saTeam, f.requester.UserID, f.outsider.UserID)
	execFixture(t, db, `INSERT INTO service_accounts(id,team_id,name,enabled) VALUES ($1,$2,'worker',true)`, f.sa, f.saTeam)
	box, err := secrets.New([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	f.s, err = New(db, box, func(context.Context) ([]*regexp.Regexp, error) {
		return []*regexp.Regexp{regexp.MustCompile(`CUSTOM-[A-Z]+`)}, nil
	}, "https://portal.test")
	if err != nil {
		t.Fatal(err)
	}
	f.rule, err = f.s.CreateRule(context.Background(), f.reviewer, f.team.String(), RuleInput{Name: "Destructive calls", TargetKind: "server", TargetID: f.server, Classes: []string{"destructive"}, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	class := "destructive"
	f.input = BeginInput{Binding: Binding{Epoch: mustEpoch(t, f.s), RequesterKind: "user", RequesterID: f.requester.UserID, GatewayID: f.gateway, ServerID: f.server, CapabilityID: f.cap, ExposedName: "server__delete", ToolClass: &class, CapabilityFingerprint: strings.Repeat("a", 64), ServerOrigin: "https://server.test"}, Arguments: json.RawMessage(`{"id":9007199254740993}`), CredentialExpiresAt: time.Now().Add(time.Hour)}
	return f
}
func execFixture(t *testing.T, db *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := db.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}
func mustEpoch(t *testing.T, s *Service) int64 {
	t.Helper()
	e, err := s.Epoch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func beginFixture(t *testing.T, f *serviceFixture) Plan {
	t.Helper()
	p, e := f.s.Begin(context.Background(), f.input)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func approveFixture(t *testing.T, f *serviceFixture, p Plan) Plan {
	t.Helper()
	r, e := f.s.Decide(context.Background(), f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	if e != nil {
		t.Fatal(e)
	}
	if r.Status != Approved {
		t.Fatal(r.Status)
	}
	return beginFixture(t, f)
}
func requireCode(t *testing.T, err error, code string) {
	t.Helper()
	var e *apperr.Error
	if !errors.As(err, &e) || e.Code != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
func requestStatus(t *testing.T, f *serviceFixture, id uuid.UUID) string {
	t.Helper()
	r, e := f.q.GetApprovalRequest(context.Background(), id)
	if e != nil {
		t.Fatal(e)
	}
	return r.Status
}
func countFixture(t *testing.T, f *serviceFixture, sql string, args ...any) int {
	t.Helper()
	var n int
	if e := f.db.QueryRow(context.Background(), sql, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}

func TestServiceDedupQuotaAndSingleSpend(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	first := beginFixture(t, f)
	var wg sync.WaitGroup
	results := make(chan Plan, 24)
	errs := make(chan error, 24)
	for range 24 {
		wg.Go(func() {
			p, e := f.s.Begin(ctx, f.input)
			if e != nil {
				errs <- e
			} else {
				results <- p
			}
		})
	}
	wg.Wait()
	close(errs)
	close(results)
	for e := range errs {
		t.Error(e)
	}
	for p := range results {
		if p.Receipt.ID != first.Receipt.ID || !p.Receipt.ExpiresAt.Equal(first.Receipt.ExpiresAt) {
			t.Fatal("dedup extended or replaced request")
		}
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action='approval_request.requested'`); n != 1 {
		t.Fatalf("requested audits=%d", n)
	}
	first = approveFixture(t, f, first)
	var wins atomic.Int32
	errs = make(chan error, 24)
	for range 24 {
		wg.Go(func() {
			e := f.s.Consume(ctx, first)
			if e == nil {
				wins.Add(1)
			} else if !errors.Is(e, ErrSpent) {
				errs <- e
			}
		})
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
	if wins.Load() != 1 {
		t.Fatalf("spends=%d", wins.Load())
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action='approval_request.used' AND actor_kind='system' AND actor_user_id IS NULL`); n != 1 {
		t.Fatalf("system use audits=%d", n)
	}
	next := beginFixture(t, f)
	if next.Receipt.ID == first.Receipt.ID || next.Receipt.Status != Pending {
		t.Fatal("spent approval reused")
	}
	for i := 1; i < 20; i++ {
		f.input.Arguments = json.RawMessage(fmt.Sprintf(`{"id":%d}`, i))
		beginFixture(t, f)
	}
	f.input.Arguments = json.RawMessage(`{"id":"twenty-first"}`)
	_, e := f.s.Begin(ctx, f.input)
	requireCode(t, e, "approval_unavailable")
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests WHERE status='pending'`); n != 20 {
		t.Fatalf("pending=%d", n)
	}
}

func TestServiceDenialRenewalAndReviewCAS(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	fixed := time.Now().UTC().Truncate(time.Microsecond)
	f.s.SetClock(func() time.Time { return fixed })
	p := beginFixture(t, f)
	_, e := f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 99, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	requireCode(t, e, "changed_since_review")
	_, e = f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 1, ExpectedArgsDigest: strings.Repeat("0", 64)})
	requireCode(t, e, "changed_since_review")
	denied, e := f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "deny", ExpectedReviewRevision: 1, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	if e != nil {
		t.Fatal(e)
	}
	retry := beginFixture(t, f)
	if retry.Receipt.ID != denied.ID || retry.Receipt.Status != Denied {
		t.Fatal("retry implicitly renewed denial")
	}
	detail, e := f.s.GetRequest(ctx, f.requester, denied.ID)
	if e != nil || !detail.CanRenew || detail.Preview != nil {
		t.Fatalf("denied detail=%+v %v", detail, e)
	}
	renewed, e := f.s.Renew(ctx, f.requester, denied.ID, denied.ReviewRevision)
	if e != nil {
		t.Fatal(e)
	}
	if renewed.ID == denied.ID || renewed.Status != Pending {
		t.Fatal("renewal resurrected old request")
	}
	// Fixed clocks and PostgreSQL microsecond precision cannot let UUID sort
	// order cause a remembered denial to outrank its explicit new attempt.
	if retry = beginFixture(t, f); retry.Receipt.ID != renewed.ID {
		t.Fatal("renewal not newest binding")
	}
	if requestStatus(t, f, denied.ID) != Denied {
		t.Fatal("old denial changed")
	}
	if _, e = f.s.Renew(ctx, f.requester, denied.ID, denied.ReviewRevision); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("repeated renewal=%v", e)
	}
	detail, e = f.s.GetRequest(ctx, f.requester, renewed.ID)
	if e != nil || detail.Preview == nil {
		t.Fatalf("new AAD preview=%+v %v", detail, e)
	}
	_, e = f.s.Cancel(ctx, f.requester, renewed.ID, 99)
	requireCode(t, e, "changed_since_review")
	cancelled, e := f.s.Cancel(ctx, f.requester, renewed.ID, renewed.ReviewRevision)
	if e != nil || cancelled.Status != Cancelled || cancelled.Preview != nil {
		t.Fatalf("cancel=%+v %v", cancelled, e)
	}
}

func TestServicePreviewPrivacyAndPagination(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	f.input.Arguments = json.RawMessage(`{"password":"plain-secret-sentinel","other":"known-secret-sentinel CUSTOM-SECRET","a-key-known-secret-sentinel":"hide","small":"abc","huge":"` + strings.Repeat("x", 16380) + `known-secret-sentinel"}`)
	f.input.Secrets = []string{"known-secret-sentinel", "abc"}
	p := beginFixture(t, f)
	for _, a := range []authz.Actor{f.requester, f.reviewer} {
		d, e := f.s.GetRequest(ctx, a, p.Receipt.ID)
		if e != nil || d.Preview == nil {
			t.Fatalf("authorized preview=%v", e)
		}
		if len(*d.Preview) > 16<<10 || strings.Contains(*d.Preview, "plain-secret-sentinel") || strings.Contains(*d.Preview, "known-secret-sentinel") || strings.Contains(*d.Preview, "CUSTOM-SECRET") || strings.Contains(*d.Preview, "abc") {
			t.Fatal("preview leaked secret or exceeded bound")
		}
		if !d.PreviewTruncated || !d.PreviewRedacted {
			t.Fatal("missing warnings")
		}
	}
	for _, a := range []authz.Actor{f.admin, f.auditor} {
		d, e := f.s.GetRequest(ctx, a, p.Receipt.ID)
		if e != nil || d.Preview != nil {
			t.Fatalf("oversight preview=%+v %v", d, e)
		}
	}
	_, e := f.s.GetRequest(ctx, f.outsider, p.Receipt.ID)
	requireCode(t, e, "approval_not_found")
	_, e = f.s.GetRequest(ctx, f.outsider, uuid.New())
	requireCode(t, e, "approval_not_found")
	for _, a := range []authz.Actor{f.requester, f.reviewer} {
		view := "requested"
		if a.UserID == f.reviewer.UserID {
			view = "actionable"
		}
		rows, e := f.s.ListRequests(ctx, a, view, 0, 10)
		if e != nil || len(rows) != 1 || rows[0].Preview != nil {
			t.Fatalf("list privacy=%+v %v", rows, e)
		}
	}
	// Seed newer private metadata that the requester must skip before offset.
	for i := 0; i < 3; i++ {
		in := f.input
		in.Binding.RequesterID = f.outsider.UserID
		in.Arguments = json.RawMessage(fmt.Sprintf(`{"private":%d}`, i))
		if _, e = f.s.Begin(ctx, in); e != nil {
			t.Fatal(e)
		}
	}
	rows, e := f.s.ListRequests(ctx, f.requester, "requested", 0, 1)
	if e != nil || len(rows) != 1 || rows[0].ID != p.Receipt.ID {
		t.Fatalf("filtered pagination=%+v %v", rows, e)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE metadata::text LIKE '%secret-sentinel%' OR coalesce(before_state::text,'') LIKE '%secret-sentinel%' OR coalesce(after_state::text,'') LIKE '%secret-sentinel%'`); n != 0 {
		t.Fatal("audit payload leaked")
	}
	_, e = f.s.Decide(ctx, f.requester, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 1, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	requireCode(t, e, "approval_unavailable")
}

func TestServiceReviewerSeparationAndFallback(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	// Named account owner is excluded, so decision 52 automatically falls
	// back to a non-requester platform admin. Gateway ownership is irrelevant.
	in := f.rule.RuleInput
	in.Approvers = []Selector{{Kind: "user", UserID: &f.saOwner.UserID}}
	var e error
	f.rule, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	if e != nil {
		t.Fatal(e)
	}
	f.input.Binding.RequesterKind = "service_account"
	f.input.Binding.RequesterID = f.sa
	f.input.Binding.RequesterTeamID = &f.saTeam
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p := beginFixture(t, f)
	d, e := f.s.GetRequest(ctx, f.saOwner, p.Receipt.ID)
	if e != nil || d.Preview == nil || d.CanDecide || !d.CanCancel {
		t.Fatalf("account agent=%+v %v", d, e)
	}
	d, e = f.s.GetRequest(ctx, f.admin, p.Receipt.ID)
	if e != nil || !d.CanDecide || d.Preview == nil {
		t.Fatalf("admin fallback=%+v %v", d, e)
	}
	_, e = f.s.Decide(ctx, f.saOwner, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 1, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	requireCode(t, e, "approval_unavailable")
	_, e = f.s.Decide(ctx, f.admin, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 1, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	if e != nil {
		t.Fatal(e)
	}
	p = beginFixture(t, f)
	if e = f.s.Consume(ctx, p); e != nil {
		t.Fatal(e)
	}
	// Explicit opt-in now makes the live named owner eligible; admin oversight
	// ceases to confer preview when a primary reviewer is available.
	in.AllowServiceAccountAdmins = true
	f.rule, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	if e != nil {
		t.Fatal(e)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p = beginFixture(t, f)
	d, e = f.s.GetRequest(ctx, f.saOwner, p.Receipt.ID)
	if e != nil || !d.CanDecide {
		t.Fatalf("opt-in=%+v %v", d, e)
	}
	d, e = f.s.GetRequest(ctx, f.admin, p.Receipt.ID)
	if e != nil || d.Preview != nil || d.CanDecide {
		t.Fatalf("primary suppresses fallback=%+v %v", d, e)
	}
	// Exact SSO groups are re-evaluated, not inferred from a creator/operator.
	in.Approvers = []Selector{{Kind: "group", GroupName: ptrString("Reviewers")}}
	f.rule, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	if e != nil {
		t.Fatal(e)
	}
	execFixture(t, f.db, `UPDATE users SET groups='{Reviewers}' WHERE id=$1`, f.reviewer.UserID)
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p = beginFixture(t, f)
	d, e = f.s.GetRequest(ctx, f.reviewer, p.Receipt.ID)
	if e != nil || !d.CanDecide {
		t.Fatalf("SSO eligibility=%+v %v", d, e)
	}
}
func ptrString(s string) *string { return &s }

func TestServiceContextDeadlinesAndAuditableCleanup(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := approveFixture(t, f, beginFixture(t, f))
	old := f.input.Binding.Epoch
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.outsider.UserID)
	execFixture(t, f.db, `UPDATE users SET status='active' WHERE id=$1`, f.outsider.UserID)
	if e := f.s.CheckContext(ctx, old, time.Time{}); !errors.Is(e, ErrContextChanged) {
		t.Fatalf("change/revert guard=%v", e)
	}
	if e := f.s.Consume(ctx, p); !errors.Is(e, ErrContextChanged) {
		t.Fatalf("change/revert consume=%v", e)
	}
	if _, e := f.s.Begin(ctx, f.input); !errors.Is(e, ErrContextChanged) {
		t.Fatalf("stale initial epoch=%v", e)
	}
	d, e := f.s.GetRequest(ctx, f.requester, p.Receipt.ID)
	if e != nil || d.Preview != nil || d.Status != Cancelled || !d.Stale {
		t.Fatalf("stale detail=%+v %v", d, e)
	}
	if _, e = f.s.Renew(ctx, f.requester, p.Receipt.ID, d.ReviewRevision); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("renew stale=%v", e)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	f.input.CredentialExpiresAt = time.Now().Add(-time.Second)
	if _, e = f.s.Begin(ctx, f.input); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("expired credential Begin=%v", e)
	}
	f.input.CredentialExpiresAt = time.Now().Add(time.Hour)
	p = approveFixture(t, f, beginFixture(t, f))
	f.s.SetClock(func() time.Time { return f.input.CredentialExpiresAt })
	if e = f.s.CheckContext(ctx, p.Binding.Epoch, p.CredentialExpiresAt); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("expired credential guard=%v", e)
	}
	if e = f.s.Consume(ctx, p); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("expired credential consume=%v", e)
	}
	if e = f.s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Expired {
		t.Fatal("expiry cleanup did not transition")
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action='approval_request.expired' AND target_id=$1`, p.Receipt.ID.String()); n != 1 {
		t.Fatalf("per-receipt expiry audits=%d", n)
	}
	// Advance beyond independent preview and metadata retention periods.
	at := time.Now().Add(26 * time.Hour)
	f.s.SetClock(func() time.Time { return at })
	if e = f.s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests WHERE preview_cipher IS NOT NULL`); n != 0 {
		t.Fatal("terminal preview not cleared within 24h")
	}
	at = at.Add(91 * 24 * time.Hour)
	if e = f.s.Cleanup(ctx, 100); e != nil {
		t.Fatal(e)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests`); n != 0 {
		t.Fatal("metadata retained beyond 90d")
	}
}

func TestServiceAuditFailureRollsBack(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := approveFixture(t, f, beginFixture(t, f))
	execFixture(t, f.owner, `CREATE FUNCTION reject_approval_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'approval_request.%' THEN RAISE EXCEPTION 'audit rejection sentinel'; END IF; RETURN NEW; END $$`)
	execFixture(t, f.owner, `CREATE TRIGGER reject_approval_audit BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION reject_approval_audit()`)
	if e := f.s.Consume(ctx, p); !errors.Is(e, ErrUnavailable) || strings.Contains(e.Error(), "sentinel") {
		t.Fatalf("unsafe consume error=%v", e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Approved {
		t.Fatal("audit failure spent authorization")
	}
	f.input.Arguments = json.RawMessage(`{"other":1}`)
	if _, e := f.s.Begin(ctx, f.input); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("Begin audit failure=%v", e)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests`); n != 1 {
		t.Fatal("unaudited request committed")
	}
	execFixture(t, f.owner, `DROP TRIGGER reject_approval_audit ON audit_log`)
	if e := f.s.Consume(ctx, p); e != nil {
		t.Fatal(e)
	}
}

func TestServiceActualSuspensionVersusDecision(t *testing.T) {
	f := newServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := beginFixture(t, f)
	writer, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Rollback(context.Background())
	if _, e = writer.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, f.reviewer.UserID); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		_, e := f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: 1, ExpectedArgsDigest: p.Receipt.ArgsDigest})
		done <- e
	}()
	// The actual user writer holds the epoch until commit. There is no
	// authority-row lock acquisition after the service's shared fence.
	if e = writer.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	requireCode(t, <-done, "forbidden")
	if requestStatus(t, f, p.Receipt.ID) != Pending {
		t.Fatal("suspended decider changed request")
	}
}

func TestServiceRuleOwnershipTokensAndLegacyArguments(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	_, e := f.s.CreateRule(ctx, f.admin, f.team.String(), RuleInput{Name: "Admin bypass", TargetKind: "server", TargetID: f.server, Classes: []string{"read"}, Enabled: true})
	requireCode(t, e, "team_not_found")
	in := f.rule.RuleInput
	_, e = f.s.CreateRule(ctx, f.admin, "", in)
	requireCode(t, e, "rule_not_found")
	_, e = f.s.CreateRule(ctx, f.reviewer, f.team.String(), in)
	requireCode(t, e, "approval_unavailable")
	token := f.admin
	token.Kind = authz.KindAutomationToken
	_, e = f.s.ListRules(ctx, token, "", 0, 10)
	requireCode(t, e, "forbidden")
	_, e = f.s.ListRequests(ctx, token, "requested", 0, 10)
	requireCode(t, e, "forbidden")
	_, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, 99, in)
	requireCode(t, e, "precondition_failed")
	in.TargetKind = "gateway"
	in.TargetID = f.gateway
	_, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	requireCode(t, e, "rule_not_found")
	if e = f.s.DeleteRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision); e != nil {
		t.Fatal(e)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	f.input.Arguments = json.RawMessage(`{"duplicate":1,"duplicate":2}`)
	p, e := f.s.Begin(ctx, f.input)
	if e != nil || p.Required {
		t.Fatalf("legacy ungoverned arguments changed: %+v %v", p, e)
	}
	if e = f.s.Consume(ctx, p); e != nil {
		t.Fatal(e)
	}
	f.input.CredentialExpiresAt = time.Now().Add(-time.Second)
	if _, e = f.s.Begin(ctx, f.input); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("ungoverned deadline=%v", e)
	}
}

// Assert genuine runtime authentication instead of SET ROLE on an owner.
func TestServiceRuntimeIsNotOwner(t *testing.T) {
	f := newServiceFixture(t)
	var current, owner string
	if e := f.db.QueryRow(context.Background(), `SELECT current_user,pg_get_userbyid(datdba) FROM pg_database WHERE datname=current_database()`).Scan(&current, &owner); e != nil {
		t.Fatal(e)
	}
	if current == owner {
		t.Fatal("integration test did not use a genuine split runtime role")
	}
}
