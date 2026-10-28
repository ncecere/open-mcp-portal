package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestApprovalRuleCRUDAndSelectors(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		q := dbgen.New(db)
		input := dbgen.InsertApprovalRuleParams{ID: uuid.New(), Name: "Rule", TargetKind: "server", TargetID: uuid.New(), Classes: []string{"destructive"}, Enabled: true, PendingMinutes: 1440, ValidMinutes: 15, CreatedBy: uuid.New()}
		r, err := q.InsertApprovalRule(ctx, input)
		if err != nil {
			t.Fatal(err)
		}
		for _, sql := range []string{
			`UPDATE approval_rules SET pending_minutes=4`, `UPDATE approval_rules SET pending_minutes=1441`,
			`UPDATE approval_rules SET valid_minutes=0`, `UPDATE approval_rules SET valid_minutes=61`,
			`UPDATE approval_rules SET classes='{invalid}'`, `UPDATE approval_rules SET classes=ARRAY[NULL]::text[]`,
		} {
			roleDenied(t, db, sql, "23514")
		}
		rows, err := q.ListMatchingApprovalRules(ctx, dbgen.ListMatchingApprovalRulesParams{ServerID: r.TargetID, GatewayID: uuid.New()})
		if err != nil || len(rows) != 1 {
			t.Fatalf("matching rules=%+v %v", rows, err)
		}
		all, err := q.ListApprovalRules(ctx, dbgen.ListApprovalRulesParams{PageLimit: 100})
		if err != nil || len(all) != 1 {
			t.Fatalf("list rules=%+v %v", all, err)
		}
		approver := dbgen.InsertApprovalRuleApproverParams{RuleID: r.ID, Kind: "group", GroupName: ptr("reviewers")}
		if err := q.InsertApprovalRuleApprover(ctx, approver); err != nil {
			t.Fatal(err)
		}
		selectors, err := q.ListApprovalRuleApprovers(ctx, r.ID)
		if err != nil || len(selectors) != 1 || *selectors[0].GroupName != "reviewers" {
			t.Fatalf("selectors=%+v %v", selectors, err)
		}
		update := dbgen.UpdateApprovalRuleParams{ID: r.ID, ExpectedRevision: r.Revision, Name: r.Name, Classes: r.Classes, Enabled: false, PendingMinutes: r.PendingMinutes, ValidMinutes: r.ValidMinutes}
		changed, err := q.UpdateApprovalRule(ctx, update)
		if err != nil || changed.Revision != 2 {
			t.Fatalf("update=%+v %v", changed, err)
		}
		if _, err := q.UpdateApprovalRule(ctx, update); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("stale revision updated: %v", err)
		}
		if n, err := q.DeleteApprovalRule(ctx, dbgen.DeleteApprovalRuleParams{ID: r.ID, Revision: 1}); err != nil || n != 0 {
			t.Fatalf("stale delete=%d %v", n, err)
		}
		if err := q.DeleteApprovalRuleApprovers(ctx, r.ID); err != nil {
			t.Fatal(err)
		}
		if err := q.InsertApprovalRuleApprover(ctx, approver); err != nil {
			t.Fatal(err)
		}
		if n, err := q.DeleteApprovalRule(ctx, dbgen.DeleteApprovalRuleParams{ID: r.ID, Revision: 2}); err != nil || n != 1 {
			t.Fatalf("delete=%d %v", n, err)
		}
		if selectors, err := q.ListApprovalRuleApprovers(ctx, r.ID); err != nil || len(selectors) != 0 {
			t.Fatal("selectors survived rule deletion", err)
		}
		if _, err := q.GetApprovalRule(ctx, r.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal("deleted rule remains", err)
		}
	})
}

func ptr(s string) *string { return &s }

func TestApprovalRequestConditionalDecisionsAndExpiry(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		q := dbgen.New(db)
		now := time.Now().UTC().Truncate(time.Microsecond)
		pending := approvalPending(t, db, now)
		for _, sql := range []string{
			`UPDATE approval_requests SET args_digest=repeat('b',64)`,
			`UPDATE approval_requests SET expires_at=expires_at+interval '1 minute'`,
			`UPDATE approval_requests SET review_revision=review_revision+1`,
			`UPDATE approval_requests SET status='used',review_revision=review_revision+1,terminal_at=now(),used_at=now()`,
		} {
			roleDenied(t, db, sql, "P0001")
		}
		deny := dbgen.DenyApprovalRequestParams{ID: pending.ID, BindingDigest: strings.Repeat("f", 64), ExpectedReviewRevision: 1, DecidedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}, AtTime: &now}
		if _, err := q.DenyApprovalRequest(ctx, deny); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("wrong digest denied: %v", err)
		}
		deny.BindingDigest = pending.BindingDigest
		deny.ExpectedReviewRevision = 2
		if _, err := q.DenyApprovalRequest(ctx, deny); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("stale review denied: %v", err)
		}
		deny.ExpectedReviewRevision = 1
		denied, err := q.DenyApprovalRequest(ctx, deny)
		if err != nil || denied.Status != "denied" {
			t.Fatalf("denied=%+v %v", denied, err)
		}
		if _, err := q.DenyApprovalRequest(ctx, deny); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("denied twice: %v", err)
		}
		if _, err := q.ApproveApprovalRequest(ctx, dbgen.ApproveApprovalRequestParams{ID: denied.ID, BindingDigest: denied.BindingDigest, ExpectedReviewRevision: 2, AtTime: &now, ValidUntil: now.Add(time.Minute), DecidedBy: deny.DecidedBy}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("denial resurrected: %v", err)
		}
		receipt, err := q.FindApprovalRequestBinding(ctx, pending.BindingDigest)
		if err != nil || receipt.ID != pending.ID || receipt.Status != "denied" {
			t.Fatalf("lost denied binding: %+v %v", receipt, err)
		}
		roleDenied(t, db, `UPDATE approval_requests SET status='pending',terminal_at=NULL,review_revision=review_revision+1`, "P0001")
		active := approvalApproved(t, db)
		deadline := *active.ValidUntil
		if _, err := q.UseApprovalRequest(ctx, approvalUseParams(active, &deadline)); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("used at exact validity deadline: %v", err)
		}
		if n, err := q.ExpireApprovalRequests(ctx, dbgen.ExpireApprovalRequestsParams{AtTime: &deadline, BatchSize: 100}); err != nil || n != 1 {
			t.Fatalf("validity expire=%d %v", n, err)
		}
		expired := approvalPending(t, db, now.Add(-25*time.Hour))
		if _, err := q.ApproveApprovalRequest(ctx, dbgen.ApproveApprovalRequestParams{ID: expired.ID, BindingDigest: expired.BindingDigest, ExpectedReviewRevision: 1, AtTime: &now, ValidUntil: now.Add(time.Minute), DecidedBy: deny.DecidedBy}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expired request approved: %v", err)
		}
		detail, err := q.GetApprovalRequest(ctx, expired.ID)
		if err != nil || detail.PreviewCipher != nil {
			t.Fatalf("elapsed pending preview exposed: %v", err)
		}
		if receipt, err := q.ExpireApprovalRequest(ctx, dbgen.ExpireApprovalRequestParams{ID: expired.ID, AtTime: &now}); err != nil || receipt.Status != "expired" {
			t.Fatalf("single receipt expiry: %+v %v", receipt, err)
		}
		if _, err := q.ExpireApprovalRequest(ctx, dbgen.ExpireApprovalRequestParams{ID: expired.ID, AtTime: &now}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expired twice: %v", err)
		}
		fresh := approvalPending(t, db, now)
		if _, err := q.ExpireApprovalRequest(ctx, dbgen.ExpireApprovalRequestParams{ID: fresh.ID, AtTime: &now}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("fresh receipt expired: %v", err)
		}
		if _, err := q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: fresh.ID, ExpectedReviewRevision: 2, AtTime: &now}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("stale cancel succeeded: %v", err)
		}
		if _, err := q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: fresh.ID, ExpectedReviewRevision: 1, AtTime: &now}); err != nil {
			t.Fatal(err)
		}
	})
}

func TestApprovalStalePreviewAndTokenDeletion(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		q := dbgen.New(db)
		seedApprovalAuthority(t, db)
		pending := approvalPending(t, db, time.Now().UTC())
		detail, err := q.GetApprovalRequest(ctx, pending.ID)
		if err != nil || len(detail.PreviewCipher) == 0 {
			t.Fatal("fresh preview missing", err)
		}
		epoch := approvalEpoch(t, db)
		roleExec(t, db, `DELETE FROM oauth_tokens WHERE kind='access'`)
		if approvalEpoch(t, db) <= epoch {
			t.Fatal("standalone access-token revoke did not advance epoch")
		}
		detail, err = q.GetApprovalRequest(ctx, pending.ID)
		if err != nil || detail.PreviewCipher != nil {
			t.Fatal("revocation-stale preview exposed", err)
		}
		pending = approvalPending(t, db, time.Now().UTC())
		roleExec(t, db, `UPDATE capture_settings SET patterns='["new-sensitive-pattern"]'`)
		detail, err = q.GetApprovalRequest(ctx, pending.ID)
		if err != nil || detail.PreviewCipher != nil {
			t.Fatal("old-redaction-policy preview exposed", err)
		}
		now := time.Now().UTC()
		if _, err := q.ApproveApprovalRequest(ctx, dbgen.ApproveApprovalRequestParams{ID: pending.ID, BindingDigest: pending.BindingDigest, ExpectedReviewRevision: 1, AtTime: &now, ValidUntil: now.Add(time.Minute), DecidedBy: uuid.NullUUID{UUID: uuid.New(), Valid: true}}); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("stale epoch approved: %v", err)
		}
	})
}

func TestApprovalMetadataRetentionUTC(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		terminal := time.Date(2026, time.March, 7, 12, 0, 0, 0, time.UTC)
		pending := approvalPending(t, db, terminal.Add(-time.Hour))
		q := dbgen.New(db)
		if _, err := q.CancelApprovalRequest(ctx, dbgen.CancelApprovalRequestParams{ID: pending.ID, ExpectedReviewRevision: 1, AtTime: &terminal}); err != nil {
			t.Fatal(err)
		}
		tx, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		roleExec(t, tx, `SET LOCAL TIME ZONE 'America/New_York'`)
		q = dbgen.New(tx)
		before := terminal.Add(90*24*time.Hour - 30*time.Minute)
		if n, err := q.PurgeApprovalRequestMetadata(ctx, dbgen.PurgeApprovalRequestMetadataParams{AtTime: before, BatchSize: 100}); err != nil || n != 0 {
			t.Fatalf("DST prematurely purged metadata: %d %v", n, err)
		}
		after := terminal.Add(90*24*time.Hour + 30*time.Minute)
		if n, err := q.PurgeApprovalRequestMetadata(ctx, dbgen.PurgeApprovalRequestMetadataParams{AtTime: after, BatchSize: 100}); err != nil || n != 1 {
			t.Fatalf("UTC retention boundary: %d %v", n, err)
		}
	})
}

func TestApprovalLockHelperPrivileges(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	outsider, _ := auxiliaryRole(t, owner, "approval_outsider_"+role)
	roleDenied(t, outsider, `SELECT omp_private.omp_lock_approval_context(false)`, "42501")
	roleDenied(t, runtime, `SELECT omp_private.omp_lock_approval_context(NULL)`, "22023")
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_proc p WHERE p.oid='omp_private.omp_lock_approval_context(boolean)'::regprocedure AND p.prosecdef AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='omp_private.approval_context'::regclass) AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']`); n != 1 {
		t.Fatal("lock helper is not fixed-path schema-owner definer")
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_proc p,LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE p.proname IN ('omp_lock_approval_context','approval_authority_changed') AND a.grantee=0 AND a.privilege_type='EXECUTE'`); n != 0 {
		t.Fatal("PUBLIC can execute approval definers")
	}
}
