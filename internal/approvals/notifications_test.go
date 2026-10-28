package approvals

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func noticeAudience(t *testing.T, f *serviceFixture, id uuid.UUID, requested bool, want ...uuid.UUID) {
	t.Helper()
	got, err := f.s.NotificationRecipients(context.Background(), f.q, id, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("audience=%v want=%v", got, want)
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("audience=%v want=%v", got, want)
		}
	}
}

// A synthetic current-epoch receipt isolates live audience selection from the
// independent coarse-epoch stale guard. Real old receipts remain stale after an
// authority edit; production never rebases their epoch.
func rebaseNoticeFixture(t *testing.T, f *serviceFixture, id uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Owner-only test instrumentation, atomically restored; runtime cannot
	// disable this immutable-binding guard. Never used by application code.
	for _, query := range []string{
		`ALTER TABLE approval_requests DISABLE TRIGGER approval_request_lifecycle`,
		`UPDATE approval_requests SET context_epoch=omp_private.omp_current_approval_context() WHERE id='` + id.String() + `'`,
		`ALTER TABLE approval_requests ENABLE TRIGGER approval_request_lifecycle`,
	} {
		if _, err := tx.Exec(ctx, query); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNotificationRecipientsLiveGroupsAndFallback(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	group := "sensitive-reviewers"
	input := f.rule.RuleInput
	input.Approvers = []Selector{{Kind: "group", GroupName: &group}}
	_, err := f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, input)
	if err != nil {
		t.Fatal(err)
	}
	execFixture(t, f.db, `UPDATE users SET groups=ARRAY[$1]::text[] WHERE id=ANY($2::uuid[])`, group, []uuid.UUID{f.reviewer.UserID, f.requester.UserID})
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p := beginFixture(t, f)
	noticeAudience(t, f, p.Receipt.ID, true, f.reviewer.UserID) // never the human requester
	noticeAudience(t, f, p.Receipt.ID, false)

	// Move the group AFTER the request: old audience is never persisted.
	execFixture(t, f.db, `UPDATE users SET groups='{}' WHERE id=$1`, f.reviewer.UserID)
	execFixture(t, f.db, `UPDATE users SET groups=ARRAY[$1]::text[] WHERE id=$2`, group, f.outsider.UserID)
	noticeAudience(t, f, p.Receipt.ID, true) // stale epoch suppresses all hints
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, true, f.outsider.UserID)
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.outsider.UserID)
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, true, f.admin.UserID) // eligible primary empty: exact service fallback
	f.s.SetClock(func() time.Time { return p.Receipt.ExpiresAt })
	noticeAudience(t, f, p.Receipt.ID, true)
}

func TestNotificationRecipientsServiceAccountSeparationAndDecisionOwners(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	// Owning-team admin, editor, suspended owner; none gains implicit review.
	execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'admin'),($1,$3,'editor')`, f.saTeam, f.outsider.UserID, f.auditor.UserID)
	f.input.Binding.RequesterKind, f.input.Binding.RequesterID = "service_account", f.sa
	f.input.Binding.RequesterTeamID = &f.saTeam
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p := beginFixture(t, f)
	noticeAudience(t, f, p.Receipt.ID, true, f.reviewer.UserID)
	// Make the primary reviewer an SA owner. Its live exclusion must leave
	// only the non-requester platform-admin fallback, not the SA's owner.
	execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'owner')`, f.saTeam, f.reviewer.UserID)
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, true, f.admin.UserID)
	// The same exclusion applies to fallback admins who own the requesting SA.
	execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'admin')`, f.saTeam, f.admin.UserID)
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, true)

	// A new receipt under an explicit separation-of-duties exception restores
	// the primary reviewer, and only CURRENT owning-team owners/admins receive
	// decisions. Platform/auditor access alone does not create an audience.
	in := f.rule.RuleInput
	in.AllowServiceAccountAdmins = true
	_, err := f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	if err != nil {
		t.Fatal(err)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p = beginFixture(t, f)
	noticeAudience(t, f, p.Receipt.ID, true, f.reviewer.UserID)
	_, err = f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "deny", ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	if err != nil {
		t.Fatal(err)
	}
	noticeAudience(t, f, p.Receipt.ID, true)
	noticeAudience(t, f, p.Receipt.ID, false, f.saOwner.UserID, f.reviewer.UserID, f.admin.UserID, f.outsider.UserID)
	// Changes since emission cannot preserve a removed/suspended owner's copy.
	execFixture(t, f.db, `DELETE FROM team_members WHERE team_id=$1 AND user_id=$2`, f.saTeam, f.admin.UserID)
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.saOwner.UserID)
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, false, f.reviewer.UserID, f.outsider.UserID)
	execFixture(t, f.db, `UPDATE teams SET status='archived' WHERE id=$1`, f.saTeam)
	rebaseNoticeFixture(t, f, p.Receipt.ID)
	noticeAudience(t, f, p.Receipt.ID, false)
}

func TestNotificationDecisionOnlyActiveUserRequester(t *testing.T) {
	for _, decision := range []string{"approve", "deny"} {
		t.Run(decision, func(t *testing.T) {
			f := newServiceFixture(t)
			p := beginFixture(t, f)
			_, err := f.s.Decide(context.Background(), f.reviewer, p.Receipt.ID, Decision{Decision: decision, ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
			if err != nil {
				t.Fatal(err)
			}
			noticeAudience(t, f, p.Receipt.ID, false, f.requester.UserID)
			noticeAudience(t, f, uuid.New(), false)
			execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.requester.UserID)
			rebaseNoticeFixture(t, f, p.Receipt.ID)
			noticeAudience(t, f, p.Receipt.ID, false)
		})
	}
}
