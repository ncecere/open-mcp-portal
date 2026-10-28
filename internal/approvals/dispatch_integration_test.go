package approvals

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestServiceFullConsumeBindingAndLiveReviewer(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := approveFixture(t, f, beginFixture(t, f))
	mutations := []struct {
		name   string
		change func(*Plan)
	}{
		{"requesterKind", func(p *Plan) { p.Binding.RequesterKind = "service_account" }},
		{"requester", func(p *Plan) { p.Binding.RequesterID = uuid.New() }},
		{"requesterTeam", func(p *Plan) { id := uuid.New(); p.Binding.RequesterTeamID = &id }},
		{"gateway", func(p *Plan) { p.Binding.GatewayID = uuid.New() }},
		{"server", func(p *Plan) { p.Binding.ServerID = uuid.New() }},
		{"capability", func(p *Plan) { p.Binding.CapabilityID = uuid.New() }},
		{"name", func(p *Plan) { p.Binding.ExposedName = "different" }},
		{"class", func(p *Plan) { v := "read"; p.Binding.ToolClass = &v }},
		{"fingerprint", func(p *Plan) { p.Binding.CapabilityFingerprint = "different" }},
		{"origin", func(p *Plan) { p.Binding.ServerOrigin = "https://elsewhere.test" }},
		{"argumentDigest", func(p *Plan) { p.Receipt.ArgsDigest = "different" }},
		{"bindingDigest", func(p *Plan) { p.BindingDigest = "different" }},
		{"rule", func(p *Plan) { p.Receipt.RuleID = uuid.New() }},
		{"ruleRevision", func(p *Plan) { p.Receipt.RuleRevision++ }},
		{"reviewRevision", func(p *Plan) { p.Receipt.ReviewRevision++ }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			wrong := p
			m.change(&wrong)
			if e := f.s.Consume(ctx, wrong); !errors.Is(e, ErrUnavailable) {
				t.Fatalf("tampered plan consumed: %v", e)
			}
			if requestStatus(t, f, p.Receipt.ID) != Approved {
				t.Fatal("tampered call spent approval")
			}
		})
	}
	// Real approver revocation changes the original epoch; changing it back
	// cannot recover the old dispatch authorization.
	execFixture(t, f.db, `DELETE FROM team_members WHERE team_id=$1 AND user_id=$2`, f.team, f.reviewer.UserID)
	if e := f.s.Consume(ctx, p); !errors.Is(e, ErrContextChanged) {
		t.Fatalf("revoked decider consumed: %v", e)
	}
	execFixture(t, f.db, `INSERT INTO team_members(team_id,user_id,role) VALUES ($1,$2,'owner')`, f.team, f.reviewer.UserID)
	if e := f.s.Consume(ctx, p); !errors.Is(e, ErrContextChanged) {
		t.Fatalf("restored decider resurrected approval: %v", e)
	}
}

func TestServiceNoEligibleReviewersRefusesCreation(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	// The only primary is the human requester, who is always excluded. The
	// only platform admin is made inactive, so decision 52 cannot find a human.
	in := f.rule.RuleInput
	in.Approvers = []Selector{{Kind: "user", UserID: &f.requester.UserID}}
	var e error
	f.rule, e = f.s.ReplaceRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision, in)
	if e != nil {
		t.Fatal(e)
	}
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.admin.UserID)
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	if _, e = f.s.Begin(ctx, f.input); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("reviewer-free request created: %v", e)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests`); n != 0 {
		t.Fatal("unreviewable queue entry created")
	}
}

func TestServiceDeadlineRecheckedAfterRequesterLock(t *testing.T) {
	f := newServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	p := approveFixture(t, f, beginFixture(t, f))
	// This transaction owns only the new requester advisory lock, not an
	// authority table/row. It forces Consume to wait after its initial guard.
	holder, e := f.db.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer holder.Rollback(context.Background())
	if e = f.q.WithTx(holder).LockApprovalRequester(ctx, dbgen.LockApprovalRequesterParams{RequesterKind: f.input.Binding.RequesterKind, RequesterID: f.input.Binding.RequesterID}); e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	p.CredentialExpiresAt = now.Add(time.Second)
	var ticks atomicClock
	ticks.Store(now)
	f.s.SetClock(ticks.Load)
	done := make(chan error, 1)
	go func() { done <- f.s.Consume(ctx, p) }()
	// Observe a real blocked advisory-lock query before moving the clock.
	waitForApprovalLock(t, f, "%approval-requester:%")
	ticks.Store(p.CredentialExpiresAt)
	if e = holder.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if e = <-done; !errors.Is(e, ErrUnavailable) {
		t.Fatalf("credential expired while waiting but consumed: %v", e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Approved {
		t.Fatal("expired credential spent authorization")
	}
}
