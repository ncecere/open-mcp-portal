package approvals

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func setFixtureRuleEnabled(t *testing.T, f *serviceFixture, enabled bool) {
	t.Helper()
	rule, err := f.s.ReplaceRule(context.Background(), f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision,
		RuleInput{Name: "Destructive calls", TargetKind: "server", TargetID: f.server, Classes: []string{"destructive"}, Enabled: enabled})
	if err != nil {
		t.Fatal(err)
	}
	f.rule = rule
	f.input.Binding.Epoch = mustEpoch(t, f.s)
}

func assertNoLifecycleApprovalWrites(t *testing.T, f *serviceFixture) {
	t.Helper()
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests`); n != 0 {
		t.Fatal("non-spending lifecycle check created an approval receipt", n)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action LIKE 'approval_request.%'`); n != 0 {
		t.Fatal("non-spending lifecycle check emitted a request audit", n)
	}
}

func TestCheckUngovernedRefusesRulesWithoutCreatingReceipts(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	if err := f.s.CheckUngoverned(ctx, f.input.Binding, f.input.CredentialExpiresAt); !errors.Is(err, ErrContextChanged) {
		t.Fatal("existing rule was treated as task permission", err)
	}
	assertNoLifecycleApprovalWrites(t, f)
	setFixtureRuleEnabled(t, f, false)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for range 20 {
		wg.Go(func() { errs <- f.s.CheckUngoverned(ctx, f.input.Binding, f.input.CredentialExpiresAt) })
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("unrestricted read-only check failed", err)
		}
	}
	assertNoLifecycleApprovalWrites(t, f)
	before := f.input.Binding
	setFixtureRuleEnabled(t, f, true)
	if err := f.s.CheckUngoverned(ctx, before, f.input.CredentialExpiresAt); !errors.Is(err, ErrContextChanged) {
		t.Fatal("stale per-exchange epoch accepted", err)
	}
	if err := f.s.CheckUngoverned(ctx, f.input.Binding, f.input.CredentialExpiresAt); !errors.Is(err, ErrContextChanged) {
		t.Fatal("newly applicable rule created or authorized a lifecycle approval", err)
	}
	assertNoLifecycleApprovalWrites(t, f)
}

func TestCheckUngovernedExpiryCancellationAndRequesterFailClosed(t *testing.T) {
	f := newServiceFixture(t)
	setFixtureRuleEnabled(t, f, false)
	ctx := context.Background()
	if err := f.s.CheckUngoverned(ctx, f.input.Binding, time.Now().Add(-time.Second)); !errors.Is(err, ErrUnavailable) {
		t.Fatal("expired current request credential accepted", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.s.CheckUngoverned(cancelled, f.input.Binding, f.input.CredentialExpiresAt); err == nil {
		t.Fatal("cancelled policy check accepted")
	}
	execFixture(t, f.owner, `UPDATE users SET status='suspended' WHERE id=$1`, f.requester.UserID)
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	if err := f.s.CheckUngoverned(ctx, f.input.Binding, f.input.CredentialExpiresAt); !errors.Is(err, ErrUnavailable) {
		t.Fatal("non-live requester accepted", err)
	}
	assertNoLifecycleApprovalWrites(t, f)
}
