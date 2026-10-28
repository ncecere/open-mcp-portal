package approvals

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestUnrestrictedReadsDoNotFenceConcurrentAuthorityWriters(t *testing.T) {
	f := newServiceFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.s.DeleteRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision); err != nil {
		t.Fatal(err)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	tx, err := f.db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Existing refresh/authentication paths can hold ROW SHARE/EXCLUSIVE locks
	// even without changing semantic authority. Non-spending checks must not
	// attempt the installation-wide exclusive writer fence.
	if _, err = tx.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, f.requester.UserID); err != nil {
		t.Fatal(err)
	}
	plan, err := f.s.Begin(ctx, f.input)
	if err != nil || plan.Required {
		t.Fatalf("unrestricted call serialized behind writer: required=%v err=%v", plan.Required, err)
	}
	if err = f.s.CheckContext(ctx, plan.Binding.Epoch, plan.CredentialExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err = f.s.Consume(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, f.requester.UserID); err != nil {
		t.Fatal(err)
	}
	// Uncommitted authority is not current. This snapshot linearizes before
	// that writer commits; the next transport after commit must refuse.
	if err = f.s.CheckContext(ctx, plan.Binding.Epoch, plan.CredentialExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err = f.s.CheckContext(ctx, plan.Binding.Epoch, plan.CredentialExpiresAt); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("committed revocation did not invalidate next transport: %v", err)
	}
}

func TestUnrestrictedSnapshotCannotBlessNewRule(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	if err := f.s.DeleteRule(ctx, f.reviewer, f.team.String(), f.rule.ID, f.rule.Revision); err != nil {
		t.Fatal(err)
	}
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	plan, err := f.s.Begin(ctx, f.input)
	if err != nil || plan.Required {
		t.Fatal(err)
	}
	if _, err = f.s.CreateRule(ctx, f.reviewer, f.team.String(), f.rule.RuleInput); err != nil {
		t.Fatal(err)
	}
	if err = f.s.CheckContext(ctx, plan.Binding.Epoch, plan.CredentialExpiresAt); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("new rule bypassed by previous unrestricted permit: %v", err)
	}
	if _, err = f.s.Begin(ctx, f.input); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("new rule blessed stale authentication: %v", err)
	}
}
