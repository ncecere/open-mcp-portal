package approvals

import (
	"context"
	"errors"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestEmailOnlyLoginInvalidatesApprovalAndCannotRevert(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	plan := approveFixture(t, f, beginFixture(t, f))
	u, err := f.q.GetUser(ctx, f.requester.UserID)
	if err != nil {
		t.Fatal(err)
	}
	login := dbgen.UpsertLoginUserParams{OIDCIssuer: u.OIDCIssuer, OIDCSubject: u.OIDCSubject, Email: u.Email, DisplayName: u.DisplayName, Claims: u.Claims, Groups: u.Groups}
	originalEpoch := mustEpoch(t, f.s)
	// Real login UPSERT changes timestamps/claims/display without changing
	// authorization identity: it must not spuriously invalidate a receipt.
	login.DisplayName = "A new display name"
	if _, err = f.q.UpsertLoginUser(ctx, login); err != nil {
		t.Fatal(err)
	}
	if got := mustEpoch(t, f.s); got != originalEpoch {
		t.Fatalf("unchanged email login advanced epoch: %d != %d", got, originalEpoch)
	}
	login.Email = "new-upstream-account@test.invalid"
	if _, err = f.q.UpsertLoginUser(ctx, login); err != nil {
		t.Fatal(err)
	}
	changed := mustEpoch(t, f.s)
	if changed <= originalEpoch {
		t.Fatal("email-only login did not invalidate approval context")
	}
	if err = f.s.Consume(ctx, plan); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("old approval accepted after email change: %v", err)
	}
	login.Email = u.Email
	if _, err = f.q.UpsertLoginUser(ctx, login); err != nil {
		t.Fatal(err)
	}
	if got := mustEpoch(t, f.s); got <= changed {
		t.Fatal("email revert resurrected old authority")
	}
	if err = f.s.Consume(ctx, plan); !errors.Is(err, ErrContextChanged) {
		t.Fatalf("old approval accepted after email revert: %v", err)
	}
}
