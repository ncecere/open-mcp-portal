package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestServiceCancelBoundRequiresExactMCPBinding(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := beginFixture(t, f)
	mutations := []func(*BeginInput){
		func(in *BeginInput) { in.Binding.RequesterID = f.outsider.UserID },
		func(in *BeginInput) { in.Binding.RequesterKind = "service_account" },
		func(in *BeginInput) { in.Binding.RequesterTeamID = &f.saTeam },
		func(in *BeginInput) { in.Binding.GatewayID = uuid.New() },
		func(in *BeginInput) { in.Binding.ServerID = uuid.New() },
		func(in *BeginInput) { in.Binding.CapabilityID = uuid.New() },
		func(in *BeginInput) { in.Binding.ExposedName = "different" },
		func(in *BeginInput) { in.Binding.ToolClass = nil },
		func(in *BeginInput) { in.Binding.CapabilityFingerprint = "different" },
		func(in *BeginInput) { in.Binding.ServerOrigin = "https://elsewhere.test" },
		func(in *BeginInput) { in.Arguments = json.RawMessage(`{"id":9007199254740992}`) },
	}
	for i, mutate := range mutations {
		wrong := f.input
		mutate(&wrong)
		e := f.s.CancelBound(ctx, wrong, p.Receipt.ID, p.Receipt.ReviewRevision)
		requireCode(t, e, "approval_not_found")
		if requestStatus(t, f, p.Receipt.ID) != Pending {
			t.Fatalf("mismatch %d cancelled request", i)
		}
	}
	if e := f.s.CancelBound(ctx, f.input, p.Receipt.ID, 99); e == nil {
		t.Fatal("stale review cancelled request")
	} else {
		requireCode(t, e, "changed_since_review")
	}
	if e := f.s.CancelBound(ctx, f.input, p.Receipt.ID, p.Receipt.ReviewRevision); e != nil {
		t.Fatal(e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Cancelled {
		t.Fatal("verified decline did not cancel")
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests`); n != 1 {
		t.Fatal("decline created a new pending request")
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action='approval_request.cancelled' AND actor_kind='system' AND actor_user_id IS NULL`); n != 1 {
		t.Fatalf("MCP cancellation system audits=%d", n)
	}
	if e := f.s.CancelBound(ctx, f.input, p.Receipt.ID, p.Receipt.ReviewRevision+1); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("terminal cancellation=%v", e)
	}
	// The same path supports an account without impersonating its creator.
	f.input.Binding.RequesterKind = "service_account"
	f.input.Binding.RequesterID = f.sa
	f.input.Binding.RequesterTeamID = &f.saTeam
	p = beginFixture(t, f)
	if e := f.s.CancelBound(ctx, f.input, p.Receipt.ID, p.Receipt.ReviewRevision); e != nil {
		t.Fatal(e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Cancelled {
		t.Fatal("service account decline failed")
	}
}
