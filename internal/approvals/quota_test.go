package approvals

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
)

func TestServiceOldEpochRequestsDoNotTrapRequesterQuota(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	approved := approveFixture(t, f, beginFixture(t, f))
	for i := 0; i < 20; i++ {
		f.input.Arguments = json.RawMessage(fmt.Sprintf(`{"pending":%d}`, i))
		beginFixture(t, f)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests WHERE status='pending'`); n != 20 {
		t.Fatalf("pending=%d", n)
	}
	// Any global edit invalidates ALL old bindings. The current digest cannot
	// find these rows, but they still must be cancelled/audited before quota.
	execFixture(t, f.db, `UPDATE users SET groups='{changed}' WHERE id=$1`, f.outsider.UserID)
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	fresh := beginFixture(t, f)
	if fresh.Receipt.Status != Pending {
		t.Fatal("fresh current-context request not created")
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests WHERE status='pending'`); n != 1 {
		t.Fatalf("stale quota rows left pending: %d", n)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM approval_requests WHERE status='cancelled'`); n != 21 {
		t.Fatalf("stale cancellations=%d", n)
	}
	if n := countFixture(t, f, `SELECT count(*) FROM audit_log WHERE action='approval_request.cancelled' AND actor_kind='system'`); n != 21 {
		t.Fatalf("per-receipt stale audits=%d", n)
	}
	detail, e := f.s.GetRequest(ctx, f.requester, approved.Receipt.ID)
	if e != nil || detail.Status != Cancelled || detail.Preview != nil || detail.CanRenew {
		t.Fatalf("stale terminal privacy=%+v %v", detail, e)
	}
}
