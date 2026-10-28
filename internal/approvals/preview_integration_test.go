package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func TestServiceCorruptPreviewCannotAuthorize(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := beginFixture(t, f)
	execFixture(t, f.db, `UPDATE approval_requests SET preview_cipher='broken'::bytea WHERE id=$1`, p.Receipt.ID)
	if _, e := f.s.GetRequest(ctx, f.reviewer, p.Receipt.ID); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("corrupt preview detail=%v", e)
	}
	if _, e := f.s.Decide(ctx, f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest}); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("corrupt preview approved=%v", e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Pending {
		t.Fatal("corrupt preview transitioned")
	}
	f.input.Arguments = json.RawMessage(`{"second":true}`)
	p = approveFixture(t, f, beginFixture(t, f))
	execFixture(t, f.db, `UPDATE approval_requests SET preview_cipher='broken'::bytea WHERE id=$1`, p.Receipt.ID)
	if e := f.s.Consume(ctx, p); !errors.Is(e, ErrUnavailable) {
		t.Fatalf("corrupt approved preview consumed=%v", e)
	}
	if requestStatus(t, f, p.Receipt.ID) != Approved {
		t.Fatal("corrupt preview spent authorization")
	}
}
