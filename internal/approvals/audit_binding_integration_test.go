package approvals

import (
	"context"
	"testing"
)

func TestApprovalAuditRetainsKeyedBindingNotArguments(t *testing.T) {
	f := newServiceFixture(t)
	pending := beginFixture(t, f)
	plan := approveFixture(t, f, pending)
	if err := f.s.Consume(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := f.db.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE target_type='approval_request' AND target_id=$1
 AND metadata->>'argsDigest'=$2 AND metadata->>'bindingDigest'=$3
 AND metadata->>'capabilityFingerprint'=$4
 AND NOT (metadata ? 'arguments' OR metadata ? 'preview' OR metadata ? 'note')`, plan.Receipt.ID.String(), plan.Receipt.ArgsDigest, plan.BindingDigest, plan.Binding.CapabilityFingerprint).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("requested/approved/used audit records lost keyed binding: %d", n)
	}
}
