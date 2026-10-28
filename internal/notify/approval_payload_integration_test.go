package notify

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
)

func TestApprovalNoticeExplicitPayloadAllowlist(t *testing.T) {
	e := newEnv(t, nil)
	secret := "PRIVATE-RECEIPT-SENTINEL"
	r := approvals.Receipt{ID: uuid.New(), Status: approvals.Pending, ExposedName: "delete",
		ArgsDigest: secret, CapabilityFingerprint: secret, ServerOrigin: "https://user:" + secret + "@private.test",
		RequesterKind: secret, RequesterID: uuid.New(), Preview: &secret, PreviewRedacted: true, PreviewTruncated: true}
	ApprovalNotice(context.Background(), e.q, r, true)
	raw := e.exec(`SELECT payload::text FROM notification_events`)
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatal(err)
	}
	if len(data) != 3 || data["approvalId"] != r.ID.String() || data["exposedName"] != "delete" || data["status"] != approvals.Pending || strings.Contains(raw, secret) {
		t.Fatalf("receipt was not reduced to the payload allowlist: %s", raw)
	}
	ApprovalNotice(context.Background(), e.q, r, true) // idempotent emitter too
	r.ID = uuid.New()
	ApprovalNotice(context.Background(), e.q, r, false) // not a decision
	r.Status = approvals.Expired
	ApprovalNotice(context.Background(), e.q, r, true) // not pending
	if e.count(`SELECT count(*) FROM notification_events`) != 1 {
		t.Fatal("duplicate/invalid lifecycle emitted")
	}
}
