package httpapi_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestApprovalsHTTPRejectsLossyUnicodeBeforeReviewOrDispatch(t *testing.T) {
	for _, era := range []testutil.Protocol{testutil.ProtocolLegacy, testutil.ProtocolModern} {
		t.Run(string(era), func(t *testing.T) {
			e := newApprovalWire(t, era, nil)
			for _, note := range []json.RawMessage{[]byte(`"\ud800"`), []byte(`"\udfff"`)} {
				p := map[string]any{"name": "reviewed_lookup", "arguments": map[string]any{"limit": 2, "note": note}}
				out := e.call(t, era == testutil.ProtocolModern, e.key.Secret, p, urlCaps)
				if out["error"] == nil || e.posts.Load() != 0 {
					t.Fatalf("lossy Unicode reached approval or upstream: %v", out)
				}
			}
			var count int
			if err := e.app.Pool.QueryRow(context.Background(), `SELECT count(*) FROM approval_requests`).Scan(&count); err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("lossy Unicode created %d review requests", count)
			}
		})
	}
}
