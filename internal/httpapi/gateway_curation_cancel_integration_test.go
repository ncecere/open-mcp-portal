package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/httpapi"
)

type cancelOnSSEFlush struct {
	*httptest.ResponseRecorder
	cancel context.CancelFunc
}

func (w *cancelOnSSEFlush) Flush() {
	w.ResponseRecorder.Flush()
	if w.Header().Get("Content-Type") == "text/event-stream" {
		w.cancel()
	}
}

// Cancel deterministically after SSE commits but before exchange's live DB
// check. Preparing an identity header must not become identity_sent=true when
// no transport happened, and the aborted check must still have one final record.
func TestCurationCancelledLiveCheckRecordsBeforeTransport(t *testing.T) {
	for _, identity := range []bool{true, false} {
		t.Run(map[bool]string{true: "identity", false: "no-identity"}[identity], func(t *testing.T) {
			var deps httpapi.Deps
			e := newRelayEnv(t, func(d *httpapi.Deps) { deps = *d })
			e.patchServer(e.owner, e.server, map[string]any{"sendIdentity": identity})
			body, headers := toolRequest(true, "status__progress", map[string]any{"count": 2}, map[string]any{"progressToken": "cancel-at-live-check"})
			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r := httptest.NewRequest("POST", "/mcp/support", bytes.NewReader(raw)).WithContext(ctx)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Accept", "application/json, text/event-stream")
			r.Header.Set("Authorization", "Bearer "+e.key)
			for k, v := range headers {
				r.Header.Set(k, v)
			}
			w := &cancelOnSSEFlush{httptest.NewRecorder(), cancel}
			after := curationLastCall(t, e.gwEnv)
			httpapi.NewAPIHandler(deps).ServeHTTP(w, r)
			if w.Code != http.StatusOK || !w.Flushed || ctx.Err() == nil {
				t.Fatalf("test did not cancel an opened SSE response: %d %t %v", w.Code, w.Flushed, ctx.Err())
			}
			if len(e.fake.ToolCalls()) != 0 {
				t.Fatal("cancelled live check reached transport")
			}
			var count int
			if err := e.app.Pool.QueryRow(t.Context(), `SELECT count(*) FROM mcp_calls WHERE id>$1 AND method='tools/call' AND outcome='upstream_error' AND error_class='client_cancelled' AND identity_sent IS NULL AND server_id=$2`, after, e.server.Id).Scan(&count); err != nil || count != 1 {
				t.Fatalf("cancelled pretransport check: %d appropriate records, err=%v", count, err)
			}
			if err := e.app.Pool.QueryRow(t.Context(), `SELECT count(*) FROM mcp_calls WHERE id>$1`, after).Scan(&count); err != nil || count != 1 {
				t.Fatalf("cancelled pretransport check: %d total records, err=%v", count, err)
			}
		})
	}
}
