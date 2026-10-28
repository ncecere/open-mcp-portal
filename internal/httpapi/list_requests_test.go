package httpapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

type queuePageFake struct {
	ApprovalService
	rows         []approvals.Receipt
	next         string
	view, cursor string
	limit        int32
}

var _ ApprovalService = (*queuePageFake)(nil)

func (f *queuePageFake) ListRequestsPage(_ context.Context, _ authz.Actor, view, cursor string, limit int32) ([]approvals.Receipt, string, error) {
	f.view, f.cursor, f.limit = view, cursor, limit
	return f.rows, f.next, nil
}

func TestListMyApprovalsUsesKeysetAndPreservesEmptyContinuation(t *testing.T) {
	for _, empty := range []bool{true, false} {
		f := &queuePageFake{next: "next-keyset"}
		if !empty {
			preview := "must-not-leak"
			f.rows = []approvals.Receipt{{ID: uuid.New(), Preview: &preview}}
		}
		a := &api{Deps: Deps{Approvals: f}}
		r := httptest.NewRequest("GET", "/v1/me/approvals?view=requested&cursor=opaque-keyset&limit=200", nil)
		r = r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{SessionID: "browser", User: dbgen.User{ID: uuid.New()}}))
		w := httptest.NewRecorder()
		a.listMyApprovals(w, r)
		if w.Code != 200 || f.cursor != "opaque-keyset" || f.view != "requested" || f.limit != 200 {
			t.Fatalf("keyset forwarding: %d %+v", w.Code, f)
		}
		var response struct {
			Data struct {
				Items      []approvals.Receipt `json:"items"`
				NextCursor *string             `json:"nextCursor"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Data.NextCursor == nil || *response.Data.NextCursor != "next-keyset" || response.Data.Items == nil {
			t.Fatalf("lost empty continuation: %s", w.Body.String())
		}
		for _, row := range response.Data.Items {
			if row.Preview != nil {
				t.Fatal("list returned a preview")
			}
		}
	}
}
