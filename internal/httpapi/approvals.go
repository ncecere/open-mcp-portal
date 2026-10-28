package httpapi

import (
	"context"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

// ApprovalService keeps browser routes independently testable. Every method
// rechecks live service authorization; middleware alone never grants approval.
type ApprovalService interface {
	ListRules(context.Context, authz.Actor, string, int32, int32) ([]approvals.Rule, error)
	CreateRule(context.Context, authz.Actor, string, approvals.RuleInput) (approvals.Rule, error)
	ReplaceRule(context.Context, authz.Actor, string, uuid.UUID, int64, approvals.RuleInput) (approvals.Rule, error)
	DeleteRule(context.Context, authz.Actor, string, uuid.UUID, int64) error
	ListRequests(context.Context, authz.Actor, string, int32, int32) ([]approvals.Receipt, error)
	GetRequest(context.Context, authz.Actor, uuid.UUID) (approvals.Receipt, error)
	Decide(context.Context, authz.Actor, uuid.UUID, approvals.Decision) (approvals.Receipt, error)
	Cancel(context.Context, authz.Actor, uuid.UUID, int64) (approvals.Receipt, error)
	Renew(context.Context, authz.Actor, uuid.UUID, int64) (approvals.Receipt, error)
}

func (a *api) approvalRoutes() []route {
	const one = "/v1/approvals/{approvalId}"
	out := []route{
		{"GET", "/v1/me/approvals", a.session(a.listMyApprovals)},
		{"GET", one, a.session(a.getApproval)},
		{"POST", one + "/decision", a.session(a.decideApproval)},
		{"POST", one + "/cancel", a.session(a.cancelApproval)},
		{"POST", one + "/renew", a.session(a.renewApproval)},
	}
	for _, base := range []string{"/v1/teams/{team}/approval-rules", "/v1/admin/approval-rules"} {
		out = append(out, route{"GET", base, a.session(a.listApprovalRules)},
			route{"POST", base, a.session(a.createApprovalRule)},
			route{"PUT", base + "/{ruleId}", a.session(a.replaceApprovalRule)},
			route{"DELETE", base + "/{ruleId}", a.session(a.deleteApprovalRule)})
	}
	return out
}

func (a *api) approvalReady(w http.ResponseWriter, r *http.Request) bool {
	if !a.browserOnly(w, r) {
		return false
	}
	if a.Approvals == nil {
		httpx.Error(w, http.StatusServiceUnavailable, "approval_unavailable", "Approvals are unavailable")
		return false
	}
	if r.Method != http.MethodGet && !a.connectLimited(w, r, "approval-mutate", 20, "Too many approval changes") {
		return false
	}
	return true
}

func approvalPage(w http.ResponseWriter, r *http.Request) (int32, int32, bool) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return 0, 0, false
	}
	keys, ok := decodeCursor(w, r, 1)
	if !ok {
		return 0, 0, false
	}
	var offset int64
	if keys != nil {
		var err error
		offset, err = strconv.ParseInt(keys[0], 10, 32)
		if err != nil || offset < 0 || offset > 1_000_000 {
			httpx.Error(w, 400, "invalid_cursor", "Invalid cursor")
			return 0, 0, false
		}
	}
	return int32(offset), limit, true
}

func writeApprovalPage[T any](w http.ResponseWriter, r *http.Request, rows []T, offset, limit int32) {
	var next *string
	if len(rows) > int(limit) {
		rows = rows[:limit]
		next = encodeCursor(strconv.FormatInt(int64(offset+limit), 10))
	}
	if rows == nil {
		rows = []T{}
	}
	httpx.JSON(w, 200, struct {
		Items      []T     `json:"items"`
		NextCursor *string `json:"nextCursor"`
	}{rows, next})
}

func (a *api) listMyApprovals(w http.ResponseWriter, r *http.Request) {
	if !a.approvalReady(w, r) {
		return
	}
	view := r.URL.Query().Get("view")
	if view == "" {
		view = "actionable"
	}
	if view != "requested" && view != "actionable" {
		httpx.Error(w, 400, "invalid_view", "Choose requested or actionable approvals")
		return
	}
	offset, limit, ok := approvalPage(w, r)
	if !ok {
		return
	}
	rows, err := a.Approvals.ListRequests(r.Context(), a.actor(r), view, offset, limit+1)
	if failed(w, r, err) {
		return
	}
	// Defense in depth: queues never carry preview even if an implementation
	// accidentally reuses a detail projection.
	for i := range rows {
		rows[i].Preview = nil
	}
	writeApprovalPage(w, r, rows, offset, limit)
}

func (a *api) getApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "approvalId")
	if !ok || !a.approvalReady(w, r) {
		return
	}
	v, err := a.Approvals.GetRequest(r.Context(), a.actor(r), id)
	if !failed(w, r, err) {
		httpx.JSON(w, 200, v)
	}
}

func (a *api) decideApproval(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "approvalId")
	if !ok || !a.approvalReady(w, r) {
		return
	}
	var in apitypes.ApprovalDecisionInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	if !in.Decision.Valid() {
		httpx.Error(w, 400, "invalid_decision", "Choose approve or deny")
		return
	}
	v, err := a.Approvals.Decide(r.Context(), a.actor(r), id, approvals.Decision{Decision: string(in.Decision), ExpectedArgsDigest: in.ExpectedArgsDigest, ExpectedReviewRevision: in.ExpectedReviewRevision})
	if !failed(w, r, err) {
		httpx.JSON(w, 200, v)
	}
}

func (a *api) cancelApproval(w http.ResponseWriter, r *http.Request) { a.reviewApproval(w, r, false) }
func (a *api) renewApproval(w http.ResponseWriter, r *http.Request)  { a.reviewApproval(w, r, true) }
func (a *api) reviewApproval(w http.ResponseWriter, r *http.Request, renew bool) {
	id, ok := pathUUID(w, r, "approvalId")
	if !ok || !a.approvalReady(w, r) {
		return
	}
	var in apitypes.ApprovalReviewInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	var v approvals.Receipt
	var err error
	if renew {
		v, err = a.Approvals.Renew(r.Context(), a.actor(r), id, in.ExpectedReviewRevision)
	} else {
		v, err = a.Approvals.Cancel(r.Context(), a.actor(r), id, in.ExpectedReviewRevision)
	}
	if !failed(w, r, err) {
		httpx.JSON(w, 200, v)
	}
}

func (a *api) listApprovalRules(w http.ResponseWriter, r *http.Request) {
	if !a.approvalReady(w, r) {
		return
	}
	offset, limit, ok := approvalPage(w, r)
	if !ok {
		return
	}
	rows, err := a.Approvals.ListRules(r.Context(), a.actor(r), r.PathValue("team"), offset, limit+1)
	if !failed(w, r, err) {
		writeApprovalPage(w, r, rows, offset, limit)
	}
}

func (a *api) createApprovalRule(w http.ResponseWriter, r *http.Request) {
	if !a.approvalReady(w, r) {
		return
	}
	var in approvals.RuleInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Approvals.CreateRule(r.Context(), a.actor(r), r.PathValue("team"), in)
	if !failed(w, r, err) {
		writeRevised(w, http.StatusCreated, v.Revision, v)
	}
}

func (a *api) replaceApprovalRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "ruleId")
	if !ok || !a.approvalReady(w, r) {
		return
	}
	in, rev, ok := decodeRevised[approvals.RuleInput](w, r)
	if !ok {
		return
	}
	v, err := a.Approvals.ReplaceRule(r.Context(), a.actor(r), r.PathValue("team"), id, rev, in)
	if !failed(w, r, err) {
		writeRevised(w, 200, v.Revision, v)
	}
}

func (a *api) deleteApprovalRule(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "ruleId")
	if !ok || !a.approvalReady(w, r) {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	writeOK(w, r, a.Approvals.DeleteRule(r.Context(), a.actor(r), r.PathValue("team"), id, rev))
}
