package httpapi

import (
	"net/http"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

func (a *api) accessRequestRoutes() []route {
	return []route{
		{"GET", "/v1/gateways/requestable", a.session(a.listRequestableGateways)},
		{"GET", "/v1/me/access-requests", a.session(a.listMyAccessRequests)},
		{"POST", "/v1/me/access-requests", a.session(a.createAccessRequest)},
		{"GET", "/v1/access-requests/{requestId}", a.session(a.getAccessRequest)},
		{"POST", "/v1/access-requests/{requestId}/decision", a.session(a.decideAccessRequest)},
		{"POST", "/v1/access-requests/{requestId}/withdraw", a.session(a.withdrawAccessRequest)},
		{"GET", "/v1/admin/gateways/{gatewayId}/access-settings", a.session(a.adminGetGatewayAccessSettings)},
		{"PUT", "/v1/admin/gateways/{gatewayId}/access-settings", a.session(a.adminSetGatewayAccessSettings)},
	}
}

func (a *api) accessReady(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Cache-Control", "no-store")
	if !a.browserOnly(w, r) {
		return false
	}
	if r.Method != http.MethodGet && !a.connectLimited(w, r, "access-request-mutate", 20, "Too many access request changes") {
		return false
	}
	if a.Gateways == nil {
		httpx.Error(w, 503, "access_unavailable", "Gateway access requests are unavailable")
		return false
	}
	return true
}

func (a *api) listRequestableGateways(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	offset, limit, ok := approvalPage(w, r)
	if !ok {
		return
	}
	rows, err := a.Gateways.Requestable(r.Context(), a.actor(r), offset, limit+1)
	if failed(w, r, err) {
		return
	}
	out := make([]apitypes.RequestableGateway, len(rows))
	for i, row := range rows {
		out[i] = apitypes.RequestableGateway{Id: row.ID, Name: row.Name, Description: row.Description}
	}
	writeApprovalPage(w, r, out, offset, limit)
}

func (a *api) listMyAccessRequests(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	offset, limit, ok := approvalPage(w, r)
	if !ok {
		return
	}
	view := r.URL.Query().Get("view")
	if view != "" && view != "requested" && view != "review" {
		httpx.Error(w, 400, "invalid_view", "Choose requested or review")
		return
	}
	pending := r.URL.Query().Get("pendingOnly")
	if pending != "" && pending != "false" && pending != "true" {
		httpx.Error(w, 400, "invalid_filter", "pendingOnly must be true or false")
		return
	}
	rows, count, err := a.Gateways.AccessRequests(r.Context(), a.actor(r), view == "review", pending == "true", offset, limit+1)
	if failed(w, r, err) {
		return
	}
	var next *string
	if len(rows) > int(limit) {
		rows, next = rows[:limit], encodeCursor(strconv.FormatInt(int64(offset+limit), 10))
	}
	httpx.JSON(w, 200, struct {
		Items              []gateways.AccessRequest `json:"items"`
		PendingReviewCount int64                    `json:"pendingReviewCount"`
		NextCursor         *string                  `json:"nextCursor"`
	}{rows, count, next})
}

func (a *api) createAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	var in apitypes.AccessRequestCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	out, err := a.Gateways.CreateAccessRequest(r.Context(), a.actor(r), in.GatewayId, in.TeamId, in.Reason)
	if !failed(w, r, err) {
		httpx.JSON(w, 201, out)
	}
}

func (a *api) getAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	id, ok := pathUUID(w, r, "requestId")
	if !ok {
		return
	}
	out, err := a.Gateways.GetAccessRequest(r.Context(), a.actor(r), id)
	if !failed(w, r, err) {
		httpx.JSON(w, 200, out)
	}
}

func (a *api) decideAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	id, ok := pathUUID(w, r, "requestId")
	if !ok {
		return
	}
	var in apitypes.AccessRequestDecision
	if !httpx.Decode(w, r, &in) {
		return
	}
	note := ""
	if in.Note != nil {
		note = *in.Note
	}
	out, err := a.Gateways.DecideAccessRequest(r.Context(), a.actor(r), id, gateways.AccessDecision{Decision: string(in.Decision), Note: note, ExpiresInDays: in.ExpiresInDays})
	if !failed(w, r, err) {
		httpx.JSON(w, 200, out)
	}
}

func (a *api) withdrawAccessRequest(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	id, ok := pathUUID(w, r, "requestId")
	if !ok {
		return
	}
	out, err := a.Gateways.WithdrawAccessRequest(r.Context(), a.actor(r), id)
	if !failed(w, r, err) {
		httpx.JSON(w, 200, out)
	}
}

func (a *api) adminGetGatewayAccessSettings(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	out, err := a.Gateways.AccessSettings(r.Context(), a.actor(r), id)
	if !failed(w, r, err) {
		httpx.JSON(w, 200, out)
	}
}

func (a *api) adminSetGatewayAccessSettings(w http.ResponseWriter, r *http.Request) {
	if !a.accessReady(w, r) {
		return
	}
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	in, keys, ok := decodeKeys[apitypes.GatewayAccessSettingsUpdate](w, r)
	if !ok {
		return
	}
	if _, present := keys["enabled"]; !present || string(keys["enabled"]) == "null" || in.StewardIds == nil {
		httpx.Error(w, 400, "invalid_settings", "Both enabled and stewardIds are required; use an empty array for no stewards")
		return
	}
	out, err := a.Gateways.SetAccessSettings(r.Context(), a.actor(r), id, rev, in.Enabled, in.StewardIds)
	if !failed(w, r, err) {
		writeRevised(w, 200, out.Revision, out)
	}
}
