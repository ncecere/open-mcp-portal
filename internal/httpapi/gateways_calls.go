package httpapi

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

// callFilter reads ?gateway=, ?server=, ?user=, ?serviceAccount=, ?outcome=, ?identitySent=, ?from=, ?to=,
// ?cursor= and ?limit=.
func callFilter(w http.ResponseWriter, r *http.Request) (calls.Filter, int32, bool) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return calls.Filter{}, 0, false
	}
	f := calls.Filter{Limit: limit + 1}
	q := r.URL.Query()
	for _, p := range []struct {
		name string
		dst  **uuid.UUID
	}{{"gateway", &f.Gateway}, {"server", &f.Server}, {"user", &f.User}, {"serviceAccount", &f.ServiceAccount}} {
		if v := q.Get(p.name); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_"+p.name, p.name+" must be an ID")
				return f, 0, false
			}
			*p.dst = &id
		}
	}
	if v := q.Get("outcome"); v != "" {
		if !calls.ValidOutcome(v) {
			httpx.Error(w, http.StatusBadRequest, "invalid_outcome",
				"outcome must be ok, tool_error, denied, upstream_error, timeout, too_large, bad_request, needs_authorization or rate_limited")
			return f, 0, false
		}
		f.Outcome = &v
	}
	if v := q.Get("identitySent"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil || (v != "true" && v != "false") {
			httpx.Error(w, http.StatusBadRequest, "invalid_identity_sent", "identitySent must be true or false")
			return f, 0, false
		}
		f.IdentitySent = &b
	}
	for _, p := range []struct {
		name string
		dst  **time.Time
	}{{"from", &f.From}, {"to", &f.To}} {
		if raw := q.Get(p.name); raw != "" {
			t, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				httpx.Error(w, http.StatusBadRequest, "invalid_range", p.name+" must be an RFC 3339 date-time")
				return f, 0, false
			}
			*p.dst = &t
		}
	}
	if f.From != nil && f.To != nil && !f.From.Before(*f.To) {
		httpx.Error(w, http.StatusBadRequest, "invalid_range", "from must be before to")
		return f, 0, false
	}
	keys, ok := decodeCursor(w, r, 1)
	if !ok {
		return f, 0, false
	}
	if keys != nil {
		before, err := strconv.ParseInt(keys[0], 10, 64)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
			return f, 0, false
		}
		f.BeforeID = &before
	}
	return f, limit, true
}

func (a *api) writeCallPage(w http.ResponseWriter, r *http.Request, rows []calls.Row, err error, limit int32) {
	if failed(w, r, err) {
		return
	}
	page := apitypes.McpCallPage{Items: []apitypes.McpCall{}}
	if len(rows) > int(limit) {
		rows = rows[:limit]
		page.NextCursor = encodeCursor(strconv.FormatInt(rows[len(rows)-1].ID, 10))
	}
	for _, c := range rows {
		page.Items = append(page.Items, a.toAPICall(c))
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) listTeamCalls(w http.ResponseWriter, r *http.Request) {
	f, limit, ok := callFilter(w, r)
	if !ok {
		return
	}
	rows, err := a.Calls.ListTeam(r.Context(), a.actor(r), r.PathValue("team"), f)
	a.writeCallPage(w, r, rows, err, limit)
}

func (a *api) adminListCalls(w http.ResponseWriter, r *http.Request) {
	f, limit, ok := callFilter(w, r)
	if !ok {
		return
	}
	if v := r.URL.Query().Get("team"); v != "" {
		if len(v) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		f.Team = v
	}
	rows, err := a.Calls.AdminList(r.Context(), a.actor(r), f)
	a.writeCallPage(w, r, rows, err, limit)
}
