package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Gateways, their selections and grants, the caller's gateways and API
// keys, call records, and the MCP endpoint (docs/phase3-gateways.md). The
// services authorize every call; these handlers only parse and render.

// gatewayRoutes: a team's gateways and calls.
func (a *api) gatewayRoutes() []route {
	const base = "/v1/teams/{team}/gateways"
	return []route{
		{"GET", base, a.session(a.listTeamGateways)},
		{"POST", base, a.session(a.createTeamGateway)},
		{"GET", base + "/{gatewayId}", a.session(a.getTeamGateway)},
		{"PATCH", base + "/{gatewayId}", a.session(a.updateTeamGateway)},
		{"DELETE", base + "/{gatewayId}", a.session(a.deleteTeamGateway)},
		{"GET", base + "/{gatewayId}/capabilities", a.session(a.listTeamGatewayCapabilities)},
		{"PUT", base + "/{gatewayId}/capabilities", a.session(a.setTeamGatewayCapabilities)},
		{"GET", "/v1/teams/{team}/gateway-options", a.session(a.listTeamGatewayOptions)},
		{"GET", "/v1/teams/{team}/calls", a.session(a.listTeamCalls)},
	}
}

// gatewayAdminRoutes: every gateway, platform gateways' grants and calls.
func (a *api) gatewayAdminRoutes() []route {
	const base = "/v1/admin/gateways"
	return []route{
		{"GET", base, a.admin(a.adminListGateways)},
		{"POST", base, a.admin(a.adminCreateGateway)},
		{"GET", base + "/{gatewayId}", a.admin(a.adminGetGateway)},
		{"PATCH", base + "/{gatewayId}", a.admin(a.adminUpdateGateway)},
		{"DELETE", base + "/{gatewayId}", a.admin(a.adminDeleteGateway)},
		{"GET", base + "/{gatewayId}/capabilities", a.admin(a.adminListGatewayCapabilities)},
		{"PUT", base + "/{gatewayId}/capabilities", a.admin(a.adminSetGatewayCapabilities)},
		{"GET", base + "/{gatewayId}/grants", a.admin(a.adminListGatewayGrants)},
		{"POST", base + "/{gatewayId}/grants", a.admin(a.adminAddGatewayGrant)},
		{"DELETE", base + "/{gatewayId}/grants/{grantId}", a.admin(a.adminRemoveGatewayGrant)},
		{"GET", "/v1/admin/gateway-options", a.admin(a.adminListGatewayOptions)},
		{"GET", "/v1/admin/calls", a.admin(a.adminListCalls)},
	}
}

// meGatewayRoutes: what the caller can connect to, and their API keys.
func (a *api) meGatewayRoutes() []route {
	return []route{
		{"GET", "/v1/me/gateways", a.session(a.listMyGateways)},
		{"GET", "/v1/me/gateways/{gatewayId}", a.session(a.getMyGateway)},
		{"GET", "/v1/me/api-keys", a.session(a.listMyApiKeys)},
		{"POST", "/v1/me/api-keys", a.session(a.createMyApiKey)},
		{"DELETE", "/v1/me/api-keys/{keyId}", a.session(a.revokeMyApiKey)},
	}
}

// mcpRoutes: the MCP endpoint and the identity keys, outside OpenAPI.
func (a *api) mcpRoutes() []route {
	return []route{
		{"POST", "/mcp/{slug}", http.HandlerFunc(a.serveMCP)},
		{"GET", "/mcp/{slug}", http.HandlerFunc(a.serveMCP)},
		{"DELETE", "/mcp/{slug}", http.HandlerFunc(a.serveMCP)},
		{"GET", "/.well-known/jwks.json", http.HandlerFunc(a.jwks)},
	}
}

func (a *api) serveMCP(w http.ResponseWriter, r *http.Request) { a.MCP.ServeHTTP(w, r) }

// jwks publishes the identity signing keys (active and retiring). Servers
// cache it for five minutes and fetch it again for an unknown kid.
func (a *api) jwks(w http.ResponseWriter, r *http.Request) {
	set, err := a.Identity.JWKS(r.Context())
	if err != nil {
		httpx.Internal(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = json.NewEncoder(w).Encode(set)
}

// gatewayListParams reads ?q=, ?cursor= and ?limit=.
func gatewayListParams(w http.ResponseWriter, r *http.Request) (gateways.ListParams, int32, bool) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return gateways.ListParams{}, 0, false
	}
	q, ok := search(w, r)
	if !ok {
		return gateways.ListParams{}, 0, false
	}
	keys, ok := decodeCursor(w, r, 2)
	if !ok {
		return gateways.ListParams{}, 0, false
	}
	p := gateways.ListParams{Search: q, Limit: limit + 1}
	if keys != nil {
		id, err := uuid.Parse(keys[1])
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
			return p, 0, false
		}
		p.AfterName, p.AfterID = &keys[0], &id
	}
	return p, limit, true
}

func (a *api) writeGatewayPage(w http.ResponseWriter, r *http.Request, rows []gateways.View, err error, limit int32) {
	if failed(w, r, err) {
		return
	}
	page := apitypes.GatewayPage{Items: []apitypes.Gateway{}}
	if len(rows) > int(limit) {
		rows = rows[:limit]
		last := rows[len(rows)-1].Gateway
		page.NextCursor = encodeCursor(last.Name, last.ID.String())
	}
	limits, err := a.gatewayLimits(r.Context(), rows)
	if failed(w, r, err) {
		return
	}
	for i, v := range rows {
		page.Items = append(page.Items, a.toAPIGateway(v, limits[i]))
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) writeGateway(w http.ResponseWriter, r *http.Request, status int, v gateways.View, err error) {
	if failed(w, r, err) {
		return
	}
	limits, err := a.gatewayLimits(r.Context(), []gateways.View{v})
	if failed(w, r, err) {
		return
	}
	writeRevised(w, status, v.Gateway.Revision, a.toAPIGateway(v, limits[0]))
}

func createInput(in apitypes.GatewayCreate) gateways.CreateInput {
	ci := gateways.CreateInput{Slug: in.Slug, Name: in.Name, Enabled: true, RateLimit: in.RateLimitPerMinute}
	setIf(&ci.Description, in.Description)
	setIf(&ci.Enabled, in.Enabled)
	setIf(&ci.CapturePayloads, in.CapturePayloads)
	return ci
}

// decodeGatewayUpdate reads a gateway update; rateLimitPerMinute
// distinguishes absent (keep) from null (inherit).
func decodeGatewayUpdate(w http.ResponseWriter, r *http.Request) (gateways.UpdateInput, int64, bool) {
	rev, ok := ifMatch(w, r)
	if !ok {
		return gateways.UpdateInput{}, 0, false
	}
	in, keys, ok := decodeKeys[apitypes.GatewayUpdate](w, r)
	if !ok {
		return gateways.UpdateInput{}, 0, false
	}
	_, setLimit := keys["rateLimitPerMinute"]
	return gateways.UpdateInput{Name: in.Name, Description: in.Description, Enabled: in.Enabled, CapturePayloads: in.CapturePayloads,
		SetRateLimit: setLimit, RateLimit: in.RateLimitPerMinute}, rev, true
}

// gatewayLimits are the gateways' effective rate limits now (nil:
// unlimited).
func (a *api) gatewayLimits(ctx context.Context, vs []gateways.View) ([]*int64, error) {
	out := make([]*int64, len(vs))
	if a.Limits == nil {
		return out, nil
	}
	teams := map[uuid.UUID]*dbgen.Team{}
	for i, v := range vs {
		g := v.Gateway
		var team *dbgen.Team
		if g.TeamID.Valid {
			t, ok := teams[g.TeamID.UUID]
			if !ok {
				row, err := a.q.GetTeamByID(ctx, g.TeamID.UUID)
				if err != nil {
					return nil, err
				}
				t, teams[g.TeamID.UUID] = &row, &row
			}
			team = t
		}
		lim, err := a.Limits.GatewayLimit(ctx, g.RateLimitPerMinute, team)
		if err != nil {
			return nil, err
		}
		out[i] = lim
	}
	return out, nil
}

func selectionInput(in apitypes.GatewayCapabilitiesUpdate) []gateways.SelectionInput {
	out := make([]gateways.SelectionInput, len(in.Items))
	for i, it := range in.Items {
		out[i] = gateways.SelectionInput{CapabilityID: it.CapabilityId, MinRole: (*string)(it.MinRole)}
	}
	return out
}

func (a *api) writeSelection(w http.ResponseWriter, r *http.Request, s gateways.Selection, err error) {
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPISelection(s))
}

func (a *api) listTeamGateways(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := gatewayListParams(w, r)
	if !ok {
		return
	}
	rows, err := a.Gateways.ListTeam(r.Context(), a.actor(r), r.PathValue("team"), p)
	a.writeGatewayPage(w, r, rows, err, limit)
}

func (a *api) createTeamGateway(w http.ResponseWriter, r *http.Request) {
	var in apitypes.GatewayCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Gateways.CreateTeam(r.Context(), a.actor(r), r.PathValue("team"), createInput(in))
	a.writeGateway(w, r, http.StatusCreated, v, err)
}

func (a *api) getTeamGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	v, err := a.Gateways.GetTeam(r.Context(), a.actor(r), r.PathValue("team"), id)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) updateTeamGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeGatewayUpdate(w, r)
	if !ok {
		return
	}
	v, err := a.Gateways.UpdateTeam(r.Context(), a.actor(r), r.PathValue("team"), id, in, rev)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) deleteTeamGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	writeOK(w, r, a.Gateways.DeleteTeam(r.Context(), a.actor(r), r.PathValue("team"), id))
}

func (a *api) listTeamGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	s, err := a.Gateways.TeamSelection(r.Context(), a.actor(r), r.PathValue("team"), id)
	a.writeSelection(w, r, s, err)
}

func (a *api) setTeamGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.GatewayCapabilitiesUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Gateways.SetTeamSelection(r.Context(), a.actor(r), r.PathValue("team"), id, selectionInput(in), rev)
	a.writeSelection(w, r, s, err)
}

// optionParams reads gateway-options' ?q=, ?kind=, ?server=, ?cursor= and
// ?limit= (default 100, at most 500).
func optionParams(w http.ResponseWriter, r *http.Request) (gateways.OptionParams, int32, bool) {
	p := gateways.OptionParams{Kind: kindParam(r)}
	limit := int32(gateways.DefaultOptionPage)
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > gateways.MaxOptionPage {
			httpx.Error(w, http.StatusBadRequest, "invalid_limit", "limit must be between 1 and 500")
			return p, 0, false
		}
		limit = int32(n)
	}
	q, ok := search(w, r)
	if !ok {
		return p, 0, false
	}
	p.Search, p.Limit = q, limit+1
	if v := r.URL.Query().Get("server"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_server", "server must be an ID")
			return p, 0, false
		}
		p.Server = &id
	}
	keys, ok := decodeCursor(w, r, 4)
	if !ok {
		return p, 0, false
	}
	if keys != nil {
		serverID, err1 := uuid.Parse(keys[1])
		id, err2 := uuid.Parse(keys[3])
		if err1 != nil || err2 != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_cursor", "Invalid cursor")
			return p, 0, false
		}
		p.After = &gateways.OptionCursor{ServerName: keys[0], ServerID: serverID, Name: keys[2], ID: id}
	}
	return p, limit, true
}

func writeOptionPage(w http.ResponseWriter, r *http.Request, opts []gateways.Option, err error, limit int32) {
	if failed(w, r, err) {
		return
	}
	page := apitypes.GatewayOptionPage{Items: []apitypes.GatewayOption{}}
	if len(opts) > int(limit) {
		opts = opts[:limit]
		c := opts[len(opts)-1].Cursor()
		page.NextCursor = encodeCursor(c.ServerName, c.ServerID.String(), c.Name, c.ID.String())
	}
	for _, o := range opts {
		page.Items = append(page.Items, toAPIGatewayOption(o))
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) listTeamGatewayOptions(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := optionParams(w, r)
	if !ok {
		return
	}
	opts, err := a.Gateways.TeamOptions(r.Context(), a.actor(r), r.PathValue("team"), p)
	writeOptionPage(w, r, opts, err, limit)
}

func (a *api) adminListGateways(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := gatewayListParams(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	switch v := q.Get("ownerKind"); v {
	case "":
	case gateways.OwnerTeam, gateways.OwnerPlatform:
		p.OwnerKind = &v
	default:
		httpx.Error(w, http.StatusBadRequest, "invalid_owner_kind", "ownerKind must be team or platform")
		return
	}
	if v := q.Get("team"); v != "" {
		if len(v) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		p.Team = v
	}
	rows, err := a.Gateways.AdminList(r.Context(), a.actor(r), p)
	a.writeGatewayPage(w, r, rows, err, limit)
}

func (a *api) adminCreateGateway(w http.ResponseWriter, r *http.Request) {
	var in apitypes.GatewayCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Gateways.AdminCreate(r.Context(), a.actor(r), createInput(in))
	a.writeGateway(w, r, http.StatusCreated, v, err)
}

func (a *api) adminGetGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	v, err := a.Gateways.AdminGet(r.Context(), a.actor(r), id)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) adminUpdateGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeGatewayUpdate(w, r)
	if !ok {
		return
	}
	v, err := a.Gateways.AdminUpdate(r.Context(), a.actor(r), id, in, rev)
	a.writeGateway(w, r, http.StatusOK, v, err)
}

func (a *api) adminDeleteGateway(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	writeOK(w, r, a.Gateways.AdminDelete(r.Context(), a.actor(r), id))
}

func (a *api) adminListGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	s, err := a.Gateways.AdminSelection(r.Context(), a.actor(r), id)
	a.writeSelection(w, r, s, err)
}

func (a *api) adminSetGatewayCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.GatewayCapabilitiesUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Gateways.AdminSetSelection(r.Context(), a.actor(r), id, selectionInput(in), rev)
	a.writeSelection(w, r, s, err)
}

func (a *api) adminListGatewayOptions(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := optionParams(w, r)
	if !ok {
		return
	}
	opts, err := a.Gateways.AdminOptions(r.Context(), a.actor(r), p)
	writeOptionPage(w, r, opts, err, limit)
}

func (a *api) adminListGatewayGrants(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	grants, err := a.Gateways.Grants(r.Context(), a.actor(r), id)
	writeList(w, r, grants, err, toAPIGrant)
}

func (a *api) adminAddGatewayGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	var in apitypes.GatewayGrantCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	g, err := a.Gateways.AddGrant(r.Context(), a.actor(r), id, gateways.GrantInput{
		Kind: string(in.SubjectKind), Team: in.Team, UserEmail: in.UserEmail, Group: in.Group,
	})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, toAPIGrant(g))
}

func (a *api) adminRemoveGatewayGrant(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	grantID, ok := pathUUID(w, r, "grantId")
	if !ok {
		return
	}
	writeOK(w, r, a.Gateways.RemoveGrant(r.Context(), a.actor(r), id, grantID))
}

func (a *api) listMyGateways(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	mine, err := a.Gateways.ListMine(r.Context(), id.User)
	writeList(w, r, mine, err, a.toAPIMyGateway)
}

func (a *api) getMyGateway(w http.ResponseWriter, r *http.Request) {
	gid, ok := pathUUID(w, r, "gatewayId")
	if !ok {
		return
	}
	id, _ := auth.FromContext(r.Context())
	m, offers, err := a.Gateways.GetMine(r.Context(), id.User, gid)
	if failed(w, r, err) {
		return
	}
	ready, err := a.Providers.ReadyFor(r.Context(), id.User.ID)
	if failed(w, r, err) {
		return
	}
	out := apitypes.MyGatewayDetail{Gateway: a.toAPIMyGateway(m), Capabilities: make([]apitypes.GatewayCapability, len(offers))}
	for i, o := range offers {
		out.Capabilities[i] = toAPIGatewayCapability(o.Selected)
		if req := o.Requires; req != nil {
			// Connected: a call would carry the token now (the person also
			// allowed this capability's server, at its current address).
			connected := ready(req, o.Server)
			out.Capabilities[i].Requires = toAPIRequirement(req, &connected)
		}
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *api) listMyApiKeys(w http.ResponseWriter, r *http.Request) {
	keys, err := a.APIKeys.List(r.Context(), a.actor(r))
	now := time.Now()
	writeList(w, r, keys, err, func(k apikeys.View) apitypes.ApiKey { return toAPIKey(k, now) })
}

func (a *api) createMyApiKey(w http.ResponseWriter, r *http.Request) {
	var in apitypes.ApiKeyCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	days := int32(0)
	setIf(&days, in.ExpiresInDays)
	if in.ExpiresInDays != nil && days == 0 {
		days = -1 // explicit 0 is invalid, not the default
	}
	ci := apikeys.CreateInput{Name: in.Name, Days: days}
	if in.GatewayIds != nil {
		ci.GatewayIDs = *in.GatewayIds
	}
	c, err := a.APIKeys.Create(r.Context(), a.actor(r), ci)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusCreated, apitypes.ApiKeyCreated{Key: toAPIKey(c.View, time.Now()), Secret: c.Secret})
}

func (a *api) revokeMyApiKey(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "keyId")
	if !ok {
		return
	}
	writeOK(w, r, a.APIKeys.Revoke(r.Context(), a.actor(r), id))
}

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
