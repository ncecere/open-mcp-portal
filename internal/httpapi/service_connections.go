package httpapi

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"net/http"
)

func (a *api) serviceConnectionRoutes() []route {
	const base = "/v1/teams/{team}/service-connections"
	const one = base + "/{connectionId}"
	return []route{
		{"GET", base, a.session(a.listTeamServiceConnections)},
		{"POST", base, a.session(a.startTeamServiceConnection)},
		{"PUT", one, a.session(a.updateTeamServiceConnection)},
		{"DELETE", one, a.session(a.revokeTeamServiceConnection)},
		{"GET", one + "/allowable-servers", a.session(a.listServiceConnectionAllowableServers)},
		{"POST", one + "/reconnect", a.session(a.reconnectTeamServiceConnection)},
		{"GET", "/v1/admin/service-connections", a.admin(a.adminListServiceConnections)},
	}
}
func (a *api) listServiceConnectionAllowableServers(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	vs, err := a.Providers.ServiceAllowable(r.Context(), a.actor(r), r.PathValue("team"), id)
	writeList(w, r, vs, err, func(v providers.Allowable) apitypes.AllowableServer {
		return apitypes.AllowableServer{Server: toAPIConnectServer(v.Server), Origin: v.Origin, Scopes: v.Scopes, Covered: v.Covered, Allowed: v.Allowed}
	})
}
func toAPIServiceConnection(v providers.ServiceConnectionView) apitypes.ServiceConnection {
	gs := make([]apitypes.ServiceConnectionGrant, len(v.Servers))
	for i, g := range v.Servers {
		gs[i] = apitypes.ServiceConnectionGrant{ServerId: g.ServerID, Origin: g.Origin, Scopes: g.Scopes}
	}
	return apitypes.ServiceConnection{Id: v.ID, TeamId: v.TeamID, ProviderId: v.ProviderID, ProviderName: v.ProviderName, Name: v.Name, AccountLabel: v.AccountLabel, Status: apitypes.ServiceConnectionStatus(v.Status), Scopes: v.Scopes, Revision: v.Revision, Accounts: v.Accounts, Servers: gs}
}
func (a *api) listTeamServiceConnections(w http.ResponseWriter, r *http.Request) {
	if !a.browserOnly(w, r) {
		return
	}
	rows, e := a.Providers.ListServiceConnections(r.Context(), a.actor(r), r.PathValue("team"), uuid.NullUUID{}, 201)
	writeList(w, r, rows, e, toAPIServiceConnection)
}
func (a *api) adminListServiceConnections(w http.ResponseWriter, r *http.Request) {
	if !a.browserOnly(w, r) {
		return
	}
	limit, ok := pageLimit(w, r)
	if !ok {
		return
	}
	keys, ok := decodeCursor(w, r, 1)
	if !ok {
		return
	}
	var after uuid.NullUUID
	if keys != nil {
		id, e := uuid.Parse(keys[0])
		if e != nil {
			httpx.Error(w, 400, "invalid_cursor", "Invalid cursor")
			return
		}
		after = uuid.NullUUID{UUID: id, Valid: true}
	}
	rows, e := a.Providers.ListServiceConnections(r.Context(), a.actor(r), "", after, limit+1)
	if failed(w, r, e) {
		return
	}
	var next *string
	if len(rows) > int(limit) {
		rows = rows[:limit]
		next = encodeCursor(rows[len(rows)-1].ID.String())
	}
	items := make([]apitypes.ServiceConnection, len(rows))
	for i, v := range rows {
		items[i] = toAPIServiceConnection(v)
	}
	httpx.JSON(w, 200, struct {
		Items      []apitypes.ServiceConnection `json:"items"`
		NextCursor *string                      `json:"nextCursor"`
	}{items, next})
}
func (a *api) startTeamServiceConnection(w http.ResponseWriter, r *http.Request) {
	if !a.browserOnly(w, r) || !a.connectLimited(w, r, "service-connect", 20, "Too many connection attempts") {
		return
	}
	var in apitypes.ServiceConnectionStart
	if !httpx.Decode(w, r, &in) {
		return
	}
	session, _ := auth.FromContext(r.Context())
	var scopes []string
	if in.Scopes != nil {
		scopes = *in.Scopes
	}
	st, e := a.Providers.StartServiceConnection(r.Context(), a.actor(r), r.PathValue("team"), in.ProviderId, in.Name, scopes, session.SessionID)
	if failed(w, r, e) {
		return
	}
	httpx.JSON(w, 200, apitypes.ConnectStarted{AuthorizeUrl: st.AuthorizeURL, Scopes: st.Scopes, ExpiresAt: st.ExpiresAt})
}
func (a *api) reconnectTeamServiceConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	if !a.connectLimited(w, r, "service-connect", 20, "Too many connection attempts") {
		return
	}
	session, _ := auth.FromContext(r.Context())
	st, e := a.Providers.ReconnectServiceConnection(r.Context(), a.actor(r), r.PathValue("team"), id, rev, session.SessionID)
	if failed(w, r, e) {
		return
	}
	httpx.JSON(w, 200, apitypes.ConnectStarted{AuthorizeUrl: st.AuthorizeURL, Scopes: st.Scopes, ExpiresAt: st.ExpiresAt})
}
func (a *api) updateTeamServiceConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	in, rev, ok := decodeRevised[apitypes.ServiceConnectionUpdate](w, r)
	if !ok {
		return
	}
	if in.Accounts == nil || in.Servers == nil {
		httpx.Error(w, http.StatusBadRequest, "invalid_assignment", "Send both accounts and servers as arrays (empty arrays remove access)")
		return
	}
	grants := make([]providers.ServiceGrant, len(in.Servers))
	for i, g := range in.Servers {
		grants[i] = providers.ServiceGrant{ServerID: g.ServerId, Origin: g.Origin, Scopes: g.Scopes}
	}
	v, e := a.Providers.UpdateServiceConnection(r.Context(), a.actor(r), r.PathValue("team"), id, rev, in.Accounts, grants)
	if failed(w, r, e) {
		return
	}
	writeRevised(w, 200, v.Revision, toAPIServiceConnection(v))
}
func (a *api) revokeTeamServiceConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	writeOK(w, r, a.Providers.RevokeServiceConnection(r.Context(), a.actor(r), r.PathValue("team"), id))
}
