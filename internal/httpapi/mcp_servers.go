package httpapi

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// The MCP server registry: team servers, the company catalog and their
// platform administration (docs/registry.md). The registry service
// authorizes every call; these handlers only parse and render.

// mcpServerRoutes: a team's servers and publishing policy, and the catalog.
func (a *api) mcpServerRoutes() []route {
	const base = "/v1/teams/{team}/mcp-servers"
	return []route{
		{"GET", base, a.session(a.listTeamMcpServers)},
		{"POST", base, a.session(a.createTeamMcpServer)},
		{"GET", base + "/{serverId}", a.session(a.getTeamMcpServer)},
		{"PATCH", base + "/{serverId}", a.session(a.updateTeamMcpServer)},
		{"DELETE", base + "/{serverId}", a.session(a.deleteTeamMcpServer)},
		{"POST", base + "/{serverId}/test", a.session(a.testTeamMcpServer)},
		{"POST", base + "/{serverId}/refresh", a.session(a.refreshTeamMcpServer)},
		{"GET", base + "/{serverId}/capabilities", a.session(a.listTeamMcpCapabilities)},
		{"PUT", base + "/{serverId}/capabilities/{capabilityId}/approval", a.session(a.approveTeamMcpCapability)},
		{"GET", base + "/{serverId}/health-checks", a.session(a.listTeamMcpHealthChecks)},
		{"POST", base + "/{serverId}/publish", a.session(a.publishTeamMcpServer)},
		{"POST", base + "/{serverId}/unpublish", a.session(a.unpublishTeamMcpServer)},
		{"GET", "/v1/teams/{team}/publishing", a.session(a.getTeamPublishing)},
		{"GET", "/v1/catalog/servers", a.session(a.listCatalogServers)},
		{"GET", "/v1/catalog/servers/{serverId}", a.session(a.getCatalogServer)},
	}
}

// mcpAdminRoutes: every team's servers, reviews, publishing settings and
// internal networks.
func (a *api) mcpAdminRoutes() []route {
	return []route{
		{"GET", "/v1/admin/mcp-servers", a.admin(a.adminListMcpServers)},
		{"GET", "/v1/admin/mcp-servers/{serverId}", a.admin(a.adminGetMcpServer)},
		{"GET", "/v1/admin/mcp-servers/{serverId}/capabilities", a.admin(a.adminListMcpCapabilities)},
		{"GET", "/v1/admin/mcp-servers/{serverId}/health-checks", a.admin(a.adminListMcpHealthChecks)},
		{"POST", "/v1/admin/mcp-servers/{serverId}/review", a.admin(a.adminReviewMcpServer)},
		{"PUT", "/v1/admin/mcp-servers/{serverId}/capabilities/{capabilityId}/approval", a.admin(a.adminApproveMcpCapability)},
		{"GET", "/v1/admin/settings/publishing", a.admin(a.adminGetPublishingSettings)},
		{"PUT", "/v1/admin/settings/publishing", a.admin(a.adminUpdatePublishingSettings)},
		{"GET", "/v1/admin/settings/network", a.admin(a.adminGetNetworkSettings)},
		{"PUT", "/v1/admin/settings/network", a.admin(a.adminUpdateNetworkSettings)},
		{"POST", "/v1/admin/settings/network/check", a.admin(a.adminCheckNetworkUrl)},
		{"GET", "/v1/admin/teams/{team}/publishing", a.admin(a.adminGetTeamPublishing)},
		{"PUT", "/v1/admin/teams/{team}/publishing", a.admin(a.adminUpdateTeamPublishing)},
	}
}

// serverListParams reads ?q=, ?cursor= and ?limit= (fetching one extra row
// to detect a next page).
func serverListParams(w http.ResponseWriter, r *http.Request) (registry.ListParams, int32, bool) {
	limit, ok := pageLimit(w, r)
	if !ok {
		return registry.ListParams{}, 0, false
	}
	q, ok := search(w, r)
	if !ok {
		return registry.ListParams{}, 0, false
	}
	keys, ok := decodeCursor(w, r, 2)
	if !ok {
		return registry.ListParams{}, 0, false
	}
	p := registry.ListParams{Search: q, Limit: limit + 1}
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

// serverPage cuts a fetched page to limit and returns its next cursor.
func serverPage(rows []registry.ServerView, limit int32) ([]registry.ServerView, *string) {
	if len(rows) <= int(limit) {
		return rows, nil
	}
	rows = rows[:limit]
	last := rows[len(rows)-1].Server
	return rows, encodeCursor(last.Name, last.ID.String())
}

func (a *api) writeServerPage(w http.ResponseWriter, r *http.Request, rows []registry.ServerView, err error, limit int32) {
	if failed(w, r, err) {
		return
	}
	rows, next := serverPage(rows, limit)
	page := apitypes.McpServerPage{Items: make([]apitypes.McpServer, len(rows)), NextCursor: next}
	for i, v := range rows {
		page.Items[i] = a.toAPIServer(v)
	}
	httpx.JSON(w, http.StatusOK, page)
}

// kindParam reads ?kind= (validated by the service).
func kindParam(r *http.Request) *string {
	if v := r.URL.Query().Get("kind"); v != "" {
		return &v
	}
	return nil
}

// failedRegistry renders a refresh that couldn't read the server as 502
// discovery_failed with the test result as details.
func failedRegistry(w http.ResponseWriter, r *http.Request, err error) bool {
	var de *registry.DiscoveryError
	if errors.As(err, &de) {
		err = de.AsAppError(toAPITestResult(de.Result))
	}
	return failed(w, r, err)
}

// decodeOptional reads an optional JSON body: none (or empty) is the zero value.
func decodeOptional[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var in T
	if r.Body == nil || r.ContentLength == 0 {
		return in, true
	}
	if r.ContentLength < 0 {
		// Unknown length: peek for an empty body.
		buf := make([]byte, 1)
		n, err := r.Body.Read(buf)
		if n == 0 && errors.Is(err, io.EOF) {
			return in, true
		}
		r.Body = struct {
			io.Reader
			io.Closer
		}{io.MultiReader(bytes.NewReader(buf[:n]), r.Body), r.Body}
	}
	return in, httpx.Decode(w, r, &in)
}

func (a *api) listTeamMcpServers(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := serverListParams(w, r)
	if !ok {
		return
	}
	rows, err := a.Registry.ListTeam(r.Context(), a.actor(r), r.PathValue("team"), p)
	a.writeServerPage(w, r, rows, err, limit)
}

func (a *api) createTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	var in apitypes.McpServerCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	ci := registry.CreateInput{Slug: in.Slug, Name: in.Name, URL: in.Url, Enabled: true}
	setIf(&ci.Description, in.Description)
	setIf(&ci.AuthHeaderName, in.AuthHeaderName)
	setIf(&ci.AuthValue, in.AuthValue)
	setIf(&ci.TimeoutSeconds, in.TimeoutSeconds)
	setIf(&ci.Enabled, in.Enabled)
	setIf(&ci.CapturePayloads, in.CapturePayloads)
	ci.Requirement = fromAPIRequirement(in.Requirement)
	if in.AuthMode != nil {
		ci.AuthMode = string(*in.AuthMode)
	}
	ci.OAuth, ci.SendIdentity = fromAPIOAuthInput(in.Oauth), in.SendIdentity
	res, err := a.Registry.Create(r.Context(), a.actor(r), r.PathValue("team"), ci)
	if failed(w, r, err) {
		return
	}
	out := apitypes.McpServerCreated{Server: a.toAPIServer(res.View)}
	if res.SetupRequired {
		yes := true
		out.SetupRequired = &yes
	}
	if res.Refresh != nil {
		rr := toAPIRefresh(*res.Refresh)
		out.Refresh = &rr
	}
	if res.Failure != nil {
		tr := toAPITestResult(*res.Failure)
		out.RefreshError = &tr
	}
	writeRevised(w, http.StatusCreated, res.View.Server.Revision, out)
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

func (a *api) getTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	v, err := a.Registry.GetTeam(r.Context(), a.actor(r), r.PathValue("team"), id)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Server.Revision, a.toAPIServer(v))
}

func (a *api) updateTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	in, keys, ok := decodeKeys[apitypes.McpServerUpdate](w, r)
	if !ok {
		return
	}
	if actor := a.actor(r); actor.IsToken() && !a.tokenMayUpdateServer(w, r, actor, id, in, keys) {
		return
	}
	_, setRequirement := keys["requirement"]
	v, err := a.Registry.Update(r.Context(), a.actor(r), r.PathValue("team"), id, registry.UpdateInput{
		Name: in.Name, Description: in.Description, URL: in.Url, AuthHeaderName: in.AuthHeaderName, AuthValue: in.AuthValue,
		TimeoutSeconds: in.TimeoutSeconds, Enabled: in.Enabled, SetRequirement: setRequirement, Requirement: fromAPIRequirement(in.Requirement),
		CapturePayloads: in.CapturePayloads, AuthMode: strPtr(in.AuthMode), OAuth: fromAPIOAuthInput(in.Oauth), SendIdentity: in.SendIdentity,
		RequiresPresentPerson: in.RequiresPresentPerson,
	}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Server.Revision, a.toAPIServer(v))
}

func (a *api) deleteTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	writeOK(w, r, a.Registry.Delete(r.Context(), a.actor(r), r.PathValue("team"), id))
}

func (a *api) testTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	res, err := a.Registry.Test(r.Context(), a.actor(r), r.PathValue("team"), id)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPITestResult(res))
}

func (a *api) refreshTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	res, err := a.Registry.Refresh(r.Context(), a.actor(r), r.PathValue("team"), id)
	if failedRegistry(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIRefresh(res))
}

func (a *api) listTeamMcpCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	caps, err := a.Registry.ListCapabilities(r.Context(), a.actor(r), r.PathValue("team"), id, kindParam(r))
	writeList(w, r, caps, err, toAPICapability)
}

func (a *api) approveTeamMcpCapability(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	in, ok := decodeOptional[apitypes.McpCapabilityApproval](w, r)
	if !ok {
		return
	}
	c, err := a.Registry.ApproveTeamCapability(r.Context(), a.actor(r), r.PathValue("team"), id, capID, in.ExpectedFingerprint)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPICapability(c))
}

func (a *api) listTeamMcpHealthChecks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	checks, err := a.Registry.HealthChecks(r.Context(), a.actor(r), r.PathValue("team"), id)
	writeList(w, r, checks, err, toAPIHealthCheck)
}

func (a *api) publishTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	in, ok := decodeOptional[apitypes.McpPublishRequest](w, r)
	if !ok {
		return
	}
	v, err := a.Registry.Publish(r.Context(), a.actor(r), r.PathValue("team"), id, in.Note, in.ExpectedDigest)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, a.toAPIServer(v))
}

func (a *api) unpublishTeamMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	v, err := a.Registry.Unpublish(r.Context(), a.actor(r), r.PathValue("team"), id)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, a.toAPIServer(v))
}

func (a *api) getTeamPublishing(w http.ResponseWriter, r *http.Request) {
	p, err := a.Registry.GetTeamPublishing(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPITeamPublishing(p))
}

func (a *api) listCatalogServers(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := serverListParams(w, r)
	if !ok {
		return
	}
	rows, err := a.Registry.ListCatalog(r.Context(), a.actor(r), p)
	if failed(w, r, err) {
		return
	}
	rows, next := serverPage(rows, limit)
	page := apitypes.CatalogServerPage{Items: make([]apitypes.CatalogServer, len(rows)), NextCursor: next}
	for i, v := range rows {
		page.Items[i] = toAPICatalogServer(v)
	}
	httpx.JSON(w, http.StatusOK, page)
}

func (a *api) getCatalogServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	c, err := a.Registry.GetCatalog(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	out := apitypes.CatalogServerDetail{Server: toAPICatalogServer(c.View), Capabilities: make([]apitypes.CatalogCapability, len(c.Capabilities))}
	for i, cp := range c.Capabilities {
		out.Capabilities[i] = toAPICatalogCapability(cp)
	}
	httpx.JSON(w, http.StatusOK, out)
}

var publishStates = map[string]bool{
	registry.StatePrivate: true, registry.StatePending: true, registry.StatePublished: true, registry.StateRejected: true,
}

func (a *api) adminListMcpServers(w http.ResponseWriter, r *http.Request) {
	p, limit, ok := serverListParams(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if v := q.Get("publishState"); v != "" {
		if !publishStates[v] {
			httpx.Error(w, http.StatusBadRequest, "invalid_publish_state", "publishState must be private, pending, published or rejected")
			return
		}
		p.PublishState = &v
	}
	if v := q.Get("changes"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_changes", "changes must be true or false")
			return
		}
		p.ChangesOnly = b
	}
	if v := q.Get("provider"); v != "" {
		pid, err := uuid.Parse(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_provider", "provider must be an auth provider ID")
			return
		}
		p.ProviderID = &pid
	}
	if v := q.Get("authMode"); v != "" {
		if v != registry.AuthNone && v != registry.AuthStaticHeader && v != registry.AuthOAuth {
			httpx.Error(w, http.StatusBadRequest, "invalid_auth_mode", "authMode must be none, static_header or oauth")
			return
		}
		p.AuthMode = &v
	}
	if v := q.Get("team"); v != "" {
		if len(v) > 100 {
			httpx.Error(w, http.StatusBadRequest, "invalid_team", "team must be a team slug or ID")
			return
		}
		p.Team = v
	}
	rows, err := a.Registry.AdminList(r.Context(), a.actor(r), p)
	a.writeServerPage(w, r, rows, err, limit)
}

func (a *api) adminGetMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	v, err := a.Registry.AdminGet(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Server.Revision, a.toAPIServer(v))
}

func (a *api) adminListMcpCapabilities(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	caps, err := a.Registry.AdminListCapabilities(r.Context(), a.actor(r), id, kindParam(r))
	writeList(w, r, caps, err, toAPICapability)
}

func (a *api) adminListMcpHealthChecks(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	checks, err := a.Registry.AdminHealthChecks(r.Context(), a.actor(r), id)
	writeList(w, r, checks, err, toAPIHealthCheck)
}

func (a *api) adminReviewMcpServer(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	var in apitypes.McpPublishReview
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Registry.Review(r.Context(), a.actor(r), id, string(in.Decision), in.Note, deref(in.ExpectedDigest))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, a.toAPIServer(v))
}

func (a *api) adminApproveMcpCapability(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	in, ok := decodeOptional[apitypes.McpCapabilityApproval](w, r)
	if !ok {
		return
	}
	c, err := a.Registry.ApproveCapability(r.Context(), a.actor(r), id, capID, in.ExpectedFingerprint)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPICapability(c))
}

func (a *api) adminGetPublishingSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Registry.GetSettings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPISettings(s))
}

func (a *api) adminUpdatePublishingSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.PublishingSettingsUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Registry.UpdateSettings(r.Context(), a.actor(r), string(in.DefaultPolicy), rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPISettings(s))
}

func (a *api) adminGetTeamPublishing(w http.ResponseWriter, r *http.Request) {
	p, err := a.Registry.AdminGetTeamPublishing(r.Context(), a.actor(r), r.PathValue("team"))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, p.TeamRevision, toAPITeamPublishing(p))
}

func (a *api) adminUpdateTeamPublishing(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.TeamPublishingUpdate](w, r)
	if !ok {
		return
	}
	p, err := a.Registry.SetTeamOverride(r.Context(), a.actor(r), r.PathValue("team"), (*string)(in.Override), rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, p.TeamRevision, toAPITeamPublishing(p))
}

func (a *api) adminGetNetworkSettings(w http.ResponseWriter, r *http.Request) {
	s, err := a.Registry.GetNetworkSettings(r.Context(), a.actor(r))
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPINetworkSettings(s))
}

func (a *api) adminUpdateNetworkSettings(w http.ResponseWriter, r *http.Request) {
	in, rev, ok := decodeRevised[apitypes.NetworkSettingsUpdate](w, r)
	if !ok {
		return
	}
	s, err := a.Registry.UpdateNetworkSettings(r.Context(), a.actor(r), fromAPINetworkEntries(in.Entries), rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, s.Revision, toAPINetworkSettings(s))
}

func (a *api) adminCheckNetworkUrl(w http.ResponseWriter, r *http.Request) {
	var in apitypes.NetworkCheckRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	res, err := a.Registry.CheckNetworkURL(r.Context(), a.actor(r), in.Url)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPINetworkCheck(res))
}
