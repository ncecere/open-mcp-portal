package httpapi

import (
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

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
		if v != registry.AuthNone && v != registry.AuthStaticHeader && v != registry.AuthOAuth && v != registry.AuthPersonSecret && v != registry.AuthMachineOAuth {
			httpx.Error(w, http.StatusBadRequest, "invalid_auth_mode", "authMode must be none, static_header, oauth, person_secret or machine_oauth")
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
