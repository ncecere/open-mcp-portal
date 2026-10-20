package httpapi

import (
	"net/http"

	"github.com/ncecere/open-mcp-portal/internal/agentidentity"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
)

// Trusted agent platforms and the relay marks of service accounts
// (api/openapi.yaml, tag agent-platforms; docs/agent-platforms.md). Every
// operation is session-only: none carries x-omp-token-scopes, so automation
// tokens answer 403 token_not_allowed (decision 58: tokens never decide
// trust), and internal/agentidentity refuses a token actor again.

func (a *api) agentPlatformRoutes() []route {
	const base = "/v1/admin/agent-platforms"
	const one = base + "/{platformId}"
	return []route{
		{"GET", base, a.admin(a.adminListAgentPlatforms)},
		{"POST", base, a.admin(a.adminCreateAgentPlatform)},
		{"GET", one, a.admin(a.adminGetAgentPlatform)},
		{"PATCH", one, a.admin(a.adminUpdateAgentPlatform)},
		{"DELETE", one, a.admin(a.adminDeleteAgentPlatform)},
		{"POST", one + "/test", a.admin(a.adminTestAgentPlatform)},
		{"GET", one + "/relays", a.admin(a.adminListAgentPlatformRelays)},
		{"PUT", one + "/relays/{serviceAccountId}", a.admin(a.adminSetServiceAccountRelay)},
		{"DELETE", one + "/relays/{serviceAccountId}", a.admin(a.adminClearServiceAccountRelay)},
	}
}

func toAPIAgentPlatform(v agentidentity.View) apitypes.AgentPlatform {
	p := v.Platform
	out := apitypes.AgentPlatform{Id: p.ID, Name: p.Name, Issuer: p.Issuer, JwksUrl: p.JwksUrl, Audience: p.Audience, Enabled: p.Enabled,
		RelayCount: v.RelayCount, KeyIds: nonNilStrings(p.JwksKeyIds), Revision: p.Revision, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt}
	if p.JwksCheckedAt != nil && p.JwksOk != nil {
		out.LastFetch = &apitypes.AgentPlatformFetch{At: *p.JwksCheckedAt, Ok: *p.JwksOk, Error: p.JwksError}
	}
	return out
}

func toAPIRelay(r agentidentity.Relay) apitypes.AgentPlatformRelay {
	sa := r.Account
	return apitypes.AgentPlatformRelay{ServiceAccountId: sa.ID, Name: sa.Name, TeamId: sa.TeamID, TeamSlug: r.TeamSlug, TeamName: r.TeamName,
		Role: apitypes.ServiceAccountRole(sa.Role), Enabled: sa.Enabled, MarkedAt: sa.RelayMarkedAt}
}

func (a *api) writeAgentPlatform(w http.ResponseWriter, r *http.Request, status int, v agentidentity.View, err error) {
	if failed(w, r, err) {
		return
	}
	writeRevised(w, status, v.Platform.Revision, toAPIAgentPlatform(v))
}

func (a *api) adminListAgentPlatforms(w http.ResponseWriter, r *http.Request) {
	rows, err := a.AgentPlatforms.List(r.Context(), a.actor(r))
	writeList(w, r, rows, err, toAPIAgentPlatform)
}

func (a *api) adminCreateAgentPlatform(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AgentPlatformCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.AgentPlatforms.Create(r.Context(), a.actor(r), agentidentity.Input{Name: &in.Name, Issuer: &in.Issuer, JWKSURL: in.JwksUrl,
		Audience: in.Audience, Enabled: in.Enabled})
	a.writeAgentPlatform(w, r, http.StatusCreated, v, err)
}

func (a *api) adminGetAgentPlatform(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	v, err := a.AgentPlatforms.Get(r.Context(), a.actor(r), id)
	a.writeAgentPlatform(w, r, http.StatusOK, v, err)
}

func (a *api) adminUpdateAgentPlatform(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.AgentPlatformUpdate](w, r)
	if !ok {
		return
	}
	v, err := a.AgentPlatforms.Update(r.Context(), a.actor(r), id, agentidentity.Input{Name: in.Name, Issuer: in.Issuer, JWKSURL: in.JwksUrl,
		Audience: in.Audience, Enabled: in.Enabled}, rev)
	a.writeAgentPlatform(w, r, http.StatusOK, v, err)
}

func (a *api) adminDeleteAgentPlatform(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	writeOK(w, r, a.AgentPlatforms.Delete(r.Context(), a.actor(r), id))
}

func (a *api) adminTestAgentPlatform(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	res, err := a.AgentPlatforms.Test(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	out := apitypes.AgentPlatformTestResult{Ok: res.OK, KeyIds: nonNilStrings(res.KeyIDs), CheckedAt: res.CheckedAt, LatencyMs: res.Latency.Milliseconds()}
	if res.Error != "" {
		out.Error = &res.Error
	}
	if res.HTTPCode > 0 {
		out.HttpStatus = &res.HTTPCode
	}
	if res.OK {
		secs := int64(res.CacheFor.Seconds())
		out.CacheSeconds = &secs
	}
	httpx.JSON(w, http.StatusOK, out)
}

func (a *api) adminListAgentPlatformRelays(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	rows, err := a.AgentPlatforms.Relays(r.Context(), a.actor(r), id)
	writeList(w, r, rows, err, toAPIRelay)
}

func (a *api) adminSetServiceAccountRelay(w http.ResponseWriter, r *http.Request) {
	platformID, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	accountID, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	rel, err := a.AgentPlatforms.SetRelay(r.Context(), a.actor(r), platformID, accountID)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIRelay(rel))
}

func (a *api) adminClearServiceAccountRelay(w http.ResponseWriter, r *http.Request) {
	platformID, ok := pathUUID(w, r, "platformId")
	if !ok {
		return
	}
	accountID, ok := pathUUID(w, r, "serviceAccountId")
	if !ok {
		return
	}
	writeOK(w, r, a.AgentPlatforms.ClearRelay(r.Context(), a.actor(r), platformID, accountID))
}
