// Delegated credentials (api/openapi.yaml, tags auth-providers and
// connections; docs/phase5-delegated-credentials.md): auth providers,
// people's connected accounts, consent links, and capability requirement
// overrides. GET /connect/callback (the providers' redirect back) is a
// browser route outside the contract, like /oauth/*; /connect/{provider}
// and /connect/done are pages of the web app.

package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/providers"
)

// connectStartsPerMinute bounds POST /v1/me/connections/start per person.
const connectStartsPerMinute = 20

// connectAllowsPerMinute bounds allowing and taking back a server's
// allowance (POST .../allow-server, DELETE .../allowed-servers/{serverId})
// per person, as connectStartsPerMinute does for connecting.
const connectAllowsPerMinute = 20

// providerRoutes: auth providers, connections, consent links and the
// providers' callback.
func (a *api) providerRoutes() []route {
	const admin = "/v1/admin/auth-providers"
	return []route{
		{"GET", "/v1/auth-providers", a.session(a.listAuthProviders)},
		{"GET", admin, a.admin(a.adminListAuthProviders)},
		{"POST", admin, a.admin(a.adminCreateAuthProvider)},
		{"GET", admin + "/{providerId}", a.admin(a.adminGetAuthProvider)},
		{"PATCH", admin + "/{providerId}", a.admin(a.adminUpdateAuthProvider)},
		{"DELETE", admin + "/{providerId}", a.admin(a.adminDeleteAuthProvider)},
		{"GET", admin + "/{providerId}/access", a.admin(a.adminGetAuthProviderAccess)},
		{"PUT", admin + "/{providerId}/access", a.admin(a.adminSetAuthProviderAccess)},
		{"GET", "/v1/admin/auth-provider-presets", a.admin(a.adminListAuthProviderPresets)},
		{"GET", "/v1/admin/users/{userId}/connections", a.admin(a.adminListUserConnections)},
		{"DELETE", "/v1/admin/users/{userId}/connections/{connectionId}", a.admin(a.adminRevokeUserConnection)},
		{"GET", "/v1/me/connections", a.session(a.listMyConnections)},
		{"POST", "/v1/me/connections/start", a.session(a.startMyConnection)},
		{"DELETE", "/v1/me/connections/{connectionId}", a.session(a.revokeMyConnection)},
		{"GET", "/v1/me/connections/{connectionId}/allowable-servers", a.session(a.listAllowableServers)},
		{"POST", "/v1/me/connections/{connectionId}/allow-server", a.session(a.allowConnectionServer)},
		{"DELETE", "/v1/me/connections/{connectionId}/allowed-servers/{serverId}", a.session(a.revokeAllowedServer)},
		{"GET", "/v1/connect/requests/{requestId}", a.session(a.getConnectRequest)},
		{"POST", "/v1/connect/requests/{requestId}/confirm", a.session(a.confirmConnectRequest)},
		{"PUT", "/v1/teams/{team}/mcp-servers/{serverId}/capabilities/{capabilityId}/requirement", a.session(a.setTeamMcpCapabilityRequirement)},
		{"GET", providers.CallbackPath, http.HandlerFunc(a.connectCallback)},
	}
}

// decodeKeys reads a JSON body into in (strictly, as httpx.Decode) and
// also returns its top-level keys, so null can be told from absent.
func decodeKeys[T any](w http.ResponseWriter, r *http.Request) (T, map[string]json.RawMessage, bool) {
	var in T
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, httpx.MaxBodyBytes))
	if err != nil {
		httpx.Error(w, http.StatusRequestEntityTooLarge, "body_too_large", "Request body is too large")
		return in, nil, false
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if !httpx.Decode(w, r, &in) {
		return in, nil, false
	}
	keys := map[string]json.RawMessage{}
	_ = json.Unmarshal(body, &keys)
	return in, keys, true
}

// isNull reports whether a key was sent as null.
func isNull(keys map[string]json.RawMessage, k string) bool {
	v, ok := keys[k]
	return ok && string(bytes.TrimSpace(v)) == "null"
}

func presetName(p *string) *apitypes.AuthProviderPresetName {
	return (*apitypes.AuthProviderPresetName)(p)
}

func (a *api) listAuthProviders(w http.ResponseWriter, r *http.Request) {
	if serviceTeam := r.URL.Query().Get("serviceTeam"); serviceTeam != "" {
		if !a.browserOnly(w, r) {
			return
		}
		if r.URL.Query().Get("team") != "" || r.URL.Query().Get("serverId") != "" {
			httpx.Error(w, 400, "invalid_filter", "serviceTeam cannot be combined with team or serverId")
			return
		}
		ps, err := a.Providers.ServicePickable(r.Context(), a.actor(r), serviceTeam)
		writeList(w, r, ps, err, toAPIProviderSummary)
		return
	}
	team := r.URL.Query().Get("team")
	if team == "" {
		ps, err := a.Providers.List(r.Context())
		writeList(w, r, ps, err, toAPIProviderSummary)
		return
	}
	// The picker of a team's server: only what the team (or the server) may
	// require. The caller must be able to see the team.
	var serverID uuid.UUID
	if v := r.URL.Query().Get("serverId"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.Error(w, http.StatusBadRequest, "invalid_id", "serverId must be a UUID")
			return
		}
		serverID = id
	}
	ta, err := a.Teams.Get(r.Context(), a.actor(r), team)
	if failed(w, r, err) {
		return
	}
	ps, err := a.Providers.Pickable(r.Context(), ta.Team.ID, serverID)
	writeList(w, r, ps, err, toAPIProviderSummary)
}

func (a *api) adminListAuthProviders(w http.ResponseWriter, r *http.Request) {
	vs, err := a.Providers.AdminList(r.Context(), a.actor(r))
	writeList(w, r, vs, err, a.toAPIAuthProvider)
}

func (a *api) adminGetAuthProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "providerId")
	if !ok {
		return
	}
	v, err := a.Providers.AdminGet(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Provider.Revision, a.toAPIAuthProvider(v))
}

func strPtr[T ~string](p *T) *string {
	if p == nil {
		return nil
	}
	s := string(*p)
	return &s
}

func (a *api) adminCreateAuthProvider(w http.ResponseWriter, r *http.Request) {
	var in apitypes.AuthProviderCreate
	if !httpx.Decode(w, r, &in) {
		return
	}
	v, err := a.Providers.Create(r.Context(), a.actor(r), providers.CreateInput{
		Slug: in.Slug, Name: in.Name, ClientID: in.ClientId, Preset: strPtr(in.Preset), Enabled: in.Enabled, ClientSecret: in.ClientSecret,
		TokenAuthMethod: strPtr(in.TokenAuthMethod), PKCE: in.Pkce, AuthorizationURL: in.AuthorizationUrl, TokenURL: in.TokenUrl,
		RevocationURL: in.RevocationUrl, UserinfoURL: in.UserinfoUrl, LogoURL: in.LogoUrl, DefaultScopes: in.DefaultScopes,
		ScopeParam: in.ScopeParam, ScopeSeparator: strPtr(in.ScopeSeparator), RespFormat: strPtr(in.TokenResponseFormat),
		ExtraParams: in.ExtraAuthorizeParams, NarrowOnRefresh: in.NarrowOnRefresh,
	})
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusCreated, v.Provider.Revision, a.toAPIAuthProvider(v))
}

func (a *api) adminUpdateAuthProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "providerId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	in, keys, ok := decodeKeys[apitypes.AuthProviderUpdate](w, r)
	if !ok {
		return
	}
	v, err := a.Providers.Update(r.Context(), a.actor(r), id, providers.UpdateInput{
		Name: in.Name, ClientID: in.ClientId, ClientSecret: in.ClientSecret, TokenAuthMethod: strPtr(in.TokenAuthMethod),
		Preset: strPtr(in.Preset), ClearPreset: isNull(keys, "preset"), Enabled: in.Enabled, PKCE: in.Pkce,
		AuthorizationURL: in.AuthorizationUrl, TokenURL: in.TokenUrl, RevocationURL: in.RevocationUrl, UserinfoURL: in.UserinfoUrl,
		ClearRevocationURL: isNull(keys, "revocationUrl"), ClearUserinfoURL: isNull(keys, "userinfoUrl"),
		ClearLogoURL: isNull(keys, "logoUrl"), LogoURL: in.LogoUrl, DefaultScopes: in.DefaultScopes, ScopeParam: in.ScopeParam,
		ScopeSeparator: strPtr(in.ScopeSeparator), RespFormat: strPtr(in.TokenResponseFormat), ExtraParams: in.ExtraAuthorizeParams,
		NarrowOnRefresh: in.NarrowOnRefresh,
	}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, v.Provider.Revision, a.toAPIAuthProvider(v))
}

func (a *api) adminDeleteAuthProvider(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "providerId")
	if !ok {
		return
	}
	writeOK(w, r, a.Providers.Delete(r.Context(), a.actor(r), id))
}

func (a *api) adminGetAuthProviderAccess(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "providerId")
	if !ok {
		return
	}
	ac, err := a.Providers.AdminAccess(r.Context(), a.actor(r), id)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, ac.Provider.Revision, toAPIAccess(ac))
}

func (a *api) adminSetAuthProviderAccess(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "providerId")
	if !ok {
		return
	}
	rev, ok := ifMatch(w, r)
	if !ok {
		return
	}
	var in apitypes.AuthProviderAccessInput
	if !httpx.Decode(w, r, &in) {
		return
	}
	ac, err := a.Providers.SetAccess(r.Context(), a.actor(r), id, providers.AccessInput{Mode: string(in.AccessMode),
		TeamIDs: in.TeamIds, ServerIDs: in.ServerIds}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, ac.Provider.Revision, toAPIAccess(ac))
}

func (a *api) adminListAuthProviderPresets(w http.ResponseWriter, r *http.Request) {
	redirect := a.Providers.RedirectURI()
	writeList(w, r, providers.Presets, nil, func(p providers.Preset) apitypes.AuthProviderPreset {
		out := toAPIPreset(p)
		out.RedirectUri = &redirect
		return out
	})
}

func (a *api) adminListUserConnections(w http.ResponseWriter, r *http.Request) {
	userID, ok := pathUUID(w, r, "userId")
	if !ok {
		return
	}
	cs, err := a.Providers.AdminListConnections(r.Context(), a.actor(r), userID)
	writeList(w, r, cs, err, toAPIConnection)
}

func (a *api) adminRevokeUserConnection(w http.ResponseWriter, r *http.Request) {
	var userID, id uuid.UUID
	var ok bool
	if userID, ok = pathUUID(w, r, "userId"); !ok {
		return
	}
	if id, ok = pathUUID(w, r, "connectionId"); !ok {
		return
	}
	writeOK(w, r, a.Providers.AdminRevoke(r.Context(), a.actor(r), userID, id))
}
