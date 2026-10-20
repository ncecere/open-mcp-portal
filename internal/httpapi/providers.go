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
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
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

func toAPIProviderSummary(p registry.Provider) apitypes.AuthProviderSummary {
	return apitypes.AuthProviderSummary{Id: p.ID, Slug: p.Slug, Name: p.Name, Kind: apitypes.AuthProviderKindOauth2, Preset: presetName(p.Preset),
		DefaultScopes: p.DefaultScopes, LogoUrl: p.LogoURL}
}

func (a *api) toAPIAuthProvider(v providers.View) apitypes.AuthProvider {
	p := v.Provider
	return apitypes.AuthProvider{
		Id: p.ID, Slug: p.Slug, Name: p.Name, Kind: apitypes.AuthProviderKind(p.Kind), Preset: presetName(p.Preset), Enabled: p.Enabled,
		ClientId: p.ClientID, HasClientSecret: v.HasSecret(), ClientSecretHint: p.ClientSecretHint,
		TokenAuthMethod: apitypes.AuthProviderTokenAuthMethod(p.TokenAuthMethod), Pkce: p.Pkce,
		AuthorizationUrl: p.AuthorizationUrl, TokenUrl: p.TokenUrl, RevocationUrl: p.RevocationUrl, UserinfoUrl: p.UserinfoUrl,
		DefaultScopes: nonNilStrings(p.DefaultScopes), ScopeParam: p.ScopeParam,
		ScopeSeparator:       apitypes.AuthProviderScopeSeparator(p.ScopeSeparator),
		TokenResponseFormat:  apitypes.AuthProviderTokenResponseFormat(p.TokenResponseFormat),
		ExtraAuthorizeParams: v.ExtraParams, LogoUrl: p.LogoUrl, RedirectUri: a.Providers.RedirectURI(),
		ServerCount: v.ServerCount, ConnectionCount: v.ConnectionCount, Revision: p.Revision,
		CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt, CreatedByName: nonEmpty(v.CreatedByName),
	}
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func toAPIPreset(p providers.Preset) apitypes.AuthProviderPreset {
	params := make([]apitypes.AuthProviderUrlParameter, len(p.URLParameters))
	for i, u := range p.URLParameters {
		params[i] = apitypes.AuthProviderUrlParameter{Name: u.Name, Label: u.Label, Default: u.Default}
	}
	return apitypes.AuthProviderPreset{
		Preset: apitypes.AuthProviderPresetName(p.Preset), Name: p.Name, AuthorizationUrl: p.AuthorizationURL, TokenUrl: p.TokenURL,
		RevocationUrl: p.RevocationURL, UserinfoUrl: p.UserinfoURL, DefaultScopes: nonNilStrings(p.DefaultScopes),
		TokenAuthMethod: apitypes.AuthProviderTokenAuthMethod(p.TokenAuthMethod), Pkce: p.PKCE, ScopeParam: p.ScopeParam,
		ScopeSeparator:      apitypes.AuthProviderPresetScopeSeparator(p.ScopeSeparator),
		TokenResponseFormat: apitypes.AuthProviderTokenResponseFormat(p.RespFormat), ExtraAuthorizeParams: p.ExtraParams,
		UrlParameters: params, DocsUrl: p.DocsURL, Notes: nonEmpty(p.Notes),
	}
}

func toAPIProviderRef(p providers.ProviderRef) apitypes.ProviderRef {
	kind := apitypes.AuthProviderKind(p.Kind)
	if kind == "" {
		kind = apitypes.AuthProviderKindOauth2
	}
	out := apitypes.ProviderRef{Id: p.ID, Slug: p.Slug, Name: p.Name, Preset: presetName(p.Preset), LogoUrl: p.LogoURL, Kind: &kind}
	if p.Server != nil {
		out.Server = &apitypes.McpServerRef{Id: p.Server.ID, Slug: p.Server.Slug, Name: p.Server.Name, TeamSlug: p.Server.TeamSlug}
	}
	return out
}

// toAPIRegistryProviderRef is a platform provider as a reference.
func toAPIRegistryProviderRef(p registry.Provider) apitypes.ProviderRef {
	kind := apitypes.AuthProviderKind(p.Kind)
	return apitypes.ProviderRef{Id: p.ID, Slug: p.Slug, Name: p.Name, Preset: presetName(p.Preset), LogoUrl: p.LogoURL, Kind: &kind}
}

func toAPIConnection(c providers.Connection) apitypes.ProviderConnection {
	pc := c.Connection
	return apitypes.ProviderConnection{
		Id: pc.ID, Provider: toAPIProviderRef(c.Provider), AccountLabel: pc.AccountLabel, Scopes: nonNilStrings(pc.Scopes),
		Status: apitypes.ProviderConnectionStatus(pc.Status), ConnectedAt: pc.ConnectedAt, RefreshedAt: pc.RefreshedAt,
		LastUsedAt: pc.LastUsedAt, ExpiresAt: pc.ExpiresAt, Refreshable: c.Refreshable(), AllowedServers: toAPIGrants(c.Servers),
	}
}

func toAPIConnectServer(s providers.ServerRef) apitypes.ConnectServer {
	return apitypes.ConnectServer{Id: s.ID, Slug: s.Slug, Name: s.Name, TeamSlug: s.TeamSlug, TeamName: s.TeamName}
}

func toAPIGrants(gs []providers.ServerGrant) []apitypes.ProviderServerGrant {
	out := make([]apitypes.ProviderServerGrant, len(gs))
	for i, g := range gs {
		out[i] = apitypes.ProviderServerGrant{Server: toAPIConnectServer(g.Server), Origin: g.Origin, Scopes: nonNilStrings(g.Scopes),
			ConsentedAt: g.ConsentedAt}
	}
	return out
}

// toAPIRequirement is an effective requirement (nil: none). connected is
// only set in the caller's own views.
func toAPIRequirement(r *registry.Requirement, connected *bool) *apitypes.CapabilityRequirement {
	if r == nil {
		return nil
	}
	out := &apitypes.CapabilityRequirement{ProviderId: r.Provider.ID, ProviderSlug: r.Provider.Slug, ProviderName: r.Provider.Name,
		Scopes: nonNilStrings(r.Scopes), Connected: connected}
	if r.Provider.ServerBound() {
		k := apitypes.AuthProviderKindMcpServer
		out.ProviderKind = &k
	}
	return out
}

func toAPIServerRequirement(r *registry.ServerRequirement) *apitypes.McpServerRequirement {
	if r == nil {
		return nil
	}
	return &apitypes.McpServerRequirement{ProviderId: r.Provider.ID, ProviderSlug: r.Provider.Slug, ProviderName: r.Provider.Name,
		ProviderEnabled: r.Provider.Enabled, Scopes: nonNilStrings(r.Scopes)}
}

func fromAPIRequirement(in *apitypes.McpServerRequirementInput) *registry.RequirementInput {
	if in == nil {
		return nil
	}
	out := &registry.RequirementInput{ProviderID: in.ProviderId, Scopes: []string{}}
	if in.Scopes != nil {
		out.Scopes = *in.Scopes
	}
	return out
}

func (a *api) listAuthProviders(w http.ResponseWriter, r *http.Request) {
	ps, err := a.Providers.List(r.Context())
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
		ExtraParams: in.ExtraAuthorizeParams,
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

func (a *api) listMyConnections(w http.ResponseWriter, r *http.Request) {
	cs, err := a.Providers.ListMyConnections(r.Context(), a.actor(r))
	writeList(w, r, cs, err, toAPIConnection)
}

func (a *api) revokeMyConnection(w http.ResponseWriter, r *http.Request) {
	id, ok := pathUUID(w, r, "connectionId")
	if !ok {
		return
	}
	writeOK(w, r, a.Providers.RevokeMine(r.Context(), a.actor(r), id))
}

// connectLimited counts one attempt of a connect operation against the
// person's limit; it answers 429 slow_down and returns false when it is
// used up.
func (a *api) connectLimited(w http.ResponseWriter, r *http.Request, key string, limit int, message string) bool {
	id, _ := auth.FromContext(r.Context())
	ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, key+":"+id.User.ID.String(), limit)
	if failed(w, r, err) {
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
		httpx.Error(w, http.StatusTooManyRequests, "slow_down", message)
		return false
	}
	return true
}

func (a *api) listAllowableServers(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	vs, err := a.Providers.ListAllowable(r.Context(), a.actor(r), connID)
	writeList(w, r, vs, err, func(v providers.Allowable) apitypes.AllowableServer {
		return apitypes.AllowableServer{Server: toAPIConnectServer(v.Server), Origin: v.Origin, Scopes: nonNilStrings(v.Scopes),
			Covered: v.Covered, Allowed: v.Allowed}
	})
}

// browserOnly answers 403 session_required unless the call is the web
// app's (a browser session): allowing a server is a person's own decision,
// never an API key's, an automation token's or an agent's.
func (a *api) browserOnly(w http.ResponseWriter, r *http.Request) bool {
	if id, _ := auth.FromContext(r.Context()); id.SessionID == "" {
		httpx.Error(w, http.StatusForbidden, "session_required", "Do this from the web app")
		return false
	}
	return true
}

func (a *api) allowConnectionServer(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "connect-allow", connectAllowsPerMinute, "Too many attempts to allow servers. Try again shortly.") {
		return
	}
	var in apitypes.AllowServerRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	c, err := a.Providers.AllowServer(r.Context(), a.actor(r), connID, providers.AllowInput{ServerID: in.ServerId, Origin: in.Origin, Scopes: in.Scopes})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectConfirmed{Provider: toAPIProviderRef(c.Provider), Server: toAPIConnectServer(c.Server),
		Scopes: nonNilStrings(c.Scopes)})
}

func (a *api) revokeAllowedServer(w http.ResponseWriter, r *http.Request) {
	connID, ok := pathUUID(w, r, "connectionId")
	if !ok {
		return
	}
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok || !a.browserOnly(w, r) {
		return
	}
	if !a.connectLimited(w, r, "connect-allow", connectAllowsPerMinute, "Too many attempts to change allowed servers. Try again shortly.") {
		return
	}
	writeOK(w, r, a.Providers.RevokeServer(r.Context(), a.actor(r), connID, serverID))
}

func (a *api) startMyConnection(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !a.connectLimited(w, r, "connect-start", connectStartsPerMinute, "Too many attempts to connect. Try again shortly.") {
		return
	}
	var in apitypes.ConnectStart
	if !httpx.Decode(w, r, &in) {
		return
	}
	// An oauth server's own sign-in without a consent link: only for people
	// who can use one of the server's capabilities through a gateway now.
	allowed := false
	if in.RequestId == nil {
		if p, err := a.q.GetAuthProvider(r.Context(), in.ProviderId); err == nil && p.ServerID.Valid {
			if allowed, err = a.Gateways.UsesServer(r.Context(), id.User, p.ServerID.UUID); failed(w, r, err) {
				return
			}
		}
	}
	st, err := a.Providers.Start(r.Context(), a.actor(r), providers.StartInput{
		ProviderID: in.ProviderId, RequestID: in.RequestId, ReturnTo: in.ReturnTo, Scopes: in.Scopes, SessionID: id.SessionID,
		ServerBoundAllowed: allowed,
	})
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectStarted{AuthorizeUrl: st.AuthorizeURL, Scopes: st.Scopes, ExpiresAt: st.ExpiresAt})
}

func (a *api) confirmConnectRequest(w http.ResponseWriter, r *http.Request) {
	if id, _ := auth.FromContext(r.Context()); id.SessionID == "" {
		httpx.Error(w, http.StatusForbidden, "session_required", "Confirm from the web app")
		return
	}
	c, err := a.Providers.ConfirmRequest(r.Context(), a.actor(r), r.PathValue("requestId"))
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectConfirmed{Provider: toAPIProviderRef(c.Provider), Server: toAPIConnectServer(c.Server),
		Scopes: nonNilStrings(c.Scopes)})
}

func (a *api) getConnectRequest(w http.ResponseWriter, r *http.Request) {
	v, err := a.Providers.GetRequest(r.Context(), a.actor(r), r.PathValue("requestId"))
	if failed(w, r, err) {
		return
	}
	req := v.Request
	var server *apitypes.ConnectServer
	if v.Server != nil {
		sv := toAPIConnectServer(*v.Server)
		server = &sv
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectRequest{Server: server,
		Id: v.ID, Provider: toAPIProviderRef(v.Provider), Reason: apitypes.ConnectRequestReason(v.Reason),
		RequiredScopes: nonNilStrings(req.RequiredScopes), RequestScopes: v.RequestScopes, GrantedScopes: v.Granted,
		AccountLabel: v.AccountLabel, Gateway: apitypes.CallRef{Id: req.GatewayID, Slug: v.GatewaySlug, Name: v.GatewayName, Exists: v.GatewayExists},
		Capability: apitypes.ConnectRequestCapability{Kind: apitypes.GatewayCapabilityKind(req.CapabilityKind), ExposedName: req.ExposedName,
			Title: req.CapabilityTitle},
		CreatedAt: req.CreatedAt, ExpiresAt: req.ExpiresAt, AuthorizationServerHost: optStr(v.AuthorizationServerHost),
	})
}

func (a *api) setTeamMcpCapabilityRequirement(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	capID, ok := pathUUID(w, r, "capabilityId")
	if !ok {
		return
	}
	in, rev, ok := decodeRevised[apitypes.CapabilityRequirementOverride](w, r)
	if !ok {
		return
	}
	c, revision, err := a.Registry.SetCapabilityRequirement(r.Context(), a.actor(r), r.PathValue("team"), serverID, capID,
		registry.OverrideInput{Mode: string(in.Mode), Scopes: in.Scopes}, rev)
	if failed(w, r, err) {
		return
	}
	writeRevised(w, http.StatusOK, revision, toAPICapability(c))
}

// connectCallback is where providers send the browser back. It always
// answers 303 to a same-origin path: the return path of the request, or the
// web app's /connect/done with the result. Never a token or the provider's
// own words.
func (a *api) connectCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if len(r.URL.RawQuery) > 8000 {
		http.Redirect(w, r, providers.DonePath+"?result="+providers.ResultExpired, http.StatusSeeOther)
		return
	}
	q := r.URL.Query()
	in := providers.CallbackInput{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error"), Iss: q.Get("iss"),
		RequestID: httpx.RequestID(r.Context()), ClientIP: httpx.ClientIP(r, a.Config.TrustedProxies)}
	id, ok, err := a.Auth.SessionIdentity(r)
	if err != nil {
		a.Log.ErrorContext(r.Context(), "connect callback session", "err", err, "request_id", in.RequestID)
	} else if ok {
		in.SessionID, in.User = id.SessionID, id.User
	}
	to, err := a.Providers.Callback(r.Context(), in)
	if err != nil {
		if !errors.Is(err, r.Context().Err()) {
			a.Log.ErrorContext(r.Context(), "connect callback", "err", err, "request_id", in.RequestID)
		}
		to = providers.DonePath + "?result=" + providers.ResultError
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}
