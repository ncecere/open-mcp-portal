// Upstream OAuth (docs/phase7-upstream-oauth.md): detecting how an MCP
// server signs people in, the setup sign-in of a server in oauth mode, and
// the gateway's own Client ID Metadata Document as an OAuth client of
// upstream servers (GET /oauth/upstream-client-metadata.json, outside the
// contract like the other /oauth/ routes).

package httpapi

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/ratelimit"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// detectsPerMinute bounds detect-auth per person.
const detectsPerMinute = 10

// identityDefaultsPerMinute bounds the identity-default lookup per person
// (the add form asks as the URL is typed).
const identityDefaultsPerMinute = 30

func (a *api) upstreamOAuthRoutes() []route {
	return []route{
		{"POST", "/v1/teams/{team}/mcp-servers/detect-auth", a.session(a.detectTeamMcpServerAuth)},
		{"POST", "/v1/teams/{team}/mcp-servers/identity-default", a.session(a.getTeamMcpServerIdentityDefault)},
		{"POST", "/v1/teams/{team}/mcp-servers/{serverId}/oauth/authorize-setup", a.session(a.authorizeTeamMcpServerSetup)},
		{"GET", registry.CIMDPath, http.HandlerFunc(a.upstreamClientMetadata)},
	}
}

// slowDown answers 429 slow_down when a per-person limit is reached.
func (a *api) slowDown(w http.ResponseWriter, r *http.Request, bucket string, limit int) bool {
	ok, wait, err := ratelimit.Allow(r.Context(), a.limiter, bucket, limit)
	if failed(w, r, err) {
		return true
	}
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(ratelimit.RetryAfter(wait)))
		httpx.Error(w, http.StatusTooManyRequests, "slow_down", "Too many attempts. Try again shortly.")
		return true
	}
	return false
}

func (a *api) detectTeamMcpServerAuth(w http.ResponseWriter, r *http.Request) {
	// 10 a minute per person, and per automation token (never one shared
	// bucket for every token).
	who := a.actor(r).UserID.String()
	if actor := a.actor(r); actor.IsToken() {
		who = "token:" + actor.TokenID.String()
	}
	if a.slowDown(w, r, "detect-auth:"+who, detectsPerMinute) {
		return
	}
	var in apitypes.DetectAuthRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	d, err := a.Registry.DetectAuth(r.Context(), a.actor(r), r.PathValue("team"), in.Url)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, toAPIDetection(d))
}

func (a *api) getTeamMcpServerIdentityDefault(w http.ResponseWriter, r *http.Request) {
	// Session only (no token scope): the limit is per person.
	if a.slowDown(w, r, "identity-default:"+a.actor(r).UserID.String(), identityDefaultsPerMinute) {
		return
	}
	var in apitypes.DetectAuthRequest
	if !httpx.Decode(w, r, &in) {
		return
	}
	d, err := a.Registry.IdentityDefault(r.Context(), a.actor(r), r.PathValue("team"), in.Url)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.IdentityDefault{Basis: apitypes.IdentityDefaultBasis(d.Basis), SendIdentity: d.SendIdentity})
}

func (a *api) authorizeTeamMcpServerSetup(w http.ResponseWriter, r *http.Request) {
	serverID, ok := pathUUID(w, r, "serverId")
	if !ok {
		return
	}
	id, _ := auth.FromContext(r.Context())
	if id.SessionID == "" {
		httpx.Error(w, http.StatusForbidden, "session_required", "Sign in from the web app")
		return
	}
	// Shared with startMyConnection.
	if a.slowDown(w, r, "connect-start:"+id.User.ID.String(), connectStartsPerMinute) {
		return
	}
	in, ok := decodeOptional[apitypes.OAuthSetupStart](w, r)
	if !ok {
		return
	}
	sv, p, teamSlug, err := a.Registry.OAuthServer(r.Context(), a.actor(r), r.PathValue("team"), serverID)
	if failed(w, r, err) {
		return
	}
	st, err := a.Providers.SetupStart(r.Context(), a.actor(r), sv, p, teamSlug, in.ReturnTo, id.SessionID)
	if failed(w, r, err) {
		return
	}
	httpx.JSON(w, http.StatusOK, apitypes.ConnectStarted{AuthorizeUrl: st.AuthorizeURL, Scopes: st.Scopes, ExpiresAt: st.ExpiresAt})
}

// upstreamClientMetadata is the gateway's Client ID Metadata Document as
// an OAuth client of upstream MCP servers (registration cimd): a public
// client whose client_id is this document's URL.
func (a *api) upstreamClientMetadata(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"client_id": a.Registry.ClientMetadataURL(), "client_name": a.Registry.InstanceName(), "client_uri": a.Config.AppURL,
		"redirect_uris": []string{a.Registry.RedirectURI()}, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none",
	})
}

func optStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func toAPIDetection(d registry.Detection) apitypes.DetectAuthResult {
	res := d.Result
	out := apitypes.DetectAuthResult{Url: res.URL, Outcome: apitypes.DetectAuthOutcome(res.Outcome), SuggestedUrl: optStr(res.SuggestedURL),
		SuggestedScopes: nonNilStrings(res.SuggestedScopes), Problems: []apitypes.DetectAuthProblem{}, Steps: []apitypes.DetectAuthStep{}}
	if res.HTTPStatus > 0 {
		st := int32(res.HTTPStatus)
		out.HttpStatus = &st
	}
	if c := res.Challenge; c != nil {
		out.Challenge = &apitypes.DetectAuthChallenge{Scheme: c.Scheme, ResourceMetadataUrl: optStr(c.ResourceMetadata()), Scope: c.Scopes(),
			Error: optStr(c.Error())}
	}
	if m := res.Resource; m != nil {
		out.ResourceMetadata = &apitypes.DetectAuthResourceMetadata{Url: m.URL, Resource: m.Resource, ResourceName: optStr(m.ResourceName),
			AuthorizationServers: nonNilStrings(m.AuthorizationServers), ScopesSupported: nonNilStrings(m.ScopesSupported),
			BearerMethodsSupported: nonNilStrings(m.BearerMethods)}
	}
	if m := res.Server; m != nil {
		out.AuthorizationServer = &apitypes.DetectAuthServerMetadata{Issuer: m.Issuer, MetadataUrl: m.MetadataURL,
			AuthorizationEndpoint: m.AuthorizationEndpoint, TokenEndpoint: m.TokenEndpoint, RevocationEndpoint: optStr(m.RevocationEndpoint),
			RegistrationEndpoint: optStr(m.RegistrationEndpoint), ScopesSupported: nonNilStrings(m.ScopesSupported),
			CodeChallengeMethodsSupported: nonNilStrings(m.CodeChallengeMethods), TokenEndpointAuthMethodsSupported: nonNilStrings(m.TokenEndpointAuthMethods),
			GrantTypesSupported: nonNilStrings(m.GrantTypesSupported), IssParameterSupported: m.IssParameterSupported,
			ClientIdMetadataDocumentSupported: m.CIMDSupported}
	}
	out.MachineOAuth = toAPIMachineDetection(d.Machine)
	if g := d.Registration; g != nil {
		reg := &apitypes.DetectAuthRegistration{Recommended: apitypes.McpServerOAuthRegistration(g.Recommended), RedirectUri: g.RedirectURI,
			ClientMetadataUrl: g.ClientMetadataURL, Options: []apitypes.McpServerOAuthRegistration{}, MatchingProviders: []apitypes.ProviderRef{}}
		for _, o := range g.Options {
			reg.Options = append(reg.Options, apitypes.McpServerOAuthRegistration(o))
		}
		for _, p := range g.Matching {
			reg.MatchingProviders = append(reg.MatchingProviders, toAPIRegistryProviderRef(p))
		}
		if g.CIMDUnavailable != "" {
			why := apitypes.DetectAuthRegistrationCimdUnavailableReason(g.CIMDUnavailable)
			reg.CimdUnavailableReason = &why
		}
		out.Registration = reg
	}
	for _, p := range res.Problems {
		out.Problems = append(out.Problems, apitypes.DetectAuthProblem{Code: apitypes.DetectAuthProblemCode(p.Code), Blocking: p.Blocking,
			Message: p.Message})
	}
	for _, s := range res.Steps {
		step := apitypes.DetectAuthStep{Purpose: apitypes.DetectAuthStepPurpose(s.Purpose), Url: s.URL,
			Result: apitypes.DetectAuthStepResult(s.Result), LatencyMs: s.Latency.Milliseconds()}
		if s.HTTPStatus > 0 {
			st := int32(s.HTTPStatus)
			step.HttpStatus = &st
		}
		out.Steps = append(out.Steps, step)
	}
	return out
}

// fromAPIOAuthInput is a server's sign-in input.
func fromAPIOAuthInput(in *apitypes.McpServerOAuthInput) *registry.OAuthInput {
	if in == nil {
		return nil
	}
	out := &registry.OAuthInput{AuthorizationServer: in.AuthorizationServer, ClientID: in.ClientId, ClientSecret: in.ClientSecret,
		PlatformProviderID: in.PlatformProviderId, SendResource: in.SendResource, Registration: strPtr(in.Registration),
		TokenAuthMethod: strPtr(in.TokenAuthMethod)}
	if in.Scopes != nil {
		scopes := []string(*in.Scopes)
		out.Scopes = &scopes
	}
	return out
}
