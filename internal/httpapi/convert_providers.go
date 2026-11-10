package httpapi

import (
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/providers"
	"github.com/ncecere/open-mcp-portal/internal/registry"
)

func toAPIProviderSummary(p registry.Provider) apitypes.AuthProviderSummary {
	return apitypes.AuthProviderSummary{Id: p.ID, Slug: p.Slug, Name: p.Name, Kind: apitypes.AuthProviderKind(p.Kind), Preset: presetName(p.Preset),
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
		ScopeSeparator:      apitypes.AuthProviderScopeSeparator(p.ScopeSeparator),
		TokenResponseFormat: apitypes.AuthProviderTokenResponseFormat(p.TokenResponseFormat),
		AccessMode:          apitypes.AuthProviderAccessMode(p.AccessMode), NarrowOnRefresh: p.NarrowOnRefresh,
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
		UrlParameters: params, DocsUrl: p.DocsURL, Notes: nonEmpty(p.Notes), NarrowOnRefresh: p.NarrowOnRefresh,
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
		LastUsedAt: pc.LastUsedAt, ExpiresAt: pc.ExpiresAt, Refreshable: c.Refreshable(), NarrowsScopes: c.NarrowsScopes,
		AllowedServers: toAPIGrants(c.Servers),
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

func toAPIAccess(ac providers.Access) apitypes.AuthProviderAccess {
	teams := make([]apitypes.AuthProviderAccessTeam, len(ac.Teams))
	for i, t := range ac.Teams {
		teams[i] = apitypes.AuthProviderAccessTeam{Id: t.ID, Slug: t.Slug, Name: t.Name}
	}
	servers := make([]apitypes.ConnectServer, len(ac.Servers))
	for i, sv := range ac.Servers {
		servers[i] = toAPIConnectServer(sv)
	}
	blocked := make([]apitypes.ConnectServer, len(ac.Blocked))
	for i, sv := range ac.Blocked {
		blocked[i] = toAPIConnectServer(sv)
	}
	return apitypes.AuthProviderAccess{AccessMode: apitypes.AuthProviderAccessMode(ac.Mode), Teams: teams, Servers: servers,
		Blocked: blocked, BlockedCount: ac.BlockedCount, Revision: ac.Provider.Revision}
}
