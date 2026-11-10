package registry

import (
	"context"
	"slices"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// providerParams are a plan's provider columns; the secret is sealed for id.
func (s *Service) planColumns(id uuid.UUID, plan *oauthPlan, cur *dbgen.AuthProvider) (cipher []byte, hint string, err error) {
	switch {
	case plan.secret != nil && *plan.secret != "":
		ct, err := s.box.Seal([]byte(*plan.secret), ProviderSecretAAD(id))
		if err != nil {
			return nil, "", err
		}
		return ct, secretHint(*plan.secret), nil
	case plan.clearSecret || (plan.secret != nil && *plan.secret == "") || cur == nil:
		return nil, "", nil
	}
	return cur.ClientSecretCipher, cur.ClientSecretHint, nil
}

func linkID(plan *oauthPlan) uuid.NullUUID {
	if plan.link == nil {
		return uuid.NullUUID{}
	}
	return uuid.NullUUID{UUID: plan.link.ID, Valid: true}
}

func optString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// insertProvider stores a new server-bound provider for a server.
func (s *Service) insertProvider(ctx context.Context, q *dbgen.Queries, a authz.Actor, sv dbgen.McpServer, plan *oauthPlan) (dbgen.AuthProvider, error) {
	id := uuid.New()
	ct, hint, err := s.planColumns(id, plan, nil)
	if err != nil {
		return dbgen.AuthProvider{}, err
	}
	md, prm := plan.disc.Server, plan.disc.Resource
	return q.InsertServerProvider(ctx, dbgen.InsertServerProviderParams{
		ID: id, Slug: newProviderSlug(), Name: sv.Name, ClientID: plan.clientID, ClientSecretCipher: ct, ClientSecretHint: hint,
		TokenAuthMethod: plan.method, AuthorizationUrl: md.AuthorizationEndpoint, TokenUrl: md.TokenEndpoint,
		RevocationUrl: optString(md.RevocationEndpoint), DefaultScopes: plan.scopes, ServerID: uuid.NullUUID{UUID: sv.ID, Valid: true},
		LinkProviderID: linkID(plan), Registration: &plan.registration, Resource: &prm.Resource, ResourceMetadataUrl: &prm.URL,
		AuthorizationServer: &md.Identifier, Issuer: &md.Issuer, ScopesSupported: nonNil(prm.ScopesSupported),
		SendResource: plan.sendResource, IssParamSupported: md.IssParameterSupported, ClientSecretExpiresAt: plan.secretExpiry,
		CreatedBy: by(a),
	})
}

// updateProvider stores a plan over a server's provider.
func (s *Service) updateProvider(ctx context.Context, q *dbgen.Queries, a authz.Actor, name string, cur dbgen.AuthProvider, plan *oauthPlan) (dbgen.AuthProvider, error) {
	ct, hint, err := s.planColumns(cur.ID, plan, &cur)
	if err != nil {
		return dbgen.AuthProvider{}, err
	}
	md, prm := plan.disc.Server, plan.disc.Resource
	return q.UpdateServerProvider(ctx, dbgen.UpdateServerProviderParams{
		ID: cur.ID, Name: name, ClientID: plan.clientID, ClientSecretCipher: ct, ClientSecretHint: hint, TokenAuthMethod: plan.method,
		AuthorizationUrl: md.AuthorizationEndpoint, TokenUrl: md.TokenEndpoint, RevocationUrl: optString(md.RevocationEndpoint),
		DefaultScopes: plan.scopes, LinkProviderID: linkID(plan), Registration: &plan.registration, Resource: &prm.Resource,
		ResourceMetadataUrl: &prm.URL, AuthorizationServer: &md.Identifier, Issuer: &md.Issuer, ScopesSupported: nonNil(prm.ScopesSupported),
		SendResource: plan.sendResource, IssParamSupported: md.IssParameterSupported, ClientSecretExpiresAt: plan.secretExpiry,
		UpdatedBy: by(a),
	})
}

// planUnchanged reports whether a plan would store what cur already holds.
func planUnchanged(cur dbgen.AuthProvider, plan *oauthPlan) bool {
	md, prm := plan.disc.Server, plan.disc.Resource
	return deref(cur.Registration) == plan.registration && cur.ClientID == plan.clientID && cur.TokenAuthMethod == plan.method &&
		plan.secret == nil && (!plan.clearSecret || cur.ClientSecretCipher == nil) && cur.LinkProviderID == linkID(plan) &&
		slices.Equal(nonNil(cur.DefaultScopes), plan.scopes) && cur.SendResource == plan.sendResource &&
		deref(cur.Issuer) == md.Issuer && deref(cur.AuthorizationServer) == md.Identifier && cur.AuthorizationUrl == md.AuthorizationEndpoint &&
		cur.TokenUrl == md.TokenEndpoint && deref(cur.RevocationUrl) == md.RevocationEndpoint && deref(cur.Resource) == prm.Resource &&
		deref(cur.ResourceMetadataUrl) == prm.URL && slices.Equal(nonNil(cur.ScopesSupported), nonNil(prm.ScopesSupported)) &&
		cur.IssParamSupported == md.IssParameterSupported
}

// authSnapshot is a server's upstream auth as audited:
// {authMode, oauth: {registration, scopes, sendResource, issuer, ...} or
// null, sendIdentity}. Never a secret or a client ID.
func authSnapshot(sv dbgen.McpServer, p *dbgen.AuthProvider) map[string]any {
	out := map[string]any{"authMode": AuthModeOf(sv), "oauth": nil, "sendIdentity": sv.SendIdentity}
	if ps := secretSnapshot(sv); ps != nil {
		out["personSecret"] = ps
	}
	if p == nil || AuthModeOf(sv) != AuthOAuth {
		return out
	}
	o := map[string]any{"registration": deref(p.Registration), "scopes": nonNil(p.DefaultScopes), "sendResource": p.SendResource,
		"issuer": deref(p.Issuer), "authorizationServer": deref(p.AuthorizationServer), "resource": deref(p.Resource)}
	if p.LinkProviderID.Valid {
		o["platformProviderId"] = p.LinkProviderID.UUID.String()
	}
	out["oauth"] = o
	return out
}

// authUpdateAudit records mcp_server.auth_update (before nil: a new server).
func authUpdateAudit(ctx context.Context, q *dbgen.Queries, a authz.Actor, beforeSv *dbgen.McpServer, before *dbgen.AuthProvider,
	sv dbgen.McpServer, after *dbgen.AuthProvider, meta map[string]any) error {
	e := a.Audit("mcp_server.auth_update", "mcp_server", sv.ID.String())
	e.TeamID = sv.TeamID
	if beforeSv != nil {
		e.Before = authSnapshot(*beforeSv, before)
	}
	e.After = authSnapshot(sv, after)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["name"] = sv.Name
	e.Metadata = meta
	return audit.Record(ctx, q, e)
}

// widensScopes reports whether after asks for a scope before didn't.
func widensScopes(before, after []string) bool {
	for _, sc := range after {
		if !slices.Contains(before, sc) {
			return true
		}
	}
	return false
}

const noteUpstreamAuthChanged = "The server's sign-in (OAuth) changed; review it again."
