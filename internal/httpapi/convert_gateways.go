package httpapi

import (
	"time"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/calls"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Conversions of gateways, API keys and call records to API types. An API
// key's digest has no field here, and its secret is only ever returned by
// create.

// toAPIGateway converts a gateway; effective is its rate limit now
// (gatewayLimits).
func (a *api) toAPIGateway(v gateways.View, effective *int64) apitypes.Gateway {
	g := v.Gateway
	capture := g.CapturePayloads
	out := apitypes.Gateway{
		Id: g.ID, Slug: g.Slug, Name: g.Name, Description: g.Description, OwnerKind: apitypes.GatewayOwnerKind(g.OwnerKind),
		Enabled: g.Enabled, Url: a.Gateways.URL(g.Slug), CapabilityCount: v.CapabilityCount, UnavailableCount: v.UnavailableCount,
		GrantCount: v.GrantCount, Revision: g.Revision, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt,
		CapturePayloads: &capture, RateLimitPerMinute: g.RateLimitPerMinute, EffectiveRateLimitPerMinute: effective,
	}
	if g.TeamID.Valid {
		id := g.TeamID.UUID
		out.TeamId, out.TeamSlug, out.TeamName = &id, nonEmpty(v.TeamSlug), nonEmpty(v.TeamName)
	}
	return out
}

func toAPIGatewayCapability(s gateways.Selected) apitypes.GatewayCapability {
	out := apitypes.GatewayCapability{
		CapabilityId: s.Capability.ID, ServerId: s.Server.ID, ServerSlug: s.Server.Slug, ServerName: s.Server.Name,
		TeamSlug: s.TeamSlug, Kind: apitypes.GatewayCapabilityKind(s.Capability.Kind), Name: s.Capability.Name,
		ExposedName: s.ExposedName, Title: s.Capability.Title, Description: s.Capability.Description, Available: s.Available,
		Requires: toAPIRequirement(s.Requires, nil), ServerCapturesPayloads: &s.Server.CapturePayloads,
	}
	if s.MinRole != nil {
		r := apitypes.TeamRole(*s.MinRole)
		out.MinRole = &r
	}
	if !s.Available {
		r := apitypes.GatewayUnavailableReason(s.Reason)
		out.UnavailableReason = &r
	}
	return out
}

func toAPISelection(s gateways.Selection) apitypes.GatewayCapabilities {
	out := apitypes.GatewayCapabilities{Revision: s.Revision, Items: make([]apitypes.GatewayCapability, len(s.Items))}
	for i, it := range s.Items {
		out.Items[i] = toAPIGatewayCapability(it)
	}
	return out
}

func toAPIGatewayOption(o gateways.Option) apitypes.GatewayOption {
	capture := o.ServerCapturePayloads
	return apitypes.GatewayOption{
		ServerCapturesPayloads: &capture,
		CapabilityId:           o.ID, ServerId: o.ServerID, ServerSlug: o.ServerSlug, ServerName: o.ServerName, TeamSlug: o.TeamSlug,
		TeamName: o.TeamName, Source: apitypes.GatewayOptionSource(o.Source), Kind: apitypes.GatewayCapabilityKind(o.Kind),
		Name: o.Name, ExposedName: o.ExposedName, Title: o.Title, Description: o.Description,
		Requires: toAPIRequirement(o.Requires, nil),
	}
}

func toAPIGrant(r dbgen.ListGatewayGrantsRow) apitypes.GatewayGrant {
	g := r.GatewayGrant
	out := apitypes.GatewayGrant{Id: g.ID, SubjectKind: apitypes.GatewayGrantSubjectKind(g.SubjectKind), CreatedAt: g.AddedAt,
		AddedByName: nonEmpty(r.AddedByName)}
	switch {
	case g.TeamID.Valid:
		out.Team = &apitypes.GrantTeam{Id: g.TeamID.UUID, Slug: r.TeamSlug, Name: r.TeamName}
	case g.UserID.Valid:
		out.User = &apitypes.MemberUser{Id: g.UserID.UUID, Email: r.UserEmail, DisplayName: r.UserDisplayName,
			Status: apitypes.UserStatus(r.UserStatus)}
	case g.GroupName != nil:
		group := *g.GroupName
		out.Group = &group
	}
	return out
}

func (a *api) toAPIMyGateway(m gateways.Mine) apitypes.MyGateway {
	g := m.View.Gateway
	out := apitypes.MyGateway{
		Id: g.ID, Slug: g.Slug, Name: g.Name, Description: g.Description, OwnerKind: apitypes.GatewayOwnerKind(g.OwnerKind),
		Url: a.Gateways.URL(g.Slug), Access: make([]apitypes.MyGatewayAccess, len(m.Access)), CapabilityCount: m.Offered,
		NeedsPersonCount: m.NeedsPerson, CapturesPayloads: &m.CapturesPayloads,
	}
	for i, acc := range m.Access {
		out.Access[i] = apitypes.MyGatewayAccess(acc)
	}
	if g.TeamID.Valid {
		out.TeamSlug, out.TeamName = nonEmpty(m.View.TeamSlug), nonEmpty(m.View.TeamName)
	}
	if len(m.Groups) > 0 {
		groups := append([]string{}, m.Groups...)
		out.Groups = &groups
	}
	return out
}

func toAPIKey(v apikeys.View, now time.Time) apitypes.ApiKey {
	k := v.Key
	exp := k.ExpiresAt
	out := apitypes.ApiKey{
		Id: k.ID, Name: k.Name, Prefix: k.Prefix, Status: apitypes.ApiKeyStatus(apikeys.Status(k, now)),
		CreatedAt: k.CreatedAt, ExpiresAt: &exp, LastUsedAt: k.LastUsedAt, RevokedAt: k.RevokedAt,
		Gateways: make([]apitypes.ApiKeyGateway, len(v.Gateways)),
	}
	for i, g := range v.Gateways {
		out.Gateways[i] = apitypes.ApiKeyGateway{Id: g.ID, Slug: g.Slug, Name: g.Name, Exists: g.Exists}
	}
	return out
}

func toAPICall(c calls.Row) apitypes.McpCall {
	r := c.ListMCPCallsRow
	captured := c.Captured
	out := apitypes.McpCall{
		Captured: &captured,
		Id:       r.ID, OccurredAt: r.OccurredAt, Method: r.Method, ExposedName: r.ExposedName,
		Gateway:    apitypes.CallRef{Id: r.GatewayID, Slug: r.GatewaySlug, Name: r.GatewayName, Exists: r.GatewayExists},
		Principal:  toAPICallPrincipal(r),
		ClientName: r.ClientName, Outcome: apitypes.McpCallOutcome(r.Outcome), ErrorClass: r.ErrorClass, LatencyMs: r.LatencyMs,
		RequestBytes: r.RequestBytes, ResponseBytes: r.ResponseBytes, RequestId: r.RequestID, ProviderSlug: r.ProviderSlug, IdentitySent: r.IdentitySent,
	}
	if r.ServerID.Valid {
		out.Server = &apitypes.CallRef{Id: r.ServerID.UUID, Slug: r.ServerSlug, Name: r.ServerName, Exists: r.ServerExists}
	}
	if r.AgentID != nil {
		out.Agent = toAPICallAgent(r)
	}
	return out
}

// toAPICallAgent is the agent behind a call an agent platform relayed: the
// platform and agent (as recorded), whether the person was present and, when
// the token named one, the person.
func toAPICallAgent(r dbgen.ListMCPCallsRow) *apitypes.AgentCall {
	out := &apitypes.AgentCall{AgentId: *r.AgentID, AgentName: r.AgentName, PlatformId: nullUUID(r.ViaPlatformID),
		PlatformName: deref(r.ViaPlatformName), PersonPresent: r.PersonPresent}
	if r.PersonPresent != nil && r.UserID.Valid {
		out.Person = &apitypes.AgentCallPerson{UserId: nullUUID(r.UserID), Email: nonEmpty(r.UserEmail), DisplayName: r.PersonDisplayName}
	}
	return out
}

// toAPICallPrincipal: a person (api_key with the key's name, oauth with the
// client's name and whether its host vouches for it), or a service account
// (its name, team and key, and whether it still exists).
func toAPICallPrincipal(r dbgen.ListMCPCallsRow) apitypes.CallPrincipal {
	p := apitypes.CallPrincipal{Kind: apitypes.CallPrincipalKind(r.PrincipalKind), DisplayName: r.UserDisplayName}
	switch r.PrincipalKind {
	case calls.PrincipalServiceAccount:
		exists := r.ServiceAccountExists
		p.ServiceAccountId, p.ServiceAccountTeamSlug, p.ApiKeyName = nullUUID(r.ServiceAccountID), nonEmpty(r.ServiceAccountTeamSlug), nonEmpty(r.ApiKeyName)
		p.ServiceAccountExists = &exists
	case calls.PrincipalOAuth:
		verified := r.OauthClientVerified
		p.UserId, p.Email, p.OauthClientName = nullUUID(r.UserID), nonEmpty(r.UserEmail), r.OauthClientName
		p.OauthClientVerified = &verified
	default:
		p.UserId, p.Email, p.ApiKeyName = nullUUID(r.UserID), nonEmpty(r.UserEmail), nonEmpty(r.ApiKeyName)
	}
	return p
}
