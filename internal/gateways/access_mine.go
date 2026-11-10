package gateways

import (
	"context"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// Mine is a gateway a person may use.
type Mine struct {
	View   View
	Access []string
	// Groups are the person's groups the gateway is granted to (when Access
	// includes AccessGroupGrant), sorted.
	Groups []string
	// Offered counts the capabilities it offers them now.
	Offered int64
	// NeedsPerson (service accounts only) counts the capabilities it would
	// offer that require a person's account (a provider requirement);
	// service accounts are refused them, so Offered leaves them out.
	NeedsPerson *int64
	// CapturesPayloads: calls may be recorded with their contents (the
	// gateway captures them, or the server of an offered capability does).
	CapturesPayloads bool
}

// ListMine lists the gateways a person may use now, by name: enabled, and
// for team gateways, of an active team.
func (s *Service) ListMine(ctx context.Context, u dbgen.User) ([]Mine, error) {
	rows, err := s.q.ListGatewaysForUser(ctx, dbgen.ListGatewaysForUserParams{UserID: uuid.NullUUID{UUID: u.ID, Valid: true}, Groups: groupsOf(u)})
	if err != nil {
		return nil, err
	}
	out := make([]Mine, 0, len(rows))
	for _, r := range rows {
		c, err := callerOf(ctx, s.q, r.Gateway, u)
		if err != nil {
			return nil, err
		}
		if !c.Allowed() {
			continue
		} // a grant/membership may have ended since the candidate query
		offers, err := s.Offers(ctx, r.Gateway, c)
		if err != nil {
			return nil, err
		}
		m := Mine{View: View{Gateway: r.Gateway, TeamSlug: r.TeamSlug, TeamName: r.TeamName}, Access: c.Access, Groups: r.GrantGroups,
			CapturesPayloads: captures(r.Gateway, offers)}
		if m.Groups == nil {
			m.Groups = []string{}
		}
		for _, o := range offers {
			if o.Allowed {
				m.Offered++
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// allowedOffers are the capabilities a person may use now through their
// gateways (enabled, a team gateway's team active, access, minimum roles).
func (s *Service) allowedOffers(ctx context.Context, u dbgen.User) ([]Offer, error) {
	rows, err := s.q.ListGatewaysForUser(ctx, dbgen.ListGatewaysForUserParams{UserID: uuid.NullUUID{UUID: u.ID, Valid: true}, Groups: groupsOf(u)})
	if err != nil {
		return nil, err
	}
	var out []Offer
	for _, r := range rows {
		c, err := callerOf(ctx, s.q, r.Gateway, u)
		if err != nil {
			return nil, err
		}
		if !c.Allowed() {
			continue
		}
		offers, err := s.Offers(ctx, r.Gateway, c)
		if err != nil {
			return nil, err
		}
		for _, o := range offers {
			if o.Allowed {
				out = append(out, o)
			}
		}
	}
	return out, nil
}

// UsesServer reports whether a person may use any capability of a server
// through one of their gateways now (signing in to an oauth server without
// a consent link, docs/phase7-upstream-oauth.md).
func (s *Service) UsesServer(ctx context.Context, u dbgen.User, serverID uuid.UUID) (bool, error) {
	offers, err := s.allowedOffers(ctx, u)
	if err != nil {
		return false, err
	}
	for _, o := range offers {
		if o.Server.ID == serverID {
			return true, nil
		}
	}
	return false, nil
}

// ProviderNeed is what a server's capabilities a person may use ask of one
// platform provider: the union of their effective scopes, in the order
// they were first asked.
type ProviderNeed struct {
	Provider registry.Provider
	Scopes   []string
}

// ReachableServer is a server a person may use through a gateway now, with
// the platform providers (enabled, not an oauth server's own sign-in) its
// reachable capabilities require.
type ReachableServer struct {
	Server             dbgen.McpServer
	TeamSlug, TeamName string
	Needs              []ProviderNeed
}

// ReachableServers lists the servers a person may use through one of their
// gateways now, by server name: the visibility rule for allowing a server
// to use a connected account (decision 68). It is the one calls use, so
// it offers exactly the servers whose calls the person could make: their
// teams' servers on their teams' gateways, and published servers with
// approved capabilities on the gateways they have access to.
func (s *Service) ReachableServers(ctx context.Context, u dbgen.User) ([]ReachableServer, error) {
	offers, err := s.allowedOffers(ctx, u)
	if err != nil {
		return nil, err
	}
	byID := map[uuid.UUID]*ReachableServer{}
	var order []uuid.UUID
	for _, o := range offers {
		rs, ok := byID[o.Server.ID]
		if !ok {
			rs = &ReachableServer{Server: o.Server, TeamSlug: o.TeamSlug, TeamName: o.TeamName}
			byID[o.Server.ID] = rs
			order = append(order, o.Server.ID)
		}
		req := o.Requires
		if req == nil || !req.Provider.Enabled || req.Provider.ServerBound() {
			continue
		}
		i := slices.IndexFunc(rs.Needs, func(n ProviderNeed) bool { return n.Provider.ID == req.Provider.ID })
		if i < 0 {
			rs.Needs = append(rs.Needs, ProviderNeed{Provider: req.Provider, Scopes: []string{}})
			i = len(rs.Needs) - 1
		}
		for _, sc := range req.Scopes {
			if !slices.Contains(rs.Needs[i].Scopes, sc) {
				rs.Needs[i].Scopes = append(rs.Needs[i].Scopes, sc)
			}
		}
	}
	out := make([]ReachableServer, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	slices.SortFunc(out, func(a, b ReachableServer) int {
		if c := strings.Compare(a.Server.Name, b.Server.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Server.ID.String(), b.Server.ID.String())
	})
	return out, nil
}

// ListForServiceAccount lists the gateways a service account of a team with
// a role may use now, by name (decision 23): its team's enabled gateways
// while the team is active (AccessTeamMember, with the role applied to
// minimum roles) and enabled platform gateways granted to the team
// (AccessTeamGrant). Offered counts what the account reaches now. It doesn't
// look at whether the account is enabled; an archived team gets none (its
// accounts' keys are refused).
func (s *Service) ListForServiceAccount(ctx context.Context, teamID uuid.UUID, role string, accountID uuid.UUID, scope []byte) ([]Mine, error) {
	t, err := s.q.GetTeamByID(ctx, teamID)
	if err != nil {
		return nil, err
	}
	if t.Status != teams.StatusActive {
		return []Mine{}, nil
	}
	rows, err := s.q.ListGatewaysForServiceAccount(ctx, uuid.NullUUID{UUID: teamID, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Mine, 0, len(rows))
	for _, r := range rows {
		c, err := serviceAccountCaller(ctx, s.q, r.Gateway, teamID, role)
		if err != nil {
			return nil, err
		}
		if !c.Allowed() {
			continue
		}
		// Management views keep their existing MyGatewayAccess vocabulary;
		// service_account is an internal runtime reason, not an API enum value.
		if r.Gateway.OwnerKind == OwnerTeam {
			c.Access = []string{AccessTeamMember}
		}
		c.ToolPolicy = toolscope.Intersect(c.ToolPolicy, toolscope.Union(toolscope.Stored(scope)))
		offers, err := s.Offers(ctx, r.Gateway, c)
		if err != nil {
			return nil, err
		}
		m := Mine{View: View{Gateway: r.Gateway, TeamSlug: r.TeamSlug, TeamName: r.TeamName}, Access: c.Access, Groups: []string{},
			CapturesPayloads: captures(r.Gateway, offers)}
		var needsPerson int64
		for _, o := range offers {
			switch {
			case !o.Allowed:
			case o.Server.AuthMode == registry.AuthPersonSecret:
				needsPerson++ // personal secrets are never shared
			case o.Requires != nil:
				ready := false
				if s.ServiceConnectionReady != nil && accountID != uuid.Nil {
					var err error
					ready, err = s.ServiceConnectionReady(ctx, o.Requires, accountID, teamID, o.Server.ID, o.Server.URL)
					if err != nil {
						return nil, err
					}
				}
				if ready {
					m.Offered++
				} else {
					needsPerson++
				}
			default:
				m.Offered++
			}
		}
		m.NeedsPerson = &needsPerson
		out = append(out, m)
	}
	return out, nil
}

// GetMine returns a gateway the person may use now, with the capabilities
// it offers them; any other is 404.
func (s *Service) GetMine(ctx context.Context, u dbgen.User, id uuid.UUID) (Mine, []Offer, error) {
	g, err := getGateway(ctx, s.q, id, false)
	if err != nil {
		return Mine{}, nil, err
	}
	if why, err := unserved(ctx, s.q, g); err != nil {
		return Mine{}, nil, err
	} else if why != "" {
		return Mine{}, nil, errNoGateway
	}
	c, err := callerOf(ctx, s.q, g, u)
	if err != nil {
		return Mine{}, nil, err
	}
	if !c.Allowed() {
		return Mine{}, nil, errNoGateway
	}
	groups := []string{}
	if slices.Contains(c.Access, AccessGroupGrant) {
		if groups, err = s.q.GatewayGrantGroupsForUser(ctx, dbgen.GatewayGrantGroupsForUserParams{GatewayID: g.ID, Groups: groupsOf(u)}); err != nil {
			return Mine{}, nil, err
		}
	}
	v, err := view(ctx, s.q, id)
	if err != nil {
		return Mine{}, nil, err
	}
	offers, err := s.Offers(ctx, g, c)
	if err != nil {
		return Mine{}, nil, err
	}
	allowed := make([]Offer, 0, len(offers))
	for _, o := range offers {
		if o.Allowed {
			allowed = append(allowed, o)
		}
	}
	return Mine{View: v, Access: c.Access, Groups: groups, Offered: int64(len(allowed)), CapturesPayloads: captures(g, allowed)}, allowed, nil
}

// captures reports whether calls through g may be captured: the gateway
// captures them, or the server of an offered capability does.
func captures(g dbgen.Gateway, offers []Offer) bool {
	if g.CapturePayloads {
		return true
	}
	for _, o := range offers {
		if o.Allowed && o.Server.CapturePayloads {
			return true
		}
	}
	return false
}
