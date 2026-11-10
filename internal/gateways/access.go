package gateways

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// Who may use a gateway: a team gateway's members, and the teams, people
// and SSO groups a platform gateway is granted to.

// Grant subject kinds.
const (
	SubjectTeam  = "team"
	SubjectUser  = "user"
	SubjectGroup = "group"
)

// Why a person may use a gateway (the API's MyGatewayAccess).
const (
	AccessTeamMember = "team_member"
	AccessTeamGrant  = "team_grant"
	AccessUserGrant  = "user_grant"
	AccessGroupGrant = "group_grant"
)

// DeniedRole is why a selected, served capability is refused to a member
// whose role is below its minimum.
const DeniedRole = "role"
const DeniedToolScope = "tool_scope"

// DeniedGatewayDisabled is why a switched-off gateway serves nobody (a team
// gateway of an archived team serves nobody either: ReasonTeamArchived).
const DeniedGatewayDisabled = "gateway_disabled"

var (
	errNoGrant         = apperr.NotFound("grant_not_found", "Grant not found")
	errGrantExists     = apperr.Conflict("grant_exists", "The gateway is already granted to them")
	errSubjectNotFound = apperr.NotFound("subject_not_found", "No such team or user")
	errInvalidGrant    = apperr.Invalid("invalid_grant", "Give exactly one of team, userEmail or group, matching subjectKind")
)

var grantAccess = map[string]string{SubjectTeam: AccessTeamGrant, SubjectUser: AccessUserGrant, SubjectGroup: AccessGroupGrant}

// accessOrder sorts access reasons.
var accessOrder = []string{AccessTeamMember, AccessTeamGrant, AccessUserGrant, AccessGroupGrant}

func grantKinds(kinds []string) []string {
	out := []string{}
	for _, a := range accessOrder {
		for _, k := range kinds {
			if grantAccess[k] == a {
				out = append(out, a)
			}
		}
	}
	return out
}

func groupsOf(u dbgen.User) []string {
	if u.Groups == nil {
		return []string{}
	}
	return u.Groups
}

// Caller is a person's access to one gateway.
type Caller struct {
	ToolPolicy toolscope.Policy
	// Role is the person's role in a team gateway's team.
	Role string
	// Access says why they may use it (empty: they may not).
	Access []string
	// ExpiresAt conservatively bounds this snapshot by the earliest matched
	// grant expiry. A fresh snapshot may still authorize through alternatives.
	ExpiresAt *time.Time
}

// Allowed reports whether the person may use the gateway.
func (c Caller) Allowed() bool { return len(c.Access) > 0 }

// CallerOf works out a person's access to a gateway from their current
// memberships, grants and stored groups. It doesn't look at whether the
// gateway or the person is enabled.
func (s *Service) CallerOf(ctx context.Context, g dbgen.Gateway, u dbgen.User) (Caller, error) {
	return callerOf(ctx, s.q, g, u)
}

func callerOf(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway, u dbgen.User) (Caller, error) {
	if g.OwnerKind == OwnerTeam {
		role, err := teams.MemberRole(ctx, q, g.TeamID.UUID, u.ID)
		if err != nil || role == "" {
			return Caller{}, err
		}
		return Caller{Role: role, Access: []string{AccessTeamMember}}, nil
	}
	grants, err := q.GatewayGrantsForUser(ctx, dbgen.GatewayGrantsForUserParams{
		GatewayID: g.ID, UserID: uuid.NullUUID{UUID: u.ID, Valid: true}, Groups: groupsOf(u),
	})
	if err != nil {
		return Caller{}, err
	}
	kinds := []string{}
	scopes := []*toolscope.Scope{}
	for _, gr := range grants {
		if !slices.Contains(kinds, gr.SubjectKind) {
			kinds = append(kinds, gr.SubjectKind)
		}
		scopes = append(scopes, toolscope.Stored(gr.ToolScope))
	}
	return Caller{Access: grantKinds(kinds), ToolPolicy: toolscope.Union(scopes...), ExpiresAt: grantDeadline(grants)}, nil
}

// Offer is a selected capability as one caller sees it.
type Offer struct {
	Selected
	// Allowed: served now and the caller's role is enough. Otherwise Denied
	// says why (an unavailable reason, or DeniedRole).
	Allowed bool
	Denied  string
}

// Evaluate applies availability and minimum roles to a selection for a
// caller (minRole only applies to team gateways).
func Evaluate(g dbgen.Gateway, items []Selected, c Caller) []Offer {
	out := make([]Offer, len(items))
	for i, it := range items {
		o := Offer{Selected: it}
		switch {
		case !it.Available:
			o.Denied = it.Reason
		case g.OwnerKind == OwnerTeam && !authz.MinRoleAllows(c.Role, it.MinRole):
			o.Denied = DeniedRole
		case it.Capability.Kind == "tool" && !c.ToolPolicy.Allows(toolscope.Class(it.Capability.ToolClass), it.ExposedName):
			o.Denied = DeniedToolScope
		default:
			o.Allowed = true
		}
		out[i] = o
	}
	return out
}

// Offers is the gateway's selection as the caller sees it, read now.
func (s *Service) Offers(ctx context.Context, g dbgen.Gateway, c Caller) ([]Offer, error) {
	items, err := selection(ctx, s.q, g)
	if err != nil {
		return nil, err
	}
	return Evaluate(g, items, c), nil
}

// Unserved says why a gateway serves nobody right now, or "" when it
// serves: switched off (DeniedGatewayDisabled), or a team gateway whose team
// is archived (ReasonTeamArchived). Unarchiving the team restores it.
func (s *Service) Unserved(ctx context.Context, g dbgen.Gateway) (string, error) {
	return unserved(ctx, s.q, g)
}

func unserved(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway) (string, error) {
	if !g.Enabled {
		return DeniedGatewayDisabled, nil
	}
	archived, err := gatewayTeamArchived(ctx, q, g)
	if err != nil || !archived {
		return "", err
	}
	return ReasonTeamArchived, nil
}

// Usable splits ids into the gateways the person may use now (enabled, a
// team gateway's team active, and they have access), in the order given,
// and the IDs they may not (unknown ones included).
func (s *Service) Usable(ctx context.Context, u dbgen.User, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error) {
	return usable(ctx, s.q, ids, func(g dbgen.Gateway) (Caller, error) { return callerOf(ctx, s.q, g, u) })
}

// UsableInTx performs all gateway, team, membership and grant reads on the
// caller's exact live registered transaction. It acquires no pool connection
// and never commits or rolls back the owner. Registration alone is not proof
// of a global gate, current user standing or an admitted request epoch.
func (s *Service) UsableInTx(ctx context.Context, q *dbgen.Queries, u dbgen.User, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error) {
	if _, ok := store.TxOf(q); !ok {
		return nil, nil, errors.New("gateway authority read requires registered transaction queries")
	}
	return usable(ctx, q, ids, func(g dbgen.Gateway) (Caller, error) { return callerOf(ctx, q, g, u) })
}

// UsableByServiceAccount is Usable for a service account of a team with a
// role (ServiceAccountCaller).
func (s *Service) UsableByServiceAccount(ctx context.Context, teamID uuid.UUID, role string, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error) {
	return usable(ctx, s.q, ids, func(g dbgen.Gateway) (Caller, error) { return serviceAccountCaller(ctx, s.q, g, teamID, role) })
}

func usable(ctx context.Context, q *dbgen.Queries, ids []uuid.UUID, caller func(dbgen.Gateway) (Caller, error)) ([]dbgen.Gateway, []uuid.UUID, error) {
	rows, err := q.ListUsableGatewayCandidates(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[uuid.UUID]dbgen.Gateway, len(rows))
	for _, g := range rows {
		byID[g.ID] = g
	}
	var usable []dbgen.Gateway
	refused := []uuid.UUID{}
	for _, id := range ids {
		g, ok := byID[id]
		if ok {
			why, err := unserved(ctx, q, g)
			if err != nil {
				return nil, nil, err
			}
			c, err := caller(g)
			if err != nil {
				return nil, nil, err
			}
			ok = why == "" && c.Allowed()
		}
		if ok {
			usable = append(usable, g)
		} else {
			refused = append(refused, id)
		}
	}
	return usable, refused, nil
}

// AccessServiceAccount is why a service account may use a gateway: its
// team's own gateway (with the account's role), or a platform gateway
// granted to its team (decision 23; AccessTeamGrant).
const AccessServiceAccount = "service_account"

// ServiceAccountCaller works out a service account's access to a gateway:
// its own team's gateways, with the account's role for minimum roles, and
// platform gateways granted to its team (decision 23: no grants to
// individual service accounts). It doesn't look at whether the gateway or
// the account is enabled.
func (s *Service) ServiceAccountCaller(ctx context.Context, g dbgen.Gateway, teamID uuid.UUID, role string) (Caller, error) {
	return serviceAccountCaller(ctx, s.q, g, teamID, role)
}

func serviceAccountCaller(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway, teamID uuid.UUID, role string) (Caller, error) {
	if g.OwnerKind == OwnerTeam {
		if g.TeamID.UUID != teamID || !authz.ValidTeamRole(role) {
			return Caller{}, nil
		}
		return Caller{Role: role, Access: []string{AccessServiceAccount}}, nil
	}
	grants, err := q.GatewayGrantsForTeam(ctx, dbgen.GatewayGrantsForTeamParams{GatewayID: g.ID, TeamID: uuid.NullUUID{UUID: teamID, Valid: true}})
	if err != nil || len(grants) == 0 {
		return Caller{}, err
	}
	scopes := []*toolscope.Scope{}
	for _, gr := range grants {
		scopes = append(scopes, toolscope.Stored(gr.ToolScope))
	}
	return Caller{Access: []string{AccessTeamGrant}, ToolPolicy: toolscope.Union(scopes...), ExpiresAt: grantDeadline(grants)}, nil
}

// Resolve finds a gateway by slug (404 gateway_not_found).
func (s *Service) Resolve(ctx context.Context, slug string) (dbgen.Gateway, error) {
	g, err := s.q.GetGatewayBySlug(ctx, slug)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return g, errNoGateway
	}
	return g, err
}
