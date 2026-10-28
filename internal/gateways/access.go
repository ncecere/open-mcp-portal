package gateways

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/registry"
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
}

// Allowed reports whether the person may use the gateway.
func (c Caller) Allowed() bool { return len(c.Access) > 0 }

// Intersect is what a call relayed by an agent platform may do (decision 66):
// the person's access and the relay service account's, both. It allows the
// gateway only when both do, and a minimum role only when both roles meet it
// (the lower of the two roles decides on team gateways). The access reasons
// are the person's.
func Intersect(person, relay Caller) Caller {
	if !person.Allowed() || !relay.Allowed() {
		return Caller{}
	}
	role := person.Role
	if authz.RoleAtLeast(person.Role, relay.Role) {
		role = relay.Role
	}
	return Caller{Role: role, Access: person.Access, ToolPolicy: toolscope.Intersect(person.ToolPolicy, relay.ToolPolicy)}
}

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
	return Caller{Access: grantKinds(kinds), ToolPolicy: toolscope.Union(scopes...)}, nil
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
	return s.usable(ctx, ids, func(g dbgen.Gateway) (Caller, error) { return callerOf(ctx, s.q, g, u) })
}

// UsableByServiceAccount is Usable for a service account of a team with a
// role (ServiceAccountCaller).
func (s *Service) UsableByServiceAccount(ctx context.Context, teamID uuid.UUID, role string, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error) {
	return s.usable(ctx, ids, func(g dbgen.Gateway) (Caller, error) { return serviceAccountCaller(ctx, s.q, g, teamID, role) })
}

func (s *Service) usable(ctx context.Context, ids []uuid.UUID, caller func(dbgen.Gateway) (Caller, error)) ([]dbgen.Gateway, []uuid.UUID, error) {
	rows, err := s.q.ListUsableGatewayCandidates(ctx, ids)
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
			why, err := unserved(ctx, s.q, g)
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
	return Caller{Access: []string{AccessTeamGrant}, ToolPolicy: toolscope.Union(scopes...)}, nil
}

// Resolve finds a gateway by slug (404 gateway_not_found).
func (s *Service) Resolve(ctx context.Context, slug string) (dbgen.Gateway, error) {
	g, err := s.q.GetGatewayBySlug(ctx, slug)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return g, errNoGateway
	}
	return g, err
}

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

// Grants lists a platform gateway's grants (platform admins and auditors);
// a team gateway has none.
func (s *Service) Grants(ctx context.Context, a authz.Actor, id uuid.UUID) ([]dbgen.ListGatewayGrantsRow, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := getGateway(ctx, s.q, id, false); err != nil {
		return nil, err
	}
	return s.q.ListGatewayGrants(ctx, id)
}

// GrantInput names a grant's subject: exactly one of Team (slug or ID),
// UserEmail or Group, matching Kind.
type GrantInput struct {
	ToolScope              []byte
	Kind                   string
	Team, UserEmail, Group *string
}

func validGroup(g string) bool {
	return g != "" && len(g) <= 256 && utf8.ValidString(g) && strings.IndexFunc(g, unicode.IsControl) < 0
}

// AddGrant grants a platform gateway to a team, a person or an SSO group
// (platform admins). Audited as gateway.grant_add.
func (s *Service) AddGrant(ctx context.Context, a authz.Actor, id uuid.UUID, in GrantInput) (dbgen.ListGatewayGrantsRow, error) {
	if !a.IsPlatformAdmin() {
		return dbgen.ListGatewayGrantsRow{}, errAdminOnly
	}
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	set := 0
	for _, p := range []*string{in.Team, in.UserEmail, in.Group} {
		if p != nil {
			set++
		}
	}
	if set != 1 {
		return dbgen.ListGatewayGrantsRow{}, errInvalidGrant
	}
	var grantID uuid.UUID
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if g.OwnerKind != OwnerPlatform {
			return errTeamGateway
		}
		p := dbgen.InsertGatewayGrantParams{GatewayID: g.ID, SubjectKind: in.Kind, AddedBy: by(a), ToolScope: toolScope}
		subject := ""
		switch {
		case in.Kind == SubjectTeam && in.Team != nil:
			t, err := teams.Resolve(ctx, q, strings.TrimSpace(*in.Team))
			if e, ok := apperr.As(err); ok && e.Status == 404 {
				return errSubjectNotFound
			} else if err != nil {
				return err
			}
			p.TeamID, subject = uuid.NullUUID{UUID: t.ID, Valid: true}, t.Slug
		case in.Kind == SubjectUser && in.UserEmail != nil:
			email, err := teams.NormalizeEmail(*in.UserEmail)
			if err != nil {
				return err
			}
			users, err := q.ListUsersByEmail(ctx, email)
			if err != nil {
				return err
			}
			if len(users) == 0 {
				return errSubjectNotFound
			}
			p.UserID, subject = uuid.NullUUID{UUID: users[0].ID, Valid: true}, email
		case in.Kind == SubjectGroup && in.Group != nil:
			group := strings.TrimSpace(*in.Group)
			if !validGroup(group) {
				return apperr.Invalid("invalid_group", "The group must be 1-256 characters on one line")
			}
			p.GroupName, subject = &group, group
		default:
			return errInvalidGrant
		}
		row, err := q.InsertGatewayGrant(ctx, p)
		if apperr.IsUniqueViolation(err, "") {
			return errGrantExists
		} else if err != nil {
			return err
		}
		grantID = row.ID
		e := a.Audit("gateway.grant_add", "gateway_grant", row.ID.String())
		e.After = map[string]any{"subjectKind": in.Kind, "subject": subject, "toolScope": toolscope.Stored(row.ToolScope)}
		e.Metadata = map[string]any{"name": g.Name + " · " + subject, "gatewayId": g.ID.String(), "gatewayName": g.Name}
		return audit.Record(ctx, q, e)
	})
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	rows, err := s.q.ListGatewayGrants(ctx, id)
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	i := slices.IndexFunc(rows, func(r dbgen.ListGatewayGrantsRow) bool { return r.GatewayGrant.ID == grantID })
	if i < 0 {
		return dbgen.ListGatewayGrantsRow{}, errNoGrant
	}
	return rows[i], nil
}

// RemoveGrant removes a grant (platform admins); the next call is refused.
// Audited as gateway.grant_remove.
func (s *Service) RemoveGrant(ctx context.Context, a authz.Actor, id, grantID uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		row, err := q.DeleteGatewayGrant(ctx, dbgen.DeleteGatewayGrantParams{ID: grantID, GatewayID: g.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoGrant
		} else if err != nil {
			return err
		}
		subject, err := grantSubject(ctx, q, row)
		if err != nil {
			return err
		}
		e := a.Audit("gateway.grant_remove", "gateway_grant", row.ID.String())
		e.Before = map[string]any{"subjectKind": row.SubjectKind, "subject": subject, "toolScope": toolscope.Stored(row.ToolScope)}
		e.Metadata = map[string]any{"name": g.Name + " · " + subject, "gatewayId": g.ID.String(), "gatewayName": g.Name}
		return audit.Record(ctx, q, e)
	})
}

// grantSubject names a grant's subject as audited: a team's slug, a
// person's email or the group.
func grantSubject(ctx context.Context, q *dbgen.Queries, g dbgen.GatewayGrant) (string, error) {
	switch {
	case g.TeamID.Valid:
		t, err := q.GetTeamByID(ctx, g.TeamID.UUID)
		if err != nil {
			return "", err
		}
		return t.Slug, nil
	case g.UserID.Valid:
		u, err := q.GetUser(ctx, g.UserID.UUID)
		if err != nil {
			return "", err
		}
		return u.Email, nil
	case g.GroupName != nil:
		return *g.GroupName, nil
	}
	return "", nil
}
