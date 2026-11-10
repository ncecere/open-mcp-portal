package registry

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// Counts are capabilities per kind.
type Counts struct {
	Tools, Resources, ResourceTemplates, Prompts int64
}

func (c *Counts) add(kind string, n int64) {
	switch kind {
	case upstream.KindTool:
		c.Tools += n
	case upstream.KindResource:
		c.Resources += n
	case upstream.KindResourceTemplate:
		c.ResourceTemplates += n
	case upstream.KindPrompt:
		c.Prompts += n
	}
}

// ServerView is a server as the API shows it.
type ServerView struct {
	Server          dbgen.McpServer
	TeamSlug        string
	TeamName        string
	TeamStatus      string // its team's: archived teams' servers are out of the catalog and gateways
	EffectivePolicy string
	ReviewedByName  string
	// Counts are listed (not gone) capabilities; Approved the approved ones.
	Counts, Approved Counts
	// PendingChanges counts listed capabilities of a published server whose
	// current definition is not approved: changed since approval, or new.
	PendingChanges int64
	// Health is the latest check (nil before the first).
	Health *dbgen.McpHealthCheck
	// Requirement is the server's user-authorization requirement (nil: none).
	Requirement *ServerRequirement
	// OAuth is the sign-in of a server in oauth mode (nil otherwise).
	OAuth *OAuthView
	// Machine is the OAuth client of a server in machine_oauth mode (nil
	// otherwise): never its secret.
	Machine *MachineOAuthView
	// ReviewDigest binds a review to what its reader saw (ReviewDigest).
	ReviewDigest string
	// PersonSecret is the settings and state of a server in person_secret
	// mode (nil otherwise).
	PersonSecret *PersonSecretView
	// Credentials are the parts of the server's own credential, in order:
	// kind, name and hint only (the legacy header counts as one part).
	Credentials []CredentialView
	// Endpoints are ordered extra replicas, never secret values or the primary.
	Endpoints []EndpointView
	// TLS is the server's CA bundle and client certificate as facts about the
	// certificates (nil: none set); never the key.
	TLS *TLSView
	// Warnings are things that aren't failures yet (a client certificate about
	// to expire), shown with the health.
	Warnings []HealthWarning
	// Governance is who is accountable for the server, how sensitive it is and
	// whether it is being retired (decision 88).
	Governance GovernanceView
}

// HasAuth reports whether the server has a stored credential.
func (v ServerView) HasAuth() bool { return len(v.Credentials) > 0 }

// views completes listed rows with counts, health and the effective policy.
func views(ctx context.Context, q *dbgen.Queries, rows []dbgen.ListMCPServersRow) ([]ServerView, error) {
	out := make([]ServerView, len(rows))
	if len(rows) == 0 {
		return out, nil
	}
	settings, err := q.GetPlatformSettings(ctx)
	if err != nil {
		return nil, err
	}
	ps, err := LoadProviders(ctx, q)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	index := make(map[uuid.UUID]int, len(rows))
	for i, r := range rows {
		ids[i], index[r.McpServer.ID] = r.McpServer.ID, i
		out[i] = ServerView{
			Server: r.McpServer, TeamSlug: r.TeamSlug, TeamName: r.TeamName, TeamStatus: r.TeamStatus, ReviewedByName: r.ReviewedByName,
			EffectivePolicy: authz.EffectivePolicy(r.TeamPolicyOverride, settings.PublishDefaultPolicy),
			Requirement:     RequirementOf(r.McpServer, ps),
		}
	}
	servers := make([]dbgen.McpServer, len(rows))
	for i, r := range rows {
		servers[i] = r.McpServer
	}
	creds, err := credentialViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	machines, err := machineViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	tlsByServer, err := tlsRows(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	endpoints, err := endpointViews(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	digest, err := digestsWith(ctx, q, servers, creds, machines, tlsByServer)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	for i := range out {
		out[i].ReviewDigest = digest[out[i].Server.ID]
		out[i].Credentials = creds[out[i].Server.ID]
		out[i].Endpoints = endpoints[out[i].Server.ID]
		out[i].Machine = machines[out[i].Server.ID]
		out[i].TLS = viewOfTLS(tlsByServer[out[i].Server.ID], now)
		out[i].Warnings = out[i].TLS.warnings()
	}
	stats, err := q.MCPCapabilityStats(ctx, ids)
	if err != nil {
		return nil, err
	}
	for _, st := range stats {
		v := &out[index[st.ServerID]]
		v.Counts.add(st.Kind, st.Listed)
		v.Approved.add(st.Kind, st.Approved)
		if v.Server.PublishState == StatePublished {
			v.PendingChanges += st.Unapproved
		}
	}
	health, err := q.LatestMCPHealthChecks(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range health {
		out[index[health[i].ServerID]].Health = &health[i]
	}
	if err := oauthViews(ctx, q, out, index, ps); err != nil {
		return nil, err
	}
	if err := secretViews(ctx, q, out, index); err != nil {
		return nil, err
	}
	if err := governanceViews(ctx, q, out, index, now); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) view(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (ServerView, error) {
	r, err := q.GetMCPServerView(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return ServerView{}, errNoServer
	} else if err != nil {
		return ServerView{}, err
	}
	vs, err := views(ctx, q, []dbgen.ListMCPServersRow{{McpServer: r.McpServer, TeamSlug: r.TeamSlug, TeamName: r.TeamName,
		TeamPolicyOverride: r.TeamPolicyOverride, TeamStatus: r.TeamStatus, ReviewedByName: r.ReviewedByName}})
	if err != nil {
		return ServerView{}, err
	}
	return vs[0], nil
}

// ListParams filter and page server lists by (name, id).
type ListParams struct {
	Search       *string // LIKE-escaped by the service
	PublishState *string
	ChangesOnly  bool
	Team         string // admin list: a team slug or ID ("" for all)
	// ProviderID narrows to servers that require that auth provider (or,
	// in oauth mode, link it).
	ProviderID *uuid.UUID
	// AuthMode narrows to servers with that upstream auth mode.
	AuthMode  *string
	AfterName *string
	AfterID   *uuid.UUID
	Limit     int32
}

func (p ListParams) query() dbgen.ListMCPServersParams {
	out := dbgen.ListMCPServersParams{PublishState: p.PublishState, ChangesOnly: p.ChangesOnly, AfterName: p.AfterName, PageSize: p.Limit,
		AuthMode: p.AuthMode}
	if p.Search != nil {
		escaped := store.EscapeLike(*p.Search)
		out.Search = &escaped
	}
	if p.AfterID != nil {
		out.AfterID = uuid.NullUUID{UUID: *p.AfterID, Valid: true}
	}
	if p.ProviderID != nil {
		out.ProviderID = uuid.NullUUID{UUID: *p.ProviderID, Valid: true}
	}
	return out
}

// ListTeam lists a team's servers (members; platform admins and auditors).
func (s *Service) ListTeam(ctx context.Context, a authz.Actor, ref string, p ListParams) ([]ServerView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	qp := p.query()
	qp.TeamID = uuid.NullUUID{UUID: ta.team.ID, Valid: true}
	rows, err := s.q.ListMCPServers(ctx, qp)
	if err != nil {
		return nil, err
	}
	return views(ctx, s.q, rows)
}

// GetTeam returns one of a team's servers.
func (s *Service) GetTeam(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (ServerView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return ServerView{}, err
	}
	if _, err := teamServer(ctx, s.q, ta.team.ID, id, false); err != nil {
		return ServerView{}, err
	}
	return s.view(ctx, s.q, id)
}

// AdminList lists every team's servers (platform admins and auditors). An
// unknown team filter lists nothing.
func (s *Service) AdminList(ctx context.Context, a authz.Actor, p ListParams) ([]ServerView, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	qp := p.query()
	if p.Team != "" {
		t, err := teams.Resolve(ctx, s.q, p.Team)
		if errors.Is(err, errTeamNotFound) || isNotFound(err) {
			return []ServerView{}, nil
		} else if err != nil {
			return nil, err
		}
		qp.TeamID = uuid.NullUUID{UUID: t.ID, Valid: true}
	}
	rows, err := s.q.ListMCPServers(ctx, qp)
	if err != nil {
		return nil, err
	}
	return views(ctx, s.q, rows)
}

func isNotFound(err error) bool {
	e, ok := apperr.As(err)
	return ok && e.Status == 404
}

// AdminGet returns any server (platform admins and auditors).
func (s *Service) AdminGet(ctx context.Context, a authz.Actor, id uuid.UUID) (ServerView, error) {
	if !a.CanReadPlatform() {
		return ServerView{}, errPlatformRead
	}
	return s.view(ctx, s.q, id)
}
