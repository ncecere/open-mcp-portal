// Package registry is the MCP server registry (SPEC.md §5, §7 phase 2;
// docs/registry.md): the remote MCP servers teams register, the tools,
// resources, resource templates and prompts discovered on them, their
// health, and publishing them to the company catalog under the platform's
// publishing policy.
//
// Header values are sealed with ENCRYPTION_KEY (internal/secrets) and never
// returned, logged or audited: only whether one is set, the header's name
// and a hint of the value's last four characters. Every mutation authorizes,
// changes and writes its audit entry in one transaction. Network exchanges
// with servers (internal/upstream) happen outside transactions.
package registry

import (
	"context"
	"errors"
	"log/slog"
	"regexp"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

var (
	errTeamNotFound   = apperr.NotFound("team_not_found", "Team not found")
	errNoServer       = apperr.NotFound("mcp_server_not_found", "MCP server not found")
	errNoCapability   = apperr.NotFound("mcp_capability_not_found", "Capability not found")
	errSlugTaken      = apperr.Conflict("slug_taken", "Another MCP server already uses that slug")
	errAdminOnly      = apperr.Forbidden("Only platform admins can do this")
	errPlatformRead   = apperr.Forbidden("Only platform admins and auditors can see this")
	errTeamArchived   = apperr.Conflict("team_archived", "This team is archived and read-only")
	errInvalidKind    = apperr.Invalid("invalid_kind", "kind must be tool, resource, resource_template or prompt")
	errNoteTooLong    = apperr.Invalid("invalid_note", "The note must be at most 2000 characters")
	errUndecryptable  = &upstream.Error{Class: upstream.ClassConfig, Message: "The stored header value can't be decrypted with the current ENCRYPTION_KEY. Enter it again."}
	errNotAllowedNow  = &upstream.Error{Class: upstream.ClassNotAllowed, Message: "The server's URL is not allowed by this installation's address rules."}
	slugRE            = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$`)
	headerNameRE      = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
	defaultTimeoutSec = int32(30)
)

// Headers the gateway sets itself, which a server's static header may not
// replace.
var reservedHeaders = map[string]bool{
	"host": true, "content-type": true, "content-length": true, "accept": true, "connection": true,
	"transfer-encoding": true, "mcp-protocol-version": true, "mcp-session-id": true, "mcp-method": true, "mcp-name": true,
	"last-event-id": true, "user-agent": true, "cookie": true, "origin": true,
	// Gateways send the caller's identity in this header when the static
	// header is Authorization (docs/upstream-identity.md), and a person's
	// provider token with its provider's slug in these (decision 27).
	"mcp-gateway-identity": true, "mcp-gateway-provider": true, "mcp-gateway-provider-token": true,
}

// Service is the registry.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *secrets.Box
	client *upstream.Client
	nets   *Networks
	log    *slog.Logger
	// oauth configures upstream OAuth (SetOAuth).
	oauth OAuthSettings
	// notify is told what people may want to hear about (SetNotifier).
	notify Notifier
	// ids signs the identity token a manual Test sends (SetIdentity).
	ids IdentitySigner
}

// New returns a Service. client reaches the servers (its AllowPrivate is the
// development allowance, which also applies to URLs when saved). Its
// Networks should be a *Networks (NewNetworks), whose admin entries this
// service edits; when it has none, one without deployment entries is set.
func New(pool *pgxpool.Pool, box *secrets.Box, client *upstream.Client, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	nets, _ := client.Networks.(*Networks)
	if nets == nil {
		nets = NewNetworks(pool, nil, log)
		if client.Networks == nil {
			client.Networks = nets
		}
	}
	return &Service{pool: pool, q: dbgen.New(pool), box: box, client: client, nets: nets, log: log}
}

// ServerAAD binds a server's sealed header value to its row.
func ServerAAD(id uuid.UUID) []byte { return []byte("mcp_server:" + id.String()) }

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// teamAccess is a team as seen by an actor.
type teamAccess struct {
	team dbgen.Team
	role string // "" when not a member
}

// access resolves a team the actor may see: members, and platform admins
// and auditors. Others get 404, so a team's existence is not revealed.
func access(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string) (teamAccess, error) {
	t, err := teams.Resolve(ctx, q, ref)
	if err != nil {
		return teamAccess{}, err
	}
	role, err := teams.MemberRole(ctx, q, t.ID, a.UserID)
	if err != nil {
		return teamAccess{}, err
	}
	role = a.TeamRole(t.ID, role) // a publisher token acts in its own team only
	if role == "" && !a.CanReadPlatform() {
		return teamAccess{}, errTeamNotFound
	}
	return teamAccess{team: t, role: role}, nil
}

// writable checks a team role rule and that the team is active.
func (ta teamAccess) writable(rule func(string) error) error {
	if err := rule(ta.role); err != nil {
		return err
	}
	if ta.team.Status != teams.StatusActive {
		return errTeamArchived
	}
	return nil
}

// teamServer returns one of the team's servers (404 for another team's).
func teamServer(ctx context.Context, q *dbgen.Queries, teamID, id uuid.UUID, lock bool) (dbgen.McpServer, error) {
	var (
		sv  dbgen.McpServer
		err error
	)
	if lock {
		sv, err = q.LockMCPServer(ctx, id)
	} else {
		sv, err = q.GetMCPServer(ctx, id)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && sv.TeamID != teamID) {
		return sv, errNoServer
	}
	return sv, err
}

func anyServer(ctx context.Context, q *dbgen.Queries, id uuid.UUID, lock bool) (dbgen.McpServer, error) {
	var (
		sv  dbgen.McpServer
		err error
	)
	if lock {
		sv, err = q.LockMCPServer(ctx, id)
	} else {
		sv, err = q.GetMCPServer(ctx, id)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return sv, errNoServer
	}
	return sv, err
}

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
	// ReviewDigest binds a review to what its reader saw (ReviewDigest).
	ReviewDigest string
}

// HasAuth reports whether the server has a stored header.
func (v ServerView) HasAuth() bool { return v.Server.AuthValueCipher != nil }

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
	digest, err := digests(ctx, q, servers)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].ReviewDigest = digest[out[i].Server.ID]
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

// CreateInput registers a server. AuthHeaderName and AuthValue are both
// empty (no credentials) or both set.
type CreateInput struct {
	Slug, Name, Description, URL string
	AuthHeaderName, AuthValue    string
	TimeoutSeconds               int32 // 0: the default (30)
	Enabled                      bool
	// Requirement is the user-authorization requirement (nil: none).
	Requirement *RequirementInput
	// CapturePayloads records calls' contents (team owners and admins only).
	CapturePayloads bool
	// AuthMode is none, static_header or oauth ("": static_header with a
	// header, else none); OAuth configures oauth.
	AuthMode string
	OAuth    *OAuthInput
	// SendIdentity sends the identity token (nil: true, except authMode none
	// on a public or unresolvable host: false; decisions 45 and 64).
	SendIdentity *bool
}

// UpdateInput holds optional changes. AuthHeaderName "" removes the header
// and its value; AuthValue nil keeps the stored value.
type UpdateInput struct {
	Name, Description, URL    *string
	AuthHeaderName, AuthValue *string
	TimeoutSeconds            *int32
	Enabled                   *bool
	// SetRequirement changes the requirement to Requirement (nil removes
	// it); false keeps it.
	SetRequirement bool
	Requirement    *RequirementInput
	// CapturePayloads changes the capture switch (nil keeps it; only team
	// owners and admins may change it).
	CapturePayloads *bool
	// AuthMode changes the upstream auth mode (nil keeps it); OAuth changes
	// the sign-in (fields nil keep their values).
	AuthMode *string
	OAuth    *OAuthInput
	// SendIdentity changes whether the identity token is sent (nil keeps it).
	SendIdentity *bool
}

// errCaptureRole: only the server team's owners and admins switch capture.
var errCaptureRole = apperr.New(403, "capture_role",
	"Only the team's owners and admins can choose whether calls' contents are recorded")

// setCapture applies a capture switch change (docs/phase6-operations.md
// "Payload capture"): team owners and admins only; not a review trigger.
func setCapture(ctx context.Context, q *dbgen.Queries, role string, row *dbgen.McpServer, on bool) error {
	if row.CapturePayloads == on {
		return nil
	}
	if !authz.RoleAtLeast(role, authz.RoleAdmin) {
		return errCaptureRole
	}
	if err := q.SetMCPServerCapture(ctx, dbgen.SetMCPServerCaptureParams{ID: row.ID, CapturePayloads: on}); err != nil {
		return err
	}
	row.CapturePayloads = on
	return nil
}

func checkFields(name, description string, timeout int32) error {
	if n := len([]rune(strings.TrimSpace(name))); n < 1 || n > 100 {
		return apperr.Invalid("invalid_name", "Name must be 1-100 characters")
	}
	if len([]rune(description)) > 2000 {
		return apperr.Invalid("invalid_description", "Description must be at most 2000 characters")
	}
	if timeout < 1 || timeout > 120 {
		return apperr.Invalid("invalid_timeout", "Timeout must be between 1 and 120 seconds")
	}
	return nil
}

func checkHeader(name, value string) error {
	if !headerNameRE.MatchString(name) || reservedHeaders[strings.ToLower(name)] {
		return apperr.Invalid("invalid_auth_header", "The header name must be a valid HTTP header such as Authorization or X-API-Key")
	}
	if value == "" || len(value) > 4096 || strings.ContainsAny(value, "\r\n\x00") {
		return apperr.Invalid("invalid_auth_value", "The header value must be 1-4096 characters on one line")
	}
	return nil
}

// valueHint is the last four characters of a value of at least eight.
func valueHint(v string) string {
	r := []rune(v)
	if len(r) < 8 {
		return ""
	}
	return string(r[len(r)-4:])
}

// snapshot is a server's audited configuration: never the header value or
// its ciphertext, only whether one is set.
func snapshot(s dbgen.McpServer) map[string]any {
	out := map[string]any{"slug": s.Slug, "name": s.Name, "description": s.Description, "url": s.URL,
		"timeoutSeconds": s.TimeoutSeconds, "enabled": s.Enabled, "hasAuth": s.AuthValueCipher != nil,
		"publishState": s.PublishState, "requirement": requirementSnapshot(s), "capturePayloads": s.CapturePayloads,
		"authMode": AuthModeOf(s), "sendIdentity": s.SendIdentity}
	if s.AuthHeaderName != nil {
		out["authHeaderName"] = *s.AuthHeaderName
	}
	return out
}

// Created is the outcome of registering a server: the server, and its
// first discovery (Refresh when it worked, Failure when not).
type Created struct {
	View    ServerView
	Refresh *RefreshResult
	Failure *TestResult
	// SetupRequired: created in oauth mode, so nobody has signed in yet and
	// capabilities weren't read.
	SetupRequired bool
}

// Create registers a server (team editors and above) and reads its
// capabilities at once. The server is created even when that fails.
// Audited as mcp_server.create (and mcp_server.refresh when discovery works).
func (s *Service) Create(ctx context.Context, a authz.Actor, ref string, in CreateInput) (Created, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = strings.TrimSpace(in.Name)
	if in.TimeoutSeconds == 0 {
		in.TimeoutSeconds = defaultTimeoutSec
	}
	mode, err := createMode(in)
	if err != nil {
		return Created{}, err
	}
	var plan *oauthPlan
	if mode == AuthOAuth {
		// Discovery and registration happen before the transaction: check
		// what can be checked first.
		ta, err := access(ctx, s.q, a, ref)
		if err != nil {
			return Created{}, err
		}
		if err := ta.writable(authz.CheckServerEdit); err != nil {
			return Created{}, err
		}
		if err := oauthConflicts(in.AuthHeaderName, in.Requirement != nil); err != nil {
			return Created{}, err
		}
		if !slugRE.MatchString(in.Slug) {
			return Created{}, apperr.Invalid("invalid_slug",
				"Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
		}
		if err := checkFields(in.Name, in.Description, in.TimeoutSeconds); err != nil {
			return Created{}, err
		}
		u, err := s.client.NormalizeURL(ctx, in.URL)
		if err != nil {
			return Created{}, err
		}
		if plan, err = s.prepareOAuth(ctx, s.q, u, in.Name, in.OAuth, nil); err != nil {
			return Created{}, err
		}
	}
	// Send identity token: an explicit value is kept; else on, except for a
	// server with no authentication on a public (or unresolvable) host
	// (decision 64). The host lookup happens here, outside the transaction.
	sendIdentity := in.SendIdentity == nil || *in.SendIdentity
	if in.SendIdentity == nil && mode == AuthNone {
		if u, err := s.client.NormalizeURL(ctx, in.URL); err == nil {
			sendIdentity = s.defaultSendIdentity(ctx, mode, u).SendIdentity
		}
	}
	id := uuid.New()
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerEdit); err != nil {
			return err
		}
		p, err := s.insertParams(ctx, id, ta.team.ID, a, in)
		if err != nil {
			return err
		}
		if p.AuthProviderID, p.AuthScopes, err = checkRequirement(ctx, q, in.Requirement, uuid.NullUUID{}); err != nil {
			return err
		}
		p.AuthMode, p.SendIdentity = mode, sendIdentity
		row, err := q.InsertMCPServer(ctx, p)
		if apperr.IsUniqueViolation(err, "mcp_servers_slug_key") {
			return errSlugTaken
		} else if err != nil {
			return err
		}
		if err := setCapture(ctx, q, ta.role, &row, in.CapturePayloads); err != nil {
			return err
		}
		e := a.Audit("mcp_server.create", "mcp_server", id.String())
		e.TeamID, e.After = ta.team.ID, snapshot(row)
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		if plan == nil {
			return nil
		}
		prov, err := s.insertProvider(ctx, q, a, row, plan)
		if err != nil {
			return err
		}
		return authUpdateAudit(ctx, q, a, nil, nil, row, &prov, map[string]any{"registered": plan.registered,
			"clientIdChanged": true, "clientSecretChanged": plan.secret != nil, "connectionsReset": 0})
	})
	if err != nil {
		return Created{}, err
	}
	sv, err := s.q.GetMCPServer(ctx, id)
	if err != nil {
		return Created{}, err
	}
	var out Created
	if mode == AuthOAuth {
		// Nobody has signed in yet: capabilities are read after the setup
		// sign-in (authorize-setup).
		out.SetupRequired = true
		out.View, err = s.view(ctx, s.q, id)
		return out, err
	}
	res, fail, err := s.refresh(ctx, a, sv)
	if err != nil {
		return Created{}, err
	}
	out.Refresh, out.Failure = res, fail
	out.View, err = s.view(ctx, s.q, id)
	return out, err
}

func (s *Service) insertParams(ctx context.Context, id, teamID uuid.UUID, a authz.Actor, in CreateInput) (dbgen.InsertMCPServerParams, error) {
	if !slugRE.MatchString(in.Slug) {
		return dbgen.InsertMCPServerParams{}, apperr.Invalid("invalid_slug",
			"Slug must be 1-48 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if err := checkFields(in.Name, in.Description, in.TimeoutSeconds); err != nil {
		return dbgen.InsertMCPServerParams{}, err
	}
	u, err := s.client.NormalizeURL(ctx, in.URL)
	if err != nil {
		return dbgen.InsertMCPServerParams{}, err
	}
	p := dbgen.InsertMCPServerParams{ID: id, TeamID: teamID, Slug: in.Slug, Name: in.Name, Description: in.Description, URL: u,
		TimeoutSeconds: in.TimeoutSeconds, Enabled: in.Enabled, CreatedBy: by(a), AuthScopes: []string{}}
	if in.AuthHeaderName != "" || in.AuthValue != "" {
		if err := checkHeader(in.AuthHeaderName, in.AuthValue); err != nil {
			return p, err
		}
		if p.AuthValueCipher, err = s.box.Seal([]byte(in.AuthValue), ServerAAD(id)); err != nil {
			return p, err
		}
		name := in.AuthHeaderName
		p.AuthHeaderName, p.AuthValueHint = &name, valueHint(in.AuthValue)
	}
	return p, nil
}

// Update changes a server's settings (team editors and above); the slug
// never changes. A new URL or header forgets the stored health. A new URL
// also forgets when capabilities were read and reads them again from the new
// endpoint, so nothing is approved on the strength of the old one. A URL with
// another origin never keeps the stored header value (422 auth_value_required
// unless a new value comes with it, or the header goes). Audited as
// mcp_server.update with whether the header value changed (never the value)
// and, for another origin, the old and new one.
// A request that changes nothing (for example the capture switch resent at its
// current value) writes nothing: no revision bump and no audit entry, as a
// member role change to the same role.
func (s *Service) Update(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (ServerView, error) {
	// Upstream OAuth changes need the network (discovery, registration,
	// revocation): that happens first, against the server as read now; the
	// transaction then checks the revision again.
	pre, err := s.prepareUpdate(ctx, a, ref, id, in, expectedRevision)
	if err != nil {
		return ServerView{}, err
	}
	var moved bool
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerEdit); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		p, valueChanged, err := s.applyUpdate(ctx, cur, in, pre.mode)
		if err != nil {
			return err
		}
		if in.SetRequirement {
			if p.AuthProviderID, p.AuthScopes, err = checkRequirement(ctx, q, in.Requirement, cur.AuthProviderID); err != nil {
				return err
			}
		}
		if pre.mode == AuthOAuth {
			if err := oauthConflicts(deref(p.AuthHeaderName), p.AuthProviderID.Valid); err != nil {
				return err
			}
		}
		if in.SendIdentity != nil {
			p.SendIdentity = *in.SendIdentity
		}
		curProv := pre.provider
		planChanged := pre.plan != nil && (curProv == nil || !planUnchanged(*curProv, pre.plan))
		if unchanged(cur, p, valueChanged, in.CapturePayloads) && !planChanged && pre.mode == AuthModeOf(cur) {
			return nil
		}
		ps, err := LoadProviders(ctx, q)
		if err != nil {
			return err
		}
		before, err := effectiveAll(ctx, q, cur, ps)
		if err != nil {
			return err
		}
		p.UpdatedBy = by(a)
		row, err := q.UpdateMCPServer(ctx, p)
		if err != nil {
			return err
		}
		if in.CapturePayloads != nil {
			if err := setCapture(ctx, q, ta.role, &row, *in.CapturePayloads); err != nil {
				return err
			}
		}
		reset := int64(0)
		if row.AuthProviderID != cur.AuthProviderID {
			// Overrides with other scopes belong to the old provider.
			if reset, err = q.ResetMCPCapabilityScopeOverrides(ctx, id); err != nil {
				return err
			}
		}
		// People allowed this server to receive their provider token at the
		// origin and for the provider it had then (F-3): not for another.
		// A path-only edit keeps the grants.
		if reason := grantResetReason(cur, row); reason != "" {
			if err := resetProviderGrants(ctx, q, a, ta.team.ID, id, reason, originChange(cur.URL, row.URL)); err != nil {
				return err
			}
		}
		after, err := effectiveAll(ctx, q, row, ps)
		if err != nil {
			return err
		}
		e := a.Audit("mcp_server.update", "mcp_server", id.String())
		e.TeamID, e.Before, e.After = ta.team.ID, snapshot(cur), snapshot(row)
		e.Metadata = map[string]any{"authValueChanged": valueChanged}
		for k, v := range originChange(cur.URL, row.URL) {
			e.Metadata[k] = v
		}
		if reset > 0 {
			e.Metadata["overridesReset"] = reset
		}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		authChanged, err := s.applyOAuth(ctx, q, a, cur, row, pre)
		if err != nil {
			return err
		}
		switch {
		case row.URL != cur.URL:
			err = s.resubmit(ctx, q, a, ta.team, cur, "url_changed", "The server's URL changed; review it again.")
		case authChanged:
			err = s.resubmit(ctx, q, a, ta.team, cur, "upstream_auth_changed", noteUpstreamAuthChanged)
		case widened(before, after):
			err = s.resubmit(ctx, q, a, ta.team, cur, "requirement_changed", noteRequirementChanged)
		}
		if err != nil {
			return err
		}
		if moved = row.URL != cur.URL; moved {
			if err := q.ClearMCPServerRefreshed(ctx, id); err != nil {
				return err
			}
		}
		// A new address or credentials make the stored health meaningless.
		if valueChanged || row.URL != cur.URL || !equalPtr(row.AuthHeaderName, cur.AuthHeaderName) || AuthModeOf(row) != AuthModeOf(cur) {
			return q.ForgetMCPHealthChecks(ctx, id)
		}
		return nil
	})
	if err != nil {
		return ServerView{}, err
	}
	if moved {
		// Best effort, like Create: a failure is stored as the refresh error.
		sv, err := s.q.GetMCPServer(ctx, id)
		if err != nil {
			return ServerView{}, err
		}
		if sv.Enabled {
			if _, _, err := s.refresh(ctx, a, sv); err != nil {
				return ServerView{}, err
			}
		}
	}
	return s.view(ctx, s.q, id)
}

// updatePrep is what an update decided before its transaction.
type updatePrep struct {
	// mode is the auth mode after the update.
	mode string
	// provider is the server-bound provider before the update (nil: none).
	provider *dbgen.AuthProvider
	// plan is the new sign-in (nil: unchanged).
	plan *oauthPlan
	// revoked: leaving oauth, the connections were revoked (results).
	revoked map[uuid.UUID]any
}

// prepareUpdate runs what an update needs from the network: discovery and
// registration when the server is (or stays) in oauth mode and its URL or
// sign-in changes, and revoking connections when it leaves oauth.
func (s *Service) prepareUpdate(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (updatePrep, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return updatePrep{}, err
	}
	if err := ta.writable(authz.CheckServerEdit); err != nil {
		return updatePrep{}, err
	}
	cur, err := teamServer(ctx, s.q, ta.team.ID, id, false)
	if err != nil {
		return updatePrep{}, err
	}
	if cur.Revision != expectedRevision {
		return updatePrep{}, apperr.Stale()
	}
	out := updatePrep{mode: AuthModeOf(cur)}
	if in.AuthMode != nil {
		switch *in.AuthMode {
		case AuthNone, AuthStaticHeader, AuthOAuth:
			out.mode = *in.AuthMode
		default:
			return out, apperr.Invalid("invalid_auth_mode", "authMode must be none, static_header or oauth")
		}
	} else if out.mode != AuthOAuth {
		// Without a mode, a header added or removed decides it.
		header := deref(cur.AuthHeaderName)
		if in.AuthHeaderName != nil {
			header = *in.AuthHeaderName
		}
		out.mode = AuthNone
		if header != "" {
			out.mode = AuthStaticHeader
		}
	}
	if out.mode != AuthOAuth {
		// An oauth input without oauth mode is ignored (clients may always
		// send it with its defaults).
		in.OAuth = nil
	}
	if AuthModeOf(cur) == AuthOAuth {
		p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return out, err
		} else if err == nil {
			out.provider = &p
		}
	}
	newURL := cur.URL
	if in.URL != nil {
		if newURL, err = s.client.NormalizeURL(ctx, *in.URL); err != nil {
			return out, err
		}
	}
	// Refused before any network exchange with the new host (F-1); applyUpdate
	// checks again under the row lock.
	if err := requireValueForOrigin(cur, newURL, in, out.mode); err != nil {
		return out, err
	}
	switch {
	case out.mode == AuthOAuth && (AuthModeOf(cur) != AuthOAuth || in.OAuth != nil || newURL != cur.URL || out.provider == nil):
		header := deref(cur.AuthHeaderName)
		if in.AuthHeaderName != nil {
			header = *in.AuthHeaderName
		}
		requirement := cur.AuthProviderID.Valid
		if in.SetRequirement {
			requirement = in.Requirement != nil
		}
		if err := oauthConflicts(header, requirement); err != nil {
			return out, err
		}
		name := cur.Name
		if in.Name != nil {
			name = strings.TrimSpace(*in.Name)
		}
		if out.plan, err = s.prepareOAuth(ctx, s.q, newURL, name, in.OAuth, out.provider); err != nil {
			return out, err
		}
	case out.mode != AuthOAuth && out.provider != nil && s.oauth.Hooks != nil:
		out.revoked = s.oauth.Hooks.RevokeConnections(ctx, *out.provider)
	}
	return out, nil
}

// applyOAuth stores an update's sign-in changes in its transaction and
// reports whether they need review again (a switch to oauth, another
// authorization server, or a scope not asked for before). A URL change,
// another authorization server or another client ID erases every
// connection's tokens; leaving oauth deletes the connections. Audited as
// mcp_server.auth_update.
func (s *Service) applyOAuth(ctx context.Context, q *dbgen.Queries, a authz.Actor, cur, row dbgen.McpServer, pre updatePrep) (bool, error) {
	beforeMode, afterMode := AuthModeOf(cur), AuthModeOf(row)
	prov := pre.provider
	switch {
	case afterMode == AuthOAuth && pre.plan != nil && prov == nil:
		np, err := s.insertProvider(ctx, q, a, row, pre.plan)
		if err != nil {
			return false, err
		}
		return true, authUpdateAudit(ctx, q, a, &cur, nil, row, &np, map[string]any{"registered": pre.plan.registered,
			"clientIdChanged": true, "clientSecretChanged": pre.plan.secret != nil, "connectionsReset": 0})
	case afterMode == AuthOAuth && prov != nil:
		// Tokens are for one resource: another origin always starts over, even
		// when discovery at the new host happens to give an identical plan (F-1).
		originMoved := !sameOrigin(cur.URL, row.URL)
		if originMoved && pre.plan == nil {
			return false, errors.New("registry: another origin without a sign-in plan")
		}
		if !originMoved && (pre.plan == nil || planUnchanged(*prov, pre.plan)) {
			if row.Name != cur.Name {
				if err := q.RenameServerProvider(ctx, dbgen.RenameServerProviderParams{Name: row.Name, ServerID: uuid.NullUUID{UUID: row.ID, Valid: true}}); err != nil {
					return false, err
				}
			}
			if row.SendIdentity != cur.SendIdentity {
				return false, authUpdateAudit(ctx, q, a, &cur, prov, row, prov, nil)
			}
			return false, nil
		}
		np, err := s.updateProvider(ctx, q, a, row.Name, *prov, pre.plan)
		if err != nil {
			return false, err
		}
		otherServer := deref(prov.Issuer) != deref(np.Issuer) || deref(prov.AuthorizationServer) != deref(np.AuthorizationServer)
		clientChanged := prov.ClientID != np.ClientID || prov.LinkProviderID != np.LinkProviderID
		var reset int64
		if otherServer || clientChanged || row.URL != cur.URL {
			if reset, err = q.ResetProviderConnections(ctx, dbgen.ResetProviderConnectionsParams{ProviderID: prov.ID,
				ErrorClass: ptr("server_auth_changed")}); err != nil {
				return false, err
			}
		}
		meta := map[string]any{"registered": pre.plan.registered, "clientIdChanged": clientChanged,
			"clientSecretChanged": pre.plan.secret != nil || (pre.plan.clearSecret && prov.ClientSecretCipher != nil), "connectionsReset": reset}
		for k, v := range originChange(cur.URL, row.URL) {
			meta[k] = v
		}
		if err := authUpdateAudit(ctx, q, a, &cur, prov, row, &np, meta); err != nil {
			return false, err
		}
		return otherServer || originMoved || widensScopes(nonNil(prov.DefaultScopes), nonNil(np.DefaultScopes)), nil
	case afterMode != AuthOAuth && prov != nil:
		if s.oauth.Hooks != nil {
			if err := s.oauth.Hooks.DeleteConnections(ctx, q, a, *prov, pre.revoked, "server_auth_changed"); err != nil {
				return false, err
			}
		}
		if err := q.DeleteServerProvider(ctx, uuid.NullUUID{UUID: row.ID, Valid: true}); err != nil {
			return false, err
		}
		return false, authUpdateAudit(ctx, q, a, &cur, prov, row, nil, map[string]any{"connectionsReset": 0,
			"connectionsDeleted": len(pre.revoked)})
	case beforeMode != afterMode || cur.SendIdentity != row.SendIdentity:
		return false, authUpdateAudit(ctx, q, a, &cur, nil, row, nil, nil)
	}
	return false, nil
}

func ptr[T any](v T) *T { return &v }

func (s *Service) applyUpdate(ctx context.Context, cur dbgen.McpServer, in UpdateInput, mode string) (dbgen.UpdateMCPServerParams, bool, error) {
	p := dbgen.UpdateMCPServerParams{ID: cur.ID, Name: cur.Name, Description: cur.Description, URL: cur.URL,
		AuthHeaderName: cur.AuthHeaderName, AuthValueCipher: cur.AuthValueCipher, AuthValueHint: cur.AuthValueHint,
		TimeoutSeconds: cur.TimeoutSeconds, Enabled: cur.Enabled, AuthProviderID: cur.AuthProviderID, AuthScopes: nonNil(cur.AuthScopes),
		AuthMode: mode, SendIdentity: cur.SendIdentity}
	setIf(&p.Name, in.Name)
	p.Name = strings.TrimSpace(p.Name)
	setIf(&p.Description, in.Description)
	setIf(&p.TimeoutSeconds, in.TimeoutSeconds)
	setIf(&p.Enabled, in.Enabled)
	if err := checkFields(p.Name, p.Description, p.TimeoutSeconds); err != nil {
		return p, false, err
	}
	if in.URL != nil {
		u, err := s.client.NormalizeURL(ctx, *in.URL)
		if err != nil {
			return p, false, err
		}
		p.URL = u
	}
	if err := requireValueForOrigin(cur, p.URL, in, mode); err != nil {
		return p, false, err
	}
	if mode == AuthNone {
		// authMode none removes the static header with its value.
		if (in.AuthHeaderName != nil && *in.AuthHeaderName != "") || (in.AuthValue != nil && *in.AuthValue != "") {
			return p, false, apperr.Invalid("invalid_auth_header", "authMode none has no static header")
		}
		p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = nil, nil, ""
		return p, cur.AuthValueCipher != nil, nil
	}
	removed := in.AuthHeaderName != nil && *in.AuthHeaderName == "" && cur.AuthValueCipher != nil
	if err := s.applyAuth(&p, cur, in); err != nil {
		return p, false, err
	}
	if mode == AuthStaticHeader && p.AuthHeaderName == nil {
		return p, false, apperr.Invalid("invalid_auth_header", "Enter the static header's name and value")
	}
	return p, in.AuthValue != nil || removed, nil
}

// applyAuth applies a header change: "" removes it; a new name keeps the
// stored value unless a new one is given.
func (s *Service) applyAuth(p *dbgen.UpdateMCPServerParams, cur dbgen.McpServer, in UpdateInput) error {
	if in.AuthHeaderName != nil && *in.AuthHeaderName == "" {
		if in.AuthValue != nil && *in.AuthValue != "" {
			return apperr.Invalid("invalid_auth_header", "Enter the header's name with its value")
		}
		p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = nil, nil, ""
		return nil
	}
	name := ""
	if cur.AuthHeaderName != nil {
		name = *cur.AuthHeaderName
	}
	setIf(&name, in.AuthHeaderName)
	if in.AuthValue == nil {
		if in.AuthHeaderName == nil {
			return nil
		}
		if cur.AuthValueCipher == nil {
			return apperr.Invalid("invalid_auth_value", "Enter the header's value")
		}
		if err := checkHeader(name, "x"); err != nil {
			return err
		}
		p.AuthHeaderName = &name
		return nil
	}
	if err := checkHeader(name, *in.AuthValue); err != nil {
		return err
	}
	ct, err := s.box.Seal([]byte(*in.AuthValue), ServerAAD(cur.ID))
	if err != nil {
		return err
	}
	p.AuthHeaderName, p.AuthValueCipher, p.AuthValueHint = &name, ct, valueHint(*in.AuthValue)
	return nil
}

// unchanged reports whether an update would leave the server as it is: the
// same settings, no new or removed header value, and the capture switch
// absent or at its current value.
func unchanged(cur dbgen.McpServer, p dbgen.UpdateMCPServerParams, valueChanged bool, capture *bool) bool {
	return !valueChanged && p.Name == cur.Name && p.Description == cur.Description && p.URL == cur.URL &&
		p.TimeoutSeconds == cur.TimeoutSeconds && p.Enabled == cur.Enabled && equalPtr(p.AuthHeaderName, cur.AuthHeaderName) &&
		p.AuthProviderID == cur.AuthProviderID && slices.Equal(p.AuthScopes, cur.AuthScopes) && p.SendIdentity == cur.SendIdentity &&
		p.AuthMode == AuthModeOf(cur) &&
		(capture == nil || *capture == cur.CapturePayloads)
}

// grantResetReason says why an update ends people's grants for a server
// ("": it doesn't): the URL moved to another origin, or the requirement
// names another provider (or none).
func grantResetReason(cur, row dbgen.McpServer) string {
	switch {
	case !sameOrigin(cur.URL, row.URL):
		return "origin_changed"
	case row.AuthProviderID != cur.AuthProviderID:
		return "provider_changed"
	}
	return ""
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}

func equalPtr(a, b *string) bool { return (a == nil) == (b == nil) && (a == nil || *a == *b) }

// Delete removes a server with its capabilities and health (team owners and
// admins). A server in oauth mode first has its connections revoked at the
// authorization server (best effort); its server-bound provider and the
// connections go with it (provider_connection.revoke, reason
// server_deleted). Audited as mcp_server.delete.
func (s *Service) Delete(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) error {
	var revoked map[uuid.UUID]any
	if ta, err := access(ctx, s.q, a, ref); err == nil && ta.writable(authz.CheckServerManage) == nil {
		if sv, err := teamServer(ctx, s.q, ta.team.ID, id, false); err == nil && AuthModeOf(sv) == AuthOAuth && s.oauth.Hooks != nil {
			if p, err := s.q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true}); err == nil {
				revoked = s.oauth.Hooks.RevokeConnections(ctx, p)
			}
		}
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := ta.writable(authz.CheckServerManage); err != nil {
			return err
		}
		cur, err := teamServer(ctx, q, ta.team.ID, id, true)
		if err != nil {
			return err
		}
		if p, err := q.GetServerProvider(ctx, uuid.NullUUID{UUID: id, Valid: true}); err == nil && s.oauth.Hooks != nil {
			if err := s.oauth.Hooks.DeleteConnections(ctx, q, a, p, revoked, "server_deleted"); err != nil {
				return err
			}
		} else if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		if err := resetProviderGrants(ctx, q, a, ta.team.ID, id, "server_deleted", nil); err != nil {
			return err
		}
		if err := q.DeleteMCPServer(ctx, id); err != nil {
			return err
		}
		e := a.Audit("mcp_server.delete", "mcp_server", id.String())
		e.TeamID, e.Before = ta.team.ID, snapshot(cur)
		return audit.Record(ctx, q, e)
	})
}

// Target is how to reach a server for a forwarded call (internal/mcpgw):
// see target.
func (s *Service) Target(ctx context.Context, sv dbgen.McpServer) (upstream.Target, error) {
	return s.target(ctx, sv)
}

// Client is the guarded client servers are reached with.
func (s *Service) Client() *upstream.Client { return s.client }

// target reads how to reach a server, decrypting its header value. The URL
// is checked against the address rule again (it may have been saved under
// the development allowance, or the allowlist may have changed since).
func (s *Service) target(ctx context.Context, sv dbgen.McpServer) (upstream.Target, error) {
	t := upstream.Target{URL: sv.URL, Timeout: timeout(sv), ServerID: sv.ID.String()}
	if _, err := s.client.NormalizeURL(ctx, sv.URL); err != nil {
		msg := errNotAllowedNow.Message
		if e, ok := apperr.As(err); ok {
			msg = "The server's URL is not allowed: " + e.Message
		}
		return t, &upstream.Error{Class: upstream.ClassNotAllowed, Message: msg}
	}
	if sv.AuthHeaderName != nil && sv.AuthValueCipher != nil {
		plain, err := s.box.Open(sv.AuthValueCipher, ServerAAD(sv.ID))
		if err != nil {
			return t, errUndecryptable
		}
		t.HeaderName, t.HeaderValue = *sv.AuthHeaderName, string(plain)
	}
	return t, nil
}
