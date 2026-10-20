// Package calls records and reads the metadata of every list and call
// through a gateway (SPEC.md §5 "Call record", docs/decisions.md decision
// 14): who, through which gateway, to which server and tool, the outcome,
// latency and sizes. Arguments and results are never stored here; payload
// capture (opt-in, internal/capture) writes them in the same transaction
// through Record's hook.
package calls

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Outcomes (the API's McpCallOutcome).
const (
	OutcomeOK            = "ok"
	OutcomeToolError     = "tool_error"
	OutcomeDenied        = "denied"
	OutcomeUpstreamError = "upstream_error"
	OutcomeTimeout       = "timeout"
	OutcomeTooLarge      = "too_large"
	OutcomeBadRequest    = "bad_request"
	// OutcomeNeedsAuthorization: not forwarded because the person must
	// connect (or reconnect) an account; the client got a consent link
	// (JSON-RPC -32042).
	OutcomeNeedsAuthorization = "needs_authorization"
	// OutcomeRateLimited: not forwarded because a rate limit was exceeded
	// (HTTP 429, JSON-RPC -32029); the error class names the limit.
	OutcomeRateLimited = "rate_limited"
)

// ValidOutcome reports whether o is an outcome.
func ValidOutcome(o string) bool {
	switch o {
	case OutcomeOK, OutcomeToolError, OutcomeDenied, OutcomeUpstreamError, OutcomeTimeout, OutcomeTooLarge, OutcomeBadRequest,
		OutcomeNeedsAuthorization, OutcomeRateLimited:
		return true
	}
	return false
}

var (
	errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")
	errForbidden    = apperr.Forbidden("Only team owners and admins, and platform admins and auditors, can see the team's calls")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errCallNotFound = apperr.NotFound("call_not_found", "Call not found")
)

// Principal kinds (the API's CallPrincipal.kind).
const (
	PrincipalAPIKey         = "api_key"
	PrincipalOAuth          = "oauth"
	PrincipalServiceAccount = "service_account"
)

// Call is one record. Strings are bounded by Record.
type Call struct {
	RequestID, Method, ExposedName string
	Gateway                        dbgen.Gateway
	Server                         *dbgen.McpServer
	CapabilityID                   uuid.UUID
	// PrincipalKind says who called (PrincipalAPIKey when empty): a person
	// with a key (UserID, APIKeyID) or a connected client (UserID,
	// OAuthGrantID, OAuthClientName, and OAuthClientKind: "metadata" for a
	// Client ID Metadata Document, else "registered"), or a service account
	// (ServiceAccount* and its key in APIKeyID). KeyName is the key's name as
	// it was.
	PrincipalKind                          string
	UserID, APIKeyID                       uuid.UUID
	KeyName                                string
	ServiceAccountID, ServiceAccountTeamID uuid.UUID
	ServiceAccountName                     string
	OAuthGrantID                           uuid.UUID
	OAuthClientName, OAuthClientKind       string
	ClientName                             string
	Outcome, ErrorClass                    string
	Latency                                time.Duration
	RequestBytes, ResponseBytes            int64
	// ProviderSlug is the auth provider the capability required (empty:
	// none). Never a token.
	ProviderSlug string
	// A call relayed by a trusted agent platform (decision 66): the agent
	// (its ID and name at the platform), the platform and, when the token
	// named a person, whether they were present. UserID is then the person
	// and the principal the relay service account; without a person only the
	// agent and platform are set (the call is the account's own).
	AgentID, AgentName string
	ViaPlatformID      uuid.UUID
	ViaPlatformName    string
	PersonPresent      *bool

	// IdentitySent says whether the identity token was attached to the
	// request to the server (nil: the call was not forwarded).
	IdentitySent *bool

	// TraceID is the request's trace when it was sampled (32 hex digits;
	// empty: tracing off or the request not sampled).
	TraceID string
}

// Error classes of calls refused because they came from an agent (decision
// 66, #57), with the outcomes they are recorded under: ClassNeedsConnection
// with OutcomeNeedsAuthorization (the person must connect an account; no
// link was given) and ClassPersonNotPresent with OutcomeDenied (the server or
// capability requires a present person).
const (
	ClassNeedsConnection  = "needs_connection"
	ClassPersonNotPresent = "person_not_present"
)

// pgBool is a nullable bool query parameter (nil: NULL, no filter).
func pgBool(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *b, Valid: true}
}

func clip(s string, n int) *string {
	if s == "" {
		return nil
	}
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	out := string(r)
	return &out
}

func null(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }

// Recorded is a stored call's ID and time.
type Recorded = dbgen.InsertMCPCallRow

// After runs in the transaction that stored a call (payload capture). Its
// error never loses the call record: its writes are rolled back to a
// savepoint and the error is returned as Record's captureErr.
type After func(ctx context.Context, q *dbgen.Queries, rec Recorded) error

// Record stores a call, then runs after (when not nil) in the same
// transaction.
func Record(ctx context.Context, pool *pgxpool.Pool, c Call, after After) (captureErr, err error) {
	p := insertParams(c)
	if after == nil {
		_, err := dbgen.New(pool).InsertMCPCall(ctx, p)
		return nil, err
	}
	err = store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		rec, err := q.InsertMCPCall(ctx, p)
		if err != nil {
			return err
		}
		captureErr = pgx.BeginFunc(ctx, tx, func(sp pgx.Tx) error { return after(ctx, dbgen.New(sp), rec) })
		return nil
	})
	if err != nil {
		return nil, err
	}
	return captureErr, nil
}

func insertParams(c Call) dbgen.InsertMCPCallParams {
	if c.PrincipalKind == "" {
		c.PrincipalKind = PrincipalAPIKey
	}
	p := dbgen.InsertMCPCallParams{
		RequestID: c.RequestID, Method: c.Method, ExposedName: clip(c.ExposedName, 1100),
		GatewayID: c.Gateway.ID, GatewaySlug: c.Gateway.Slug, GatewayName: c.Gateway.Name, GatewayTeamID: c.Gateway.TeamID,
		CapabilityID: null(c.CapabilityID), PrincipalKind: c.PrincipalKind, UserID: null(c.UserID), ApiKeyID: null(c.APIKeyID),
		KeyName: clip(c.KeyName, 100), ServiceAccountID: null(c.ServiceAccountID), ServiceAccountName: clip(c.ServiceAccountName, 64),
		ServiceAccountTeamID: null(c.ServiceAccountTeamID), OauthGrantID: null(c.OAuthGrantID), OauthClientName: clip(c.OAuthClientName, 200),
		OauthClientKind: clip(c.OAuthClientKind, 20), ClientName: clip(c.ClientName, 200), Outcome: c.Outcome, ErrorClass: clip(c.ErrorClass, 64),
		LatencyMs: int32(min(c.Latency.Milliseconds(), 1<<31-1)), RequestBytes: max(c.RequestBytes, 0), ResponseBytes: max(c.ResponseBytes, 0),
		ProviderSlug: clip(c.ProviderSlug, 48), IdentitySent: c.IdentitySent,
		AgentID: clip(c.AgentID, 128), AgentName: clip(c.AgentName, 200), ViaPlatformID: null(c.ViaPlatformID),
		ViaPlatformName: clip(c.ViaPlatformName, 100), PersonPresent: c.PersonPresent, TraceID: clip(c.TraceID, 32),
	}
	if c.Server != nil {
		p.ServerID, p.ServerTeamID = null(c.Server.ID), null(c.Server.TeamID)
		p.ServerSlug, p.ServerName = &c.Server.Slug, &c.Server.Name
	}
	return p
}

// Service reads call records.
type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

// New returns a Service.
func New(pool *pgxpool.Pool) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q}
}

// Filter narrows and pages a list (newest first, by ID).
type Filter struct {
	Gateway, Server, User, ServiceAccount *uuid.UUID
	Outcome                               *string
	// IdentitySent keeps calls whose identity token was (true) or was not
	// (false) sent to the server.
	IdentitySent *bool
	From, To     *time.Time
	BeforeID     *int64
	Team         string // admin list: a team slug or ID
	Limit        int32
}

func (f Filter) query() dbgen.ListMCPCallsParams {
	p := dbgen.ListMCPCallsParams{Outcome: f.Outcome, IdentitySent: pgBool(f.IdentitySent), OccurredFrom: f.From, OccurredTo: f.To, BeforeID: f.BeforeID, PageSize: f.Limit}
	if f.Gateway != nil {
		p.GatewayID = null(*f.Gateway)
	}
	if f.Server != nil {
		p.ServerID = null(*f.Server)
	}
	if f.User != nil {
		p.UserID = null(*f.User)
	}
	if f.ServiceAccount != nil {
		p.ServiceAccountID = null(*f.ServiceAccount)
	}
	return p
}

// Row is a call as a list shows it. Captured: a captured payload is stored
// that the caller may open (team views: captured under that team's
// gateway or server switch, and the caller is one of its owners or admins;
// admin views: any).
type Row struct {
	dbgen.ListMCPCallsRow
	Captured bool
}

// CapturedFor reports whether a call's payload was captured under team's
// switch (its gateway's or its server's).
func CapturedFor(r dbgen.ListMCPCallsRow, team uuid.UUID) bool {
	return (r.PayloadByGateway && r.GatewayTeamID.Valid && r.GatewayTeamID.UUID == team) ||
		(r.PayloadByServer && r.ServerTeamID.Valid && r.ServerTeamID.UUID == team)
}

// TeamScope is a team's call list as seen by an actor.
type TeamScope struct {
	Team dbgen.Team
	// Role is the actor's role in the team ("" for platform staff who are not
	// members).
	Role string
}

// teamScope resolves a team whose calls the actor may see: its owners and
// admins, and platform admins and auditors.
func (s *Service) teamScope(ctx context.Context, a authz.Actor, ref string) (TeamScope, error) {
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return TeamScope{}, err
	}
	role, err := teams.MemberRole(ctx, s.q, t.ID, a.UserID)
	if err != nil {
		return TeamScope{}, err
	}
	switch {
	case a.CanReadPlatform() || authz.RoleAtLeast(role, authz.RoleAdmin):
	case role == "":
		return TeamScope{}, errTeamNotFound
	default:
		return TeamScope{}, errForbidden
	}
	return TeamScope{Team: t, Role: role}, nil
}

func teamRows(rows []dbgen.ListMCPCallsRow, sc TeamScope) []Row {
	out := make([]Row, len(rows))
	owner := authz.RoleAtLeast(sc.Role, authz.RoleAdmin)
	for i, r := range rows {
		out[i] = Row{ListMCPCallsRow: r, Captured: owner && CapturedFor(r, sc.Team.ID)}
	}
	return out
}

func adminRows(rows []dbgen.ListMCPCallsRow) []Row {
	out := make([]Row, len(rows))
	for i, r := range rows {
		out[i] = Row{ListMCPCallsRow: r, Captured: r.PayloadByGateway || r.PayloadByServer}
	}
	return out
}

// ListTeam lists calls through the team's gateways, to its servers, or by
// its service accounts through any gateway (team owners and admins;
// platform admins and auditors).
func (s *Service) ListTeam(ctx context.Context, a authz.Actor, ref string, f Filter) ([]Row, error) {
	sc, err := s.teamScope(ctx, a, ref)
	if err != nil {
		return nil, err
	}
	p := f.query()
	p.TeamID = null(sc.Team.ID)
	rows, err := s.q.ListMCPCalls(ctx, p)
	if err != nil {
		return nil, err
	}
	return teamRows(rows, sc), nil
}

// TeamCall returns one call listTeamCalls would list for the team (404
// call_not_found otherwise), with the actor's scope.
func (s *Service) TeamCall(ctx context.Context, a authz.Actor, ref string, id int64) (Row, TeamScope, error) {
	sc, err := s.teamScope(ctx, a, ref)
	if err != nil {
		return Row{}, sc, err
	}
	rows, err := s.q.ListMCPCalls(ctx, dbgen.ListMCPCallsParams{TeamID: null(sc.Team.ID), CallID: &id, PageSize: 1})
	if err != nil {
		return Row{}, sc, err
	}
	if len(rows) == 0 {
		return Row{}, sc, errCallNotFound
	}
	return teamRows(rows, sc)[0], sc, nil
}

// AdminList lists every call (platform admins and auditors). An unknown
// team filter lists nothing.
func (s *Service) AdminList(ctx context.Context, a authz.Actor, f Filter) ([]Row, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	p := f.query()
	if f.Team != "" {
		t, err := teams.Resolve(ctx, s.q, f.Team)
		if e, ok := apperr.As(err); ok && e.Status == 404 {
			return []Row{}, nil
		} else if err != nil {
			return nil, err
		}
		p.TeamID = null(t.ID)
	}
	rows, err := s.q.ListMCPCalls(ctx, p)
	if err != nil {
		return nil, err
	}
	return adminRows(rows), nil
}

// AdminCall returns any call (platform admins and auditors).
func (s *Service) AdminCall(ctx context.Context, a authz.Actor, id int64) (Row, error) {
	if !a.CanReadPlatform() {
		return Row{}, errPlatformRead
	}
	rows, err := s.q.ListMCPCalls(ctx, dbgen.ListMCPCallsParams{CallID: &id, PageSize: 1})
	if err != nil {
		return Row{}, err
	}
	if len(rows) == 0 {
		return Row{}, errCallNotFound
	}
	return adminRows(rows)[0], nil
}
