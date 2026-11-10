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
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/limits"
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
	// machine fetches and caches the bearer tokens of servers in
	// machine_oauth mode (machine.go).
	machine *upstream.MachineTokens
	limits  *limits.Service
	// now is the clock of the governance loop (SetClock; tests).
	now func() time.Time
	// ObserveLeader is told whether this replica led the latest governance run.
	ObserveLeader func(leader bool)
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
	return &Service{pool: pool, q: dbgen.New(pool), box: box, client: client, nets: nets, log: log, machine: upstream.NewMachineTokens(client), limits: limits.New(pool, log)}
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

// Target is how to reach a server for a forwarded call (internal/mcpgw):
// see target.
func (s *Service) Target(ctx context.Context, sv dbgen.McpServer) (upstream.Target, error) {
	return s.forwardTarget(ctx, sv)
}

// Client is the guarded client servers are reached with.
func (s *Service) Client() *upstream.Client { return s.client }

// target reads how to reach a server, decrypting its credential parts. The URL
// is checked against the address rule again (it may have been saved under
// the development allowance, or the allowlist may have changed since).
func (s *Service) target(ctx context.Context, sv dbgen.McpServer) (upstream.Target, error) {
	t := upstream.Target{URL: sv.URL, Timeout: timeout(sv), ServerID: sv.ID.String(), ServerSlug: sv.Slug}
	if sv.MaxConcurrent != nil {
		t.MaxConcurrent = *sv.MaxConcurrent
	}
	if _, err := s.client.NormalizeURL(ctx, sv.URL); err != nil {
		msg := errNotAllowedNow.Message
		if e, ok := apperr.As(err); ok {
			msg = "The server's URL is not allowed: " + e.Message
		}
		return t, &upstream.Error{Class: upstream.ClassNotAllowed, Message: msg}
	}
	if AuthModeOf(sv) != AuthNone {
		creds, err := s.openCredentials(ctx, sv)
		if err != nil {
			return t, err
		}
		t.Credentials = creds
	}
	if AuthModeOf(sv) == AuthMachineOAuth {
		// The portal's own token for this server, the same for every caller
		// (a person, a service account, a health check). A failure is an
		// *upstream.Error: auth when the client was refused, else
		// machine_auth_unavailable.
		tok, uerr := s.machineToken(ctx, sv, "")
		if uerr != nil {
			return t, uerr
		}
		t.BearerToken = tok
	}
	tid, err := s.openTLS(ctx, sv)
	if err != nil {
		return t, err
	}
	t.TLS = tid
	return t, nil
}
