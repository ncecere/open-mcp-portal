// Package personsecrets is per-person secrets as an upstream auth mode
// (decision 72, docs/person-secrets.md): each person pastes their own API
// key or token for a server in person_secret mode once, it is sealed with
// ENCRYPTION_KEY and bound to (person, server, origin), shown only as a
// hint, and their calls to that server carry it as the server's team chose
// (a header, a bearer token or a query parameter).
//
// A secret is never returned by any operation, logged, audited or recorded:
// this package hands the bare value to exactly one caller, Resolve, which
// internal/mcpgw uses to build one forwarded call. The rules that bound it:
//
//   - F-1/F-3 extended: a secret is for the origin its server had when it
//     was entered. The registry deletes everyone's secrets when the URL moves
//     to another origin, the mode changes or the placement changes; Resolve
//     refuses one whose origin is not the server's now.
//   - The person decides. Entering and replacing happen in a browser session
//     (My connections, or a link a call returned), for a server they may use
//     through a gateway now, and the request names the origin they were shown.
//   - A service account has no secret (roadmap #26 is shared team secrets).
package personsecrets

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

const (
	// RequestTTL is a link's life; requestKeep how long expired and used ones
	// answer 410 before they are deleted.
	RequestTTL  = 10 * time.Minute
	requestKeep = 24 * time.Hour
	// MaxOpenRequests per person; the oldest open one is dropped.
	MaxOpenRequests = 20
	idBytes         = 32
)

// Reasons a call needs the person to act (secret_requests.reason, and the
// call's error class).
const (
	ReasonMissing  = "secret_missing"
	ReasonRejected = "secret_rejected"
)

// Secret statuses.
const (
	StatusActive   = "active"
	StatusRejected = "rejected"
)

var (
	errNoRequest      = apperr.NotFound("secret_request_not_found", "This link was made for someone else, or doesn't exist")
	errRequestExpired = apperr.New(http.StatusGone, "secret_request_expired", "This link expired. Run the tool again.")
	errServerNotFound = apperr.NotFound("server_not_found", "That server isn't one you can use, or it doesn't exist")
	errNotSecretMode  = apperr.Conflict("not_person_secret", "That server doesn't ask people for their own key")
	errChanged        = apperr.Conflict("server_changed",
		"The server's address changed since you opened this page. Reload and review it again.")
	errShown        = apperr.New(http.StatusBadRequest, "invalid_secret", "Send the server's origin as the page showed it")
	errNoSecret     = apperr.NotFound("person_secret_not_found", "There is no key entered for that server")
	errValueNeeded  = apperr.Invalid("secret_required", "Enter the key")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errAdminOnly    = apperr.Forbidden("Only platform admins can do this")
	errSetupRole    = apperr.Forbidden("Only editors of the server's team can use their key to read its capabilities")

	requestIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
)

// ErrInactive: the person is not active (suspended). Their secrets are kept
// (decision 53) and used again when they are reactivated, but never while
// suspended.
var ErrInactive = errors.New("personsecrets: the person is not active")

// ErrNotConfigured: the server isn't in person_secret mode, or has no
// placement.
var ErrNotConfigured = errors.New("personsecrets: the server doesn't use person secrets")

// Service is the person secrets.
type Service struct {
	pool   *pgxpool.Pool
	q      *dbgen.Queries
	box    *secrets.Box
	log    *slog.Logger
	appURL string
	// Reachable lists the servers a person may use through a gateway now
	// (gateways.Service.ReachableServers; nil: none): the servers they may
	// enter a secret for, the rule calls use.
	Reachable func(ctx context.Context, u dbgen.User) ([]gateways.ReachableServer, error)
	// Registry reads a server's capabilities with the setup person's secret
	// (nil: not done).
	Registry *registry.Service
	now      func() time.Time
}

// New returns a Service. appURL is the portal's own URL (links).
func New(pool *pgxpool.Pool, box *secrets.Box, appURL string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{pool: pool, q: dbgen.New(pool), box: box, log: log, appURL: strings.TrimRight(appURL, "/"), now: time.Now}
}

// SetClock sets the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// RequestURL is the link a call returns for a request.
func (s *Service) RequestURL(requestID string) string {
	return s.appURL + "/connect/secret/" + requestID
}

func randomID() string {
	b := make([]byte, idBytes)
	_, _ = rand.Read(b) // crypto/rand never fails on supported platforms
	return base64.RawURLEncoding.EncodeToString(b)
}

func requestDigest(id string) string {
	sum := sha256.Sum256([]byte(id))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// RequestAAD binds a request's sealed ID to its digest.
func RequestAAD(digest string) []byte { return []byte("secret_request:" + digest) }

// ServerRef names a server with its team.
type ServerRef struct {
	ID                             uuid.UUID
	Slug, Name, TeamSlug, TeamName string
}

func displayName(u dbgen.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// --- The call path ----------------------------------------------------

// --- What a person sees ------------------------------------------------

// Mine is one server a person has, or may have, a secret for.
type Mine struct {
	Server ServerRef
	Config registry.PersonSecretInput
	// Origin is the server's origin now: what an entered secret is bound to.
	Origin string
	// Has: a secret is entered; the fields below describe it.
	Has                               bool
	Hint, Status                      string
	CreatedAt                         time.Time
	RotatedAt, RejectedAt, LastUsedAt *time.Time
	// Reachable: the person may use the server through a gateway now (they
	// may enter or replace a secret).
	Reachable bool
	// CanSetup: the person is an editor of the server's team, so their key can
	// read its capabilities; IsSetup: it does now.
	CanSetup, IsSetup bool
}

// Revoked-or-missing secrets are not listed; a secret whose server a person
// can no longer reach is, so they can take it back.

// ListMine lists the servers in person_secret mode the person may use through
// a gateway now, and every secret they have (reachable or not), by server name.
func (s *Service) ListMine(ctx context.Context, a authz.Actor) ([]Mine, error) {
	return s.listFor(ctx, a.UserID, true)
}

// AdminList lists a person's secrets (platform admins and auditors): the same
// rows without the servers they could still enter one for.
func (s *Service) AdminList(ctx context.Context, a authz.Actor, userID uuid.UUID) ([]Mine, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := s.q.GetUser(ctx, userID); err != nil {
		return nil, store.NotFound(err)
	}
	return s.listFor(ctx, userID, false)
}

func (s *Service) listFor(ctx context.Context, userID uuid.UUID, withReachable bool) ([]Mine, error) {
	u, err := s.q.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListPersonSecretsForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	var reach []gateways.ReachableServer
	if withReachable && s.Reachable != nil {
		if reach, err = s.Reachable(ctx, u); err != nil {
			return nil, err
		}
	}
	reachable := map[uuid.UUID]bool{}
	out := []Mine{}
	add := func(sv dbgen.McpServer, ref ServerRef) error {
		if reachable[sv.ID] {
			return nil
		}
		if _, ok := registry.PersonSecretConfig(sv); !ok {
			return nil
		}
		reachable[sv.ID] = true
		m, err := s.mine(ctx, u, sv, ref)
		if err != nil {
			return err
		}
		m.Reachable = true
		out = append(out, m)
		return nil
	}
	for _, r := range reach {
		if err := add(r.Server, ServerRef{ID: r.Server.ID, Slug: r.Server.Slug, Name: r.Server.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}); err != nil {
			return nil, err
		}
	}
	if withReachable {
		// An editor can enter a key for their team's servers before any gateway
		// offers one: the setup key is what reads its capabilities.
		eds, err := s.q.ListPersonSecretServersForEditor(ctx, userID)
		if err != nil {
			return nil, err
		}
		for _, r := range eds {
			if err := add(r.McpServer, ServerRef{ID: r.McpServer.ID, Slug: r.McpServer.Slug, Name: r.McpServer.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}); err != nil {
				return nil, err
			}
		}
	}
	for _, r := range rows {
		if reachable[r.ServerID] {
			continue
		}
		sv, err := s.q.GetMCPServer(ctx, r.ServerID)
		if err != nil {
			return nil, err
		}
		m, err := s.mine(ctx, u, sv, ServerRef{ID: r.ServerID, Slug: r.ServerSlug, Name: r.ServerName, TeamSlug: r.TeamSlug, TeamName: r.TeamName})
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	slices.SortFunc(out, func(a, b Mine) int {
		if c := strings.Compare(a.Server.Name, b.Server.Name); c != 0 {
			return c
		}
		return strings.Compare(a.Server.ID.String(), b.Server.ID.String())
	})
	return out, nil
}

func (s *Service) mine(ctx context.Context, u dbgen.User, sv dbgen.McpServer, ref ServerRef) (Mine, error) {
	cfg, _ := registry.PersonSecretConfig(sv)
	m := Mine{Server: ref, Config: cfg, Origin: registry.OriginOf(sv.URL)}
	ps, err := s.q.GetPersonSecret(ctx, dbgen.GetPersonSecretParams{UserID: u.ID, ServerID: sv.ID})
	switch {
	case err == nil:
		m.Has, m.Hint, m.Status = true, ps.Hint, ps.Status
		m.CreatedAt, m.RotatedAt, m.RejectedAt, m.LastUsedAt = ps.CreatedAt, ps.RotatedAt, ps.RejectedAt, ps.LastUsedAt
	case !errors.Is(store.NotFound(err), store.ErrNotFound):
		return m, err
	}
	role, err := teams.MemberRole(ctx, s.q, sv.TeamID, u.ID)
	if err != nil {
		return m, err
	}
	m.CanSetup = u.Status == "active" && authz.CheckServerEdit(role) == nil
	m.IsSetup = m.CanSetup && sv.SecretSetupUserID == (uuid.NullUUID{UUID: u.ID, Valid: true})
	return m, nil
}

// reachableServer finds a server in person_secret mode the person may use
// through a gateway now, or, for an editor of its team, any of the team's
// (404 server_not_found otherwise: another team's private server and an
// unknown one answer the same).
func (s *Service) reachableServer(ctx context.Context, u dbgen.User, id uuid.UUID) (dbgen.McpServer, error) {
	var reach []gateways.ReachableServer
	if s.Reachable != nil {
		var err error
		if reach, err = s.Reachable(ctx, u); err != nil {
			return dbgen.McpServer{}, err
		}
	}
	var sv dbgen.McpServer
	if i := slices.IndexFunc(reach, func(r gateways.ReachableServer) bool { return r.Server.ID == id }); i >= 0 {
		sv = reach[i].Server
	} else {
		// Not offered by any gateway yet: an editor of the server's team may
		// still enter a key (it reads the server's capabilities). Anyone else,
		// and an unknown server, answer the same.
		eds, err := s.q.ListPersonSecretServersForEditor(ctx, u.ID)
		if err != nil {
			return dbgen.McpServer{}, err
		}
		j := slices.IndexFunc(eds, func(r dbgen.ListPersonSecretServersForEditorRow) bool { return r.McpServer.ID == id })
		if j < 0 {
			return dbgen.McpServer{}, errServerNotFound
		}
		sv = eds[j].McpServer
	}
	if _, ok := registry.PersonSecretConfig(sv); !ok {
		return dbgen.McpServer{}, errNotSecretMode
	}
	return sv, nil
}

// --- The link ----------------------------------------------------------
