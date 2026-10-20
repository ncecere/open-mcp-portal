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
//   - An agent's call (decisions 65 to 68) uses a person's secret only when
//     the person allowed agents for that server, and never gets a link.
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
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
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
	// ReasonAgentsNotAllowed: the person has a usable secret but hasn't
	// allowed agents to use it (a relayed call only; never a link).
	ReasonAgentsNotAllowed = "agents_not_allowed"
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

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func displayName(u dbgen.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// --- The call path ----------------------------------------------------

// CallContext is the call that needs a secret.
type CallContext struct {
	User    dbgen.User
	Server  dbgen.McpServer
	Gateway dbgen.Gateway
	// CapabilityID, Kind, ExposedName and Title describe the capability.
	CapabilityID             uuid.UUID
	Kind, ExposedName, Title string
	// NoConsent: the call is an agent's, with no browser to open a link in
	// (decision 66). A missing or rejected secret still answers
	// *NeedsSecret, but no link is made: nothing is stored.
	NoConsent bool
}

// Secret is a person's secret as one call uses it. Value is the bare secret;
// it lives only in memory, for the length of the call.
type Secret struct {
	Value                   string
	Placement, Name, Prefix string
	// ID and Sealed identify the stored value that was read, so a rejection
	// marks that value and not one entered since.
	ID     uuid.UUID
	Sealed []byte
}

// NeedsSecret: the person must enter (or enter again) their key. URL is the
// link (empty for an agent's call).
type NeedsSecret struct {
	Reason, RequestID, URL string
	Server                 ServerRef
	Label                  string
}

func (e *NeedsSecret) Error() string { return "personsecrets: a key is needed (" + e.Reason + ")" }

// Resolve returns the person's secret for a call to a person_secret server,
// or a *NeedsSecret (nothing is sent anywhere), or ErrInactive. It is the
// only way a secret leaves this package. There is no fallback to any other
// credential: without a usable secret the call doesn't go.
func (s *Service) Resolve(ctx context.Context, cc CallContext) (Secret, error) {
	cfg, ok := registry.PersonSecretConfig(cc.Server)
	if !ok {
		return Secret{}, ErrNotConfigured
	}
	if cc.User.Status != "active" {
		return Secret{}, ErrInactive
	}
	origin := registry.OriginOf(cc.Server.URL)
	ps, err := s.q.GetPersonSecret(ctx, dbgen.GetPersonSecretParams{UserID: cc.User.ID, ServerID: cc.Server.ID})
	switch {
	case errors.Is(store.NotFound(err), store.ErrNotFound):
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonMissing)
	case err != nil:
		return Secret{}, err
	case ps.Origin != origin:
		// Entered for another origin (a reset would have deleted it): never
		// sent here.
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonMissing)
	case ps.Status != StatusActive:
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonRejected)
	}
	plain, err := s.box.Open(ps.SecretCipher, registry.PersonSecretAAD(ps.ID))
	if err != nil {
		// Sealed under a key that is gone: enter it again.
		s.log.WarnContext(ctx, "a person secret can't be decrypted with the current ENCRYPTION_KEY", "secret_id", ps.ID)
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonRejected)
	}
	if cc.NoConsent && !ps.AllowAgents {
		return Secret{}, s.need(ctx, cc, cfg, origin, ReasonAgentsNotAllowed)
	}
	if err := s.q.TouchPersonSecret(ctx, ps.ID); err != nil {
		s.log.WarnContext(ctx, "could not record a person secret's use", "secret_id", ps.ID, "err", err)
	}
	return Secret{Value: string(plain), Placement: cfg.Placement, Name: cfg.Name, Prefix: cfg.Prefix, ID: ps.ID, Sealed: ps.SecretCipher}, nil
}

// Reject marks a secret the server refused (401 or 403) as rejected, so it
// is not sent again until the person replaces it. Only the value that was
// sent is marked. It reports whether a secret was marked.
func (s *Service) Reject(ctx context.Context, sec Secret) (bool, error) {
	n, err := s.q.RejectPersonSecret(ctx, dbgen.RejectPersonSecretParams{ID: sec.ID, SecretCipher: sec.Sealed})
	return n > 0, err
}

// NeedAgain makes the *NeedsSecret for a secret that was just rejected (the
// same answer a later call gets).
func (s *Service) NeedAgain(ctx context.Context, cc CallContext) error {
	cfg, ok := registry.PersonSecretConfig(cc.Server)
	if !ok {
		return ErrNotConfigured
	}
	return s.need(ctx, cc, cfg, registry.OriginOf(cc.Server.URL), ReasonRejected)
}

func (s *Service) need(ctx context.Context, cc CallContext, cfg registry.PersonSecretInput, origin, reason string) error {
	ref, err := s.serverRef(ctx, s.q, cc.Server.ID)
	if err != nil {
		return err
	}
	n := &NeedsSecret{Reason: reason, Server: ref, Label: label(cfg)}
	if cc.NoConsent || reason == ReasonAgentsNotAllowed {
		return n
	}
	id, err := s.request(ctx, cc, origin, reason)
	if err != nil {
		return err
	}
	n.RequestID, n.URL = id, s.RequestURL(id)
	return n
}

func label(cfg registry.PersonSecretInput) string {
	if cfg.Label != "" {
		return cfg.Label
	}
	return "API key"
}

func (s *Service) serverRef(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (ServerRef, error) {
	r, err := q.GetServerRef(ctx, id)
	if err != nil {
		return ServerRef{}, err
	}
	return ServerRef{ID: r.ID, Slug: r.Slug, Name: r.Name, TeamSlug: r.TeamSlug, TeamName: r.TeamName}, nil
}

// request returns the ID of an open link for the call, making one when none
// stays valid for at least two more minutes. A person has at most
// MaxOpenRequests open; the oldest is dropped.
func (s *Service) request(ctx context.Context, cc CallContext, origin, reason string) (string, error) {
	var id string
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		open, err := q.FindOpenSecretRequest(ctx, dbgen.FindOpenSecretRequestParams{UserID: cc.User.ID, GatewayID: cc.Gateway.ID,
			CapabilityID: cc.CapabilityID, ServerID: cc.Server.ID, ServerOrigin: origin, Reason: reason, ValidUntil: s.now().Add(2 * time.Minute)})
		if err == nil {
			if b, err := s.box.Open(open.IDCipher, RequestAAD(open.IDDigest)); err == nil {
				id = string(b)
				return nil
			}
		} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		id = randomID()
		digest := requestDigest(id)
		ct, err := s.box.Seal([]byte(id), RequestAAD(digest))
		if err != nil {
			return err
		}
		title := []rune(cc.Title)
		if len(title) > 200 {
			title = title[:200]
		}
		if _, err := q.InsertSecretRequest(ctx, dbgen.InsertSecretRequestParams{
			IDDigest: digest, IDCipher: ct, UserID: cc.User.ID, ServerID: cc.Server.ID, ServerOrigin: origin, Reason: reason,
			GatewayID: cc.Gateway.ID, GatewaySlug: cc.Gateway.Slug, GatewayName: cc.Gateway.Name, CapabilityID: cc.CapabilityID,
			CapabilityKind: cc.Kind, ExposedName: cc.ExposedName, CapabilityTitle: string(title), ExpiresAt: s.now().Add(RequestTTL),
		}); err != nil {
			return err
		}
		if _, err := q.TrimOpenSecretRequests(ctx, dbgen.TrimOpenSecretRequestsParams{UserID: cc.User.ID, Keep: MaxOpenRequests}); err != nil {
			return err
		}
		_, err = q.DeleteStaleSecretRequests(ctx, s.now().Add(-requestKeep))
		return err
	})
	return id, err
}

// Cleanup deletes links that expired a day ago (the retention loop).
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	return s.q.DeleteStaleSecretRequests(ctx, s.now().Add(-requestKeep))
}

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
	AllowAgents                       bool
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
		m.Has, m.Hint, m.Status, m.AllowAgents = true, ps.Hint, ps.Status, ps.AllowAgents
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

// SetInput is what a person sends: the key (nil keeps the stored one; needed
// when there is none), the origin of the server they were shown, whether
// agents may use it (nil keeps), and whether to read the server's
// capabilities with it.
type SetInput struct {
	Value       *string
	Origin      string
	AllowAgents *bool
	UseForSetup bool
}

// Set enters, replaces or changes the caller's secret for a server. Refusals:
// 404 server_not_found (a server they may not use, or none), 409
// not_person_secret, 409 server_changed (the origin differs from what they
// were shown), 422 invalid_secret_value or secret_required, 403 when they
// ask to read the server with a key and are not an editor of its team.
// Audited as person_secret.create or person_secret.rotate (and
// person_secret.agents_update when the agents switch changes on its own);
// never the value.
func (s *Service) Set(ctx context.Context, a authz.Actor, serverID uuid.UUID, in SetInput) (Mine, error) {
	if in.Origin == "" {
		return Mine{}, errShown
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return Mine{}, err
	}
	if u.Status != "active" {
		return Mine{}, apperr.Forbidden("Your account is suspended")
	}
	if _, err := s.reachableServer(ctx, u, serverID); err != nil {
		return Mine{}, err
	}
	var value string
	if in.Value != nil {
		// A pasted key often carries a trailing newline or space.
		value = strings.TrimSpace(*in.Value)
		if err := registry.CheckPersonSecretValue(value); err != nil {
			return Mine{}, err
		}
	}
	var setup bool
	var ref ServerRef
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// The server's row is locked, so an edit of its address, mode or
		// placement (which deletes the secrets) is before or after this,
		// never between.
		sv, err := q.LockMCPServer(ctx, serverID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errServerNotFound
		} else if err != nil {
			return err
		}
		if _, ok := registry.PersonSecretConfig(sv); !ok {
			return errNotSecretMode
		}
		origin := registry.OriginOf(sv.URL)
		if origin != in.Origin {
			return errChanged
		}
		if in.UseForSetup {
			role, err := teams.MemberRole(ctx, q, sv.TeamID, u.ID)
			if err != nil {
				return err
			}
			if authz.CheckServerEdit(role) != nil {
				return errSetupRole
			}
		}
		cur, err := q.LockPersonSecret(ctx, dbgen.LockPersonSecretParams{UserID: u.ID, ServerID: serverID})
		exists := err == nil
		if err != nil && !errors.Is(store.NotFound(err), store.ErrNotFound) {
			return err
		}
		if in.Value == nil && !exists {
			return errValueNeeded
		}
		allow := exists && cur.AllowAgents
		if in.AllowAgents != nil {
			allow = *in.AllowAgents
		}
		action := "person_secret.agents_update"
		var row dbgen.PersonSecret
		switch {
		case in.Value != nil && exists:
			ct, err := s.box.Seal([]byte(value), registry.PersonSecretAAD(cur.ID))
			if err != nil {
				return err
			}
			row, err = q.ReplacePersonSecret(ctx, dbgen.ReplacePersonSecretParams{ID: cur.ID, Origin: origin, SecretCipher: ct,
				Hint: hintOf(value), AllowAgents: allow})
			if err != nil {
				return err
			}
			action = "person_secret.rotate"
		case in.Value != nil:
			id := uuid.New()
			ct, err := s.box.Seal([]byte(value), registry.PersonSecretAAD(id))
			if err != nil {
				return err
			}
			row, err = q.InsertPersonSecret(ctx, dbgen.InsertPersonSecretParams{ID: id, UserID: u.ID, ServerID: serverID, Origin: origin,
				SecretCipher: ct, Hint: hintOf(value), AllowAgents: allow})
			if err != nil {
				return err
			}
			action = "person_secret.create"
		case allow != cur.AllowAgents:
			if row, err = q.SetPersonSecretAllowAgents(ctx, dbgen.SetPersonSecretAllowAgentsParams{ID: cur.ID, AllowAgents: allow}); err != nil {
				return err
			}
		default:
			row = cur
			action = ""
		}
		if in.Value != nil {
			// Its open links are done.
			if _, err := q.MarkSecretRequestsUsedFor(ctx, dbgen.MarkSecretRequestsUsedForParams{UserID: u.ID, ServerID: serverID}); err != nil {
				return err
			}
		}
		if action != "" {
			e := a.Audit(action, "person_secret", row.ID.String())
			e.TeamID = sv.TeamID
			e.Metadata = map[string]any{"name": displayName(u) + " · " + sv.Name, "userId": u.ID.String(), "serverId": sv.ID.String(),
				"server": sv.Name, "origin": origin, "allowAgents": row.AllowAgents}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		if in.UseForSetup && row.Status == StatusActive {
			if _, err := registry.SetSecretSetup(ctx, q, a, serverID, displayName(u)); err != nil {
				return err
			}
			setup = true
		}
		ref, err = s.serverRef(ctx, q, serverID)
		return err
	})
	if err != nil {
		return Mine{}, err
	}
	if setup && s.Registry != nil {
		// Best effort, like a server's first refresh: a failure is stored as
		// the server's refresh error and shown on its page.
		if err := s.Registry.RefreshAsSetup(ctx, a, serverID); err != nil {
			s.log.WarnContext(ctx, "reading a server with its setup person's key failed", "server", serverID, "err", err)
		}
	}
	sv, err := s.q.GetMCPServer(ctx, serverID)
	if err != nil {
		return Mine{}, err
	}
	return s.mine(ctx, u, sv, ref)
}

// hintOf is the last four characters of a secret (every secret here has at
// least eight).
func hintOf(v string) string {
	r := []rune(v)
	return string(r[len(r)-4:])
}

// Revoke deletes the caller's secret for a server (404 person_secret_not_found
// when there is none). Allowed whether or not they can still use the server.
// Audited as person_secret.revoke.
func (s *Service) Revoke(ctx context.Context, a authz.Actor, serverID uuid.UUID) error {
	return s.revoke(ctx, a, a.UserID, serverID, "self")
}

// AdminRevoke deletes a person's secret (platform admins; reason admin), for
// a leaver or a key that leaked.
func (s *Service) AdminRevoke(ctx context.Context, a authz.Actor, userID, serverID uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return s.revoke(ctx, a, userID, serverID, "admin")
}

func (s *Service) revoke(ctx context.Context, a authz.Actor, userID, serverID uuid.UUID, reason string) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if _, err := q.LockMCPServer(ctx, serverID); errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoSecret
		} else if err != nil {
			return err
		}
		u, err := q.GetUser(ctx, userID)
		if err != nil {
			return store.NotFound(err)
		}
		row, err := q.DeletePersonSecret(ctx, dbgen.DeletePersonSecretParams{UserID: userID, ServerID: serverID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoSecret
		} else if err != nil {
			return err
		}
		sv, err := q.GetMCPServer(ctx, serverID)
		if err != nil {
			return err
		}
		e := a.Audit("person_secret.revoke", "person_secret", row.ID.String())
		e.TeamID = sv.TeamID
		e.Metadata = map[string]any{"name": displayName(u) + " · " + sv.Name, "reason": reason, "userId": userID.String(),
			"serverId": serverID.String(), "server": sv.Name}
		return audit.Record(ctx, q, e)
	})
}

// --- The link ----------------------------------------------------------

// RequestView is a link as its person's page sees it.
type RequestView struct {
	ID     string
	Reason string
	Server ServerRef
	Config registry.PersonSecretInput
	// Origin is the server's origin now (the request's, checked).
	Origin string
	// Mine describes the secret the person has now, if any.
	Mine Mine
	// The gateway as it is now (or as it was, when deleted), and the
	// capability that asked.
	GatewayID                uuid.UUID
	GatewaySlug, GatewayName string
	GatewayExists            bool
	CapabilityKind           string
	ExposedName, Title       string
}

func (s *Service) loadRequest(ctx context.Context, userID uuid.UUID, id string) (dbgen.SecretRequest, error) {
	if !requestIDRE.MatchString(id) {
		return dbgen.SecretRequest{}, errNoRequest
	}
	r, err := s.q.GetSecretRequest(ctx, requestDigest(id))
	if errors.Is(store.NotFound(err), store.ErrNotFound) || (err == nil && r.UserID != userID) {
		return r, errNoRequest
	} else if err != nil {
		return r, err
	}
	if r.UsedAt != nil || !s.now().Before(r.ExpiresAt) {
		return r, errRequestExpired
	}
	return r, nil
}

// GetRequest returns a link for the person it was made for: 404 for an
// unknown or another person's, 410 once expired or used, or when its server
// moved to another origin (or left person_secret mode) since it was made.
func (s *Service) GetRequest(ctx context.Context, a authz.Actor, id string) (RequestView, error) {
	r, err := s.loadRequest(ctx, a.UserID, id)
	if err != nil {
		return RequestView{}, err
	}
	sv, err := s.q.GetMCPServer(ctx, r.ServerID)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, errRequestExpired
	} else if err != nil {
		return RequestView{}, err
	}
	cfg, ok := registry.PersonSecretConfig(sv)
	if !ok || registry.OriginOf(sv.URL) != r.ServerOrigin {
		return RequestView{}, errRequestExpired
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return RequestView{}, err
	}
	ref, err := s.serverRef(ctx, s.q, sv.ID)
	if err != nil {
		return RequestView{}, err
	}
	m, err := s.mine(ctx, u, sv, ref)
	if err != nil {
		return RequestView{}, err
	}
	v := RequestView{ID: id, Reason: r.Reason, Server: ref, Config: cfg, Origin: r.ServerOrigin, Mine: m, GatewayID: r.GatewayID, GatewaySlug: r.GatewaySlug,
		GatewayName: r.GatewayName, CapabilityKind: r.CapabilityKind, ExposedName: r.ExposedName, Title: r.CapabilityTitle}
	if g, err := s.q.GetGateway(ctx, r.GatewayID); err == nil {
		v.GatewaySlug, v.GatewayName, v.GatewayExists = g.Slug, g.Name, true
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return RequestView{}, err
	}
	return v, nil
}
