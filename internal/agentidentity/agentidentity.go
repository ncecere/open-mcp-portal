// Package agentidentity lets the portal trust an external agent platform
// (Pi Durable Platform) that relays its agents' calls through a team service
// account and names the person each agent acts for (roadmap #55 to #58,
// decisions 65 and 66; docs/agent-platforms.md, docs/threat-model.md "The
// agent platform relay").
//
// Platform admins add trusted platforms (name, issuer, JWKS URL, audience,
// enabled) and mark team service accounts as relays for one of them. A call
// on /mcp/{gateway} authenticated with a relay account's key may carry the
// platform's signed identity token in MCP-Gateway-Identity. Verify (verify.go)
// checks the token; internal/mcpgw then authorises the call as the named
// person, limited to what the relay account could reach itself.
//
// Everything here fails closed: a token that fails any check is a *Rejection
// and never changes who the caller is.
package agentidentity

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"crypto/tls"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/upstream"
)

// MaxPlatforms is how many trusted platforms the portal keeps.
const MaxPlatforms = 20

// WellKnownJWKS is where a platform publishes its keys, under its issuer.
const WellKnownJWKS = "/.well-known/mcp-identity-jwks.json"

var (
	errAdminOnly    = apperr.Forbidden("Only platform admins can manage trusted agent platforms and relay accounts")
	errSessionOnly  = apperr.New(403, "session_required", "Trusted agent platforms and relay accounts can only be changed in a browser session")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errNotFound     = apperr.NotFound("agent_platform_not_found", "Trusted agent platform not found")
	errAccountGone  = apperr.NotFound("service_account_not_found", "Service account not found")
	errNameTaken    = apperr.Conflict("name_taken", "Another trusted agent platform has that name")
	errIssuerTaken  = apperr.Conflict("issuer_taken", "That issuer is already trusted")
	errTooMany      = apperr.Conflict("too_many_agent_platforms", "At most 20 agent platforms can be trusted")
	errBadName      = apperr.Invalid("invalid_name", "Name must be 1-100 characters on one line")
	errBadIssuer    = apperr.New(422, "invalid_issuer", "The issuer must be an absolute https URL without a query or fragment, exactly as the platform puts it in iss (an http URL only for a loopback host in development)")
	errBadAudience  = apperr.Invalid("invalid_audience", "The audience must be 1-500 characters without spaces, such as this portal's URL")
	errTeamArchived = apperr.Conflict("team_archived", "This team is archived and read-only")
	errPlatformOff  = apperr.Conflict("platform_disabled", "Turn the platform on before marking relay accounts for it")
	errNotRelay     = apperr.NotFound("relay_not_found", "That service account is not a relay for this platform")
)

// Service manages trusted platforms and relay marks and verifies their tokens.
type Service struct {
	// Client applies the outbound address guard to JWKS fetches (the same
	// allowlist as MCP servers; required).
	Client *upstream.Client
	// TLS configures JWKS requests (tests: to trust a test server).
	TLS *tls.Config
	// PersonIssuer is the issuer people sign in with at this portal
	// (OIDC_ISSUER; the development issuer with DEV_AUTH alone). A token's
	// person.iss must equal it (decision 65); empty accepts no person.
	PersonIssuer string
	// AppURL is the default audience.
	AppURL string
	Log    *slog.Logger

	pool *pgxpool.Pool
	q    *dbgen.Queries
	now  func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]*platformKeys
}

// New returns a Service. client is the upstream client of MCP servers.
func New(pool *pgxpool.Pool, client *upstream.Client, appURL, personIssuer string, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{Client: client, AppURL: appURL, PersonIssuer: personIssuer, Log: log, pool: pool, q: q, now: time.Now,
		cache: map[uuid.UUID]*platformKeys{}}
}

// SetClock sets the clock of the time checks and caches (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// canWrite: platform admins in a browser session. Automation tokens never
// change trust settings (decision 58), whatever their scopes.
func canWrite(a authz.Actor) error {
	switch {
	case a.IsToken():
		return errSessionOnly
	case !a.IsPlatformAdmin():
		return errAdminOnly
	}
	return nil
}

// View is a platform with how many accounts relay for it.
type View struct {
	Platform   dbgen.AgentPlatform
	RelayCount int64
}

// List lists the trusted platforms by name (platform admins and auditors).
func (s *Service) List(ctx context.Context, a authz.Actor) ([]View, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	rows, err := s.q.ListAgentPlatforms(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]View, len(rows))
	for i, r := range rows {
		out[i] = View{Platform: r.AgentPlatform, RelayCount: r.RelayCount}
	}
	return out, nil
}

func (s *Service) view(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (View, error) {
	p, err := q.GetAgentPlatform(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return View{}, errNotFound
	} else if err != nil {
		return View{}, err
	}
	relays, err := q.ListRelayServiceAccounts(ctx, uuid.NullUUID{UUID: id, Valid: true})
	if err != nil {
		return View{}, err
	}
	return View{Platform: p, RelayCount: int64(len(relays))}, nil
}

// Get returns one platform (platform admins and auditors).
func (s *Service) Get(ctx context.Context, a authz.Actor, id uuid.UUID) (View, error) {
	if !a.CanReadPlatform() {
		return View{}, errPlatformRead
	}
	return s.view(ctx, s.q, id)
}

// Relay is a service account that relays for a platform.
type Relay struct {
	Account  dbgen.ServiceAccount
	TeamSlug string
	TeamName string
}

// Relays lists the accounts that relay for a platform (platform admins and
// auditors).
func (s *Service) Relays(ctx context.Context, a authz.Actor, id uuid.UUID) ([]Relay, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := s.view(ctx, s.q, id); err != nil {
		return nil, err
	}
	rows, err := s.q.ListRelayServiceAccounts(ctx, uuid.NullUUID{UUID: id, Valid: true})
	if err != nil {
		return nil, err
	}
	out := make([]Relay, len(rows))
	for i, r := range rows {
		out[i] = Relay{Account: r.ServiceAccount, TeamSlug: r.TeamSlug, TeamName: r.TeamName}
	}
	return out, nil
}

func oneLine(s string, max int) bool {
	n := utf8.RuneCountInString(s)
	return n >= 1 && n <= max && utf8.ValidString(s) && !strings.ContainsFunc(s, unicode.IsControl)
}

// issuerOK checks an issuer's shape: an absolute https URL (http for a
// loopback host when the development allowance is on) without user info,
// query or fragment. It is compared as written, never normalised.
func (s *Service) issuerOK(raw string) bool {
	if !oneLine(raw, 500) || raw != strings.TrimSpace(raw) || strings.ContainsAny(raw, " #?") {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		return s.Client != nil && s.Client.AllowPrivate && (strings.EqualFold(u.Hostname(), "localhost") || strings.HasPrefix(u.Hostname(), "127.") || u.Hostname() == "::1")
	}
	return false
}

// Input is a platform to add or edit; nil fields keep their value when
// editing and default when adding.
type Input struct {
	Name, Issuer, JWKSURL, Audience *string
	Enabled                         *bool
}

func snapshot(p dbgen.AgentPlatform) map[string]any {
	return map[string]any{"name": p.Name, "issuer": p.Issuer, "jwksUrl": p.JwksUrl, "audience": p.Audience, "enabled": p.Enabled}
}

// resolve fills defaults and validates the fields of a platform.
func (s *Service) resolve(ctx context.Context, cur *dbgen.AgentPlatform, in Input) (dbgen.AgentPlatform, error) {
	var p dbgen.AgentPlatform
	if cur != nil {
		p = *cur
	} else {
		p.Enabled = true
	}
	if in.Name != nil {
		p.Name = strings.TrimSpace(*in.Name)
	}
	if in.Issuer != nil {
		p.Issuer = *in.Issuer
	}
	if in.Enabled != nil {
		p.Enabled = *in.Enabled
	}
	if !oneLine(p.Name, 100) {
		return p, errBadName
	}
	if !s.issuerOK(p.Issuer) {
		return p, errBadIssuer
	}
	switch {
	case in.JWKSURL != nil && strings.TrimSpace(*in.JWKSURL) != "":
		p.JwksUrl = strings.TrimSpace(*in.JWKSURL)
	case in.JWKSURL != nil || cur == nil || (in.Issuer != nil && *in.Issuer != cur.Issuer && p.JwksUrl == defaultJWKS(cur.Issuer)):
		// Adding without a URL, clearing it, or a new issuer while the URL
		// was the default for the old one: the default for the issuer.
		p.JwksUrl = defaultJWKS(p.Issuer)
	}
	switch {
	case in.Audience != nil && strings.TrimSpace(*in.Audience) != "":
		p.Audience = strings.TrimSpace(*in.Audience)
	case in.Audience != nil || cur == nil:
		p.Audience = s.AppURL
	}
	if !oneLine(p.Audience, 500) || strings.ContainsAny(p.Audience, " \t") {
		return p, errBadAudience
	}
	// The JWKS URL follows the address rule of MCP servers (private
	// addresses only for hosts a platform admin allowed) and is https
	// always: 422 url_not_allowed.
	norm, err := s.checkJWKSURL(ctx, p.JwksUrl)
	if err != nil {
		return p, err
	}
	p.JwksUrl = norm
	return p, nil
}

func defaultJWKS(issuer string) string { return strings.TrimRight(issuer, "/") + WellKnownJWKS }

// errJWKSNotHTTPS: the keys decide who the portal believes a person is, so
// they are never fetched in clear (L-1 of the security review). An internal
// address may be allowed for the host, but not plain http.
var errJWKSNotHTTPS = func() error {
	e := apperr.New(422, "url_not_allowed", "The keys address must use https, even for an internal address a platform admin allowed: the keys decide who the portal believes a person is.")
	e.Details = map[string]any{"reason": upstream.ReasonScheme}
	return e
}()

// checkJWKSURL applies the rule of MCP server URLs (address allowlist, no
// userinfo, query or fragment) and, on top of it, https without exception.
// It is used when a platform is saved and again before every fetch.
func (s *Service) checkJWKSURL(ctx context.Context, raw string) (string, error) {
	if u, err := url.Parse(strings.TrimSpace(raw)); err == nil && u.Scheme != "https" {
		return "", errJWKSNotHTTPS
	}
	return s.Client.NormalizeURL(ctx, raw)
}

func uniqueErr(err error) error {
	switch {
	case apperr.IsUniqueViolation(err, "agent_platforms_name_key"):
		return errNameTaken
	case apperr.IsUniqueViolation(err, "agent_platforms_issuer_key"):
		return errIssuerTaken
	}
	return err
}

// Create trusts a platform (platform admins, browser session). Audited as
// agent_platform.create.
func (s *Service) Create(ctx context.Context, a authz.Actor, in Input) (View, error) {
	if err := canWrite(a); err != nil {
		return View{}, err
	}
	p, err := s.resolve(ctx, nil, in)
	if err != nil {
		return View{}, err
	}
	var out View
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		n, err := q.CountAgentPlatforms(ctx)
		if err != nil {
			return err
		}
		if n >= MaxPlatforms {
			return errTooMany
		}
		row, err := q.InsertAgentPlatform(ctx, dbgen.InsertAgentPlatformParams{Name: p.Name, Issuer: p.Issuer, JwksUrl: p.JwksUrl,
			Audience: p.Audience, Enabled: p.Enabled, CreatedBy: by(a)})
		if err != nil {
			return uniqueErr(err)
		}
		e := a.Audit("agent_platform.create", "agent_platform", row.ID.String())
		e.After = snapshot(row)
		e.Metadata = map[string]any{"name": row.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.view(ctx, q, row.ID)
		return err
	})
	return out, err
}

// Update changes a platform (platform admins, browser session), If-Match on
// its revision. Turning it off refuses its tokens at the next request.
// Audited as agent_platform.update.
func (s *Service) Update(ctx context.Context, a authz.Actor, id uuid.UUID, in Input, expectedRevision int64) (View, error) {
	if err := canWrite(a); err != nil {
		return View{}, err
	}
	var out View
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockAgentPlatform(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		p, err := s.resolve(ctx, &cur, in)
		if err != nil {
			return err
		}
		row, err := q.UpdateAgentPlatform(ctx, dbgen.UpdateAgentPlatformParams{ID: id, Name: p.Name, Issuer: p.Issuer, JwksUrl: p.JwksUrl,
			Audience: p.Audience, Enabled: p.Enabled, UpdatedBy: by(a)})
		if err != nil {
			return uniqueErr(err)
		}
		e := a.Audit("agent_platform.update", "agent_platform", id.String())
		e.Before, e.After = snapshot(cur), snapshot(row)
		e.Metadata = map[string]any{"name": row.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.view(ctx, q, id)
		return err
	})
	if err == nil {
		s.forget(id)
	}
	return out, err
}

// Delete stops trusting a platform (platform admins, browser session): its
// tokens are refused and its relay accounts are ordinary service accounts
// again. Audited as agent_platform.delete with how many relays it had.
func (s *Service) Delete(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if err := canWrite(a); err != nil {
		return err
	}
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockAgentPlatform(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		relays, err := q.ListRelayServiceAccounts(ctx, uuid.NullUUID{UUID: id, Valid: true})
		if err != nil {
			return err
		}
		if err := q.DeleteAgentPlatform(ctx, id); err != nil {
			return err
		}
		e := a.Audit("agent_platform.delete", "agent_platform", id.String())
		e.Before = snapshot(cur)
		e.Metadata = map[string]any{"name": cur.Name, "relaysCleared": len(relays)}
		return audit.Record(ctx, q, e)
	})
	if err == nil {
		s.forget(id)
	}
	return err
}

// forget drops this replica's cached keys of a platform (a changed or
// deleted platform; other replicas follow within the cache lifetime, and
// the issuer, enabled flag and audience are read from the database at every
// verification anyway).
func (s *Service) forget(id uuid.UUID) {
	s.mu.Lock()
	delete(s.cache, id)
	s.mu.Unlock()
}

// TestResult is the outcome of fetching a platform's JWKS.
type TestResult struct {
	OK        bool
	Error     string // a Fetch* code
	HTTPCode  int
	KeyIDs    []string
	CheckedAt time.Time
	Latency   time.Duration
	// CacheFor is how long a replica would cache the answer.
	CacheFor time.Duration
}

// Test fetches the platform's JWKS now, through the same guarded path as a
// verification, and stores the result as its last fetch (platform admins,
// browser session; auditors read the stored result). A successful test also
// refreshes this replica's cache.
func (s *Service) Test(ctx context.Context, a authz.Actor, id uuid.UUID) (TestResult, error) {
	if err := canWrite(a); err != nil {
		return TestResult{}, err
	}
	p, err := s.q.GetAgentPlatform(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return TestResult{}, errNotFound
	} else if err != nil {
		return TestResult{}, err
	}
	start := s.now()
	pk := s.keysOf(id)
	pk.fetchMu.Lock()
	set, ferr := s.fetchJWKS(ctx, p)
	if ferr == nil {
		pk.mu.Lock()
		pk.set, pk.lastFailure = set, time.Time{}
		pk.mu.Unlock()
	}
	pk.fetchMu.Unlock()
	s.recordFetch(ctx, p, set, ferr)
	res := TestResult{CheckedAt: s.now(), Latency: s.now().Sub(start), KeyIDs: []string{}}
	if ferr != nil {
		res.Error, res.HTTPCode = ferr.Code, ferr.HTTPStatus
		return res, nil
	}
	res.OK, res.KeyIDs, res.CacheFor = true, set.kids, set.expiresAt.Sub(set.fetchedAt)
	return res, nil
}

// SetRelay marks a service account as a relay for a platform (platform
// admins, browser session; the team's owners and admins can't), moving it
// from another platform when it had one. Audited as
// service_account.relay_set on the account's team.
func (s *Service) SetRelay(ctx context.Context, a authz.Actor, platformID, accountID uuid.UUID) (Relay, error) {
	if err := canWrite(a); err != nil {
		return Relay{}, err
	}
	var out Relay
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockServiceAccountByID(ctx, accountID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errAccountGone
		} else if err != nil {
			return err
		}
		team, err := q.GetTeamByID(ctx, cur.TeamID)
		if err != nil {
			return err
		}
		plat, err := q.LockAgentPlatform(ctx, platformID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		switch {
		case team.Status != teams.StatusActive:
			return errTeamArchived
		case !plat.Enabled:
			return errPlatformOff
		}
		var before any
		if cur.RelayPlatformID.Valid {
			before = map[string]any{"platformId": cur.RelayPlatformID.UUID.String()}
		}
		row, err := q.SetServiceAccountRelay(ctx, dbgen.SetServiceAccountRelayParams{ID: accountID,
			PlatformID: uuid.NullUUID{UUID: plat.ID, Valid: true}, MarkedBy: by(a)})
		if err != nil {
			return err
		}
		e := a.Audit("service_account.relay_set", "service_account", accountID.String())
		e.TeamID, e.Before = team.ID, before
		e.After = map[string]any{"platformId": plat.ID.String(), "platform": plat.Name}
		e.Metadata = map[string]any{"name": row.Name, "team": team.Slug, "platform": plat.Name}
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out = Relay{Account: row, TeamSlug: team.Slug, TeamName: team.Name}
		return nil
	})
	return out, err
}

// ClearRelay clears a service account's relay mark for a platform (platform
// admins, browser session): 404 unless it relays for that platform now. Its
// tokens are ignored from the next request. Audited as
// service_account.relay_clear.
func (s *Service) ClearRelay(ctx context.Context, a authz.Actor, platformID, accountID uuid.UUID) error {
	if err := canWrite(a); err != nil {
		return err
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		cur, err := q.LockServiceAccountByID(ctx, accountID)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errAccountGone
		} else if err != nil {
			return err
		}
		if !cur.RelayPlatformID.Valid || cur.RelayPlatformID.UUID != platformID {
			return errNotRelay
		}
		team, err := q.GetTeamByID(ctx, cur.TeamID)
		if err != nil {
			return err
		}
		plat, err := q.GetAgentPlatform(ctx, platformID)
		if err != nil {
			return err
		}
		row, err := q.SetServiceAccountRelay(ctx, dbgen.SetServiceAccountRelayParams{ID: accountID})
		if err != nil {
			return err
		}
		e := a.Audit("service_account.relay_clear", "service_account", accountID.String())
		e.TeamID = team.ID
		e.Before = map[string]any{"platformId": platformID.String(), "platform": plat.Name}
		e.Metadata = map[string]any{"name": row.Name, "team": team.Slug, "platform": plat.Name}
		return audit.Record(ctx, q, e)
	})
}

// Platform returns a platform by ID (the relay mark of an authenticated
// service account).
func (s *Service) Platform(ctx context.Context, id uuid.UUID) (dbgen.AgentPlatform, error) {
	return s.q.GetAgentPlatform(ctx, id)
}

// Cleanup deletes the jtis of tokens that can no longer be valid (a
// retention hook; any replica may run it).
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	return s.q.DeleteExpiredAgentTokenJTIs(ctx)
}
