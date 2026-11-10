// Package automation manages automation tokens (docs/automation-tokens.md;
// decisions 55 and 58): bearer credentials for CI and scripts that call
// /v1, never /mcp.
//
// A token is "ompadm_" (platform-admin token) or "omppub_" (team publisher
// token) followed by 43 random URL-safe characters. Only its HMAC-SHA256
// digest under API_KEY_PEPPER is stored (pepper_id says which pepper made
// it; API_KEY_PEPPER_PREVIOUS is accepted and the digest redone on use), with
// its first 15 characters to recognise it. The secret is shown once, when
// the token is created, by a person in a browser session: a token can never
// create or revoke tokens. Tokens always expire (1-365 days, default 90),
// are limited to 20 active per team and 20 for the platform, and are
// revoked at once. A platform token is refused while its creator isn't an
// active platform admin; a team token outlives its creator.
//
// Which operations a token reaches is decided by api/openapi.yaml's
// x-omp-token-scopes (internal/httpapi); this package authenticates and
// manages tokens.
package automation

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/credentials"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
)

// Limits.
const (
	// MaxActive is how many active tokens a team may have, and the platform.
	MaxActive = 20
	// DefaultDays and MaxDays bound a token's lifetime.
	DefaultDays = 90
	MaxDays     = 365
)

// Statuses.
const (
	StatusActive  = "active"
	StatusExpired = "expired"
	StatusRevoked = "revoked"
)

// BlockedCreatorNotAdmin marks a platform token refused because its creator
// is not an active platform admin.
const BlockedCreatorNotAdmin = "creator_not_platform_admin"

var (
	errAdminOnly     = apperr.Forbidden("Only platform admins can manage platform tokens")
	errPlatformRead  = apperr.Forbidden("Only platform admins and auditors can see platform tokens")
	errTeamNotFound  = apperr.NotFound("team_not_found", "Team not found")
	errNotFound      = apperr.NotFound("token_not_found", "Token not found")
	errBadName       = apperr.Invalid("invalid_name", "Name must be 1-100 characters on one line")
	errBadExpiry     = apperr.Invalid("invalid_expiry", "expiresInDays must be between 1 and 365")
	errTooManyTeam   = apperr.Conflict("too_many_tokens", "This team has 20 active automation tokens. Revoke one you no longer use first.")
	errTooManyAdmin  = apperr.Conflict("too_many_tokens", "There are 20 active platform tokens. Revoke one you no longer use first.")
	errArchived      = apperr.Conflict("team_archived", "This team is archived and read-only")
	errSessionNeeded = apperr.New(http.StatusForbidden, "session_required", "Tokens are created and revoked in a browser session only")
	// ErrInvalid is any token that doesn't authenticate: unknown, expired,
	// revoked, its creator no longer a platform admin.
	ErrInvalid = errors.New("invalid automation token")
)

// Service manages tokens.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	pepper   []byte
	previous []byte
	// Observe counts an authentication outcome (ok, unknown, expired,
	// revoked, creator_not_admin); nil: not counted.
	Observe func(result string)
}

// New returns a Service; pepper is API_KEY_PEPPER (decoded).
func New(pool *pgxpool.Pool, pepper []byte) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q, pepper: pepper}
}

// SetPreviousPepper accepts tokens digested with API_KEY_PEPPER_PREVIOUS and
// re-digests them with the current pepper when used.
func (s *Service) SetPreviousPepper(p []byte) { s.previous = p }

// Digest is the stored form of a token: HMAC-SHA256 keyed with the pepper
// (the same as personal keys').
func Digest(pepper []byte, secret string) string { return apikeys.Digest(pepper, secret) }

// Token is a token as the API shows it.
type Token struct {
	Row        dbgen.AutomationToken
	TeamSlug   string
	TeamName   string
	TeamStatus string
	// CreatorIsAdmin: the creator is still an active platform admin (only
	// meaningful for platform tokens).
	CreatorIsAdmin bool
}

func view(t dbgen.AutomationToken, slug, name, status string, creatorAdmin bool) Token {
	return Token{Row: t, TeamSlug: slug, TeamName: name, TeamStatus: status, CreatorIsAdmin: creatorAdmin}
}

// Status says whether the token is active, expired or revoked at now.
func (t Token) Status(now time.Time) string {
	switch {
	case t.Row.RevokedAt != nil:
		return StatusRevoked
	case !t.Row.ExpiresAt.After(now):
		return StatusExpired
	}
	return StatusActive
}

// BlockedReason is why an otherwise active token is refused ("" when it
// isn't): a platform token whose creator is not an active platform admin.
func (t Token) BlockedReason(now time.Time) string {
	if t.Row.Kind == authz.TokenPlatformAdmin && t.Status(now) == StatusActive && !t.CreatorIsAdmin {
		return BlockedCreatorNotAdmin
	}
	return ""
}

// Created is a new token and its secret (shown once).
type Created struct {
	Token
	Secret string
}

// CreateInput is a new token.
type CreateInput struct {
	Name string
	// Scopes of the token's kind; a write scope includes its read scope.
	Scopes []string
	// Days is its lifetime (0: DefaultDays).
	Days int32
}

// Scopes of each kind, read before write.
var (
	platformScopes  = []string{authz.ScopePlatformRead, authz.ScopePlatformWrite}
	publisherScopes = []string{authz.ScopeServersRead, authz.ScopeServersWrite}
)

// ValidScope reports whether scope is one of the four scopes.
func ValidScope(scope string) bool {
	return slices.Contains(platformScopes, scope) || slices.Contains(publisherScopes, scope)
}

// NormalizeScopes checks scopes against a token kind's (400 invalid_scopes)
// and returns the stored list: sorted, deduplicated, with a write scope
// including its read scope.
func NormalizeScopes(kind string, scopes []string) ([]string, error) {
	allowed := platformScopes
	if kind == authz.TokenTeamPublisher {
		allowed = publisherScopes
	}
	if len(scopes) == 0 {
		return nil, apperr.Invalid("invalid_scopes", "Choose at least one scope")
	}
	held := map[string]bool{}
	for _, sc := range scopes {
		if !slices.Contains(allowed, sc) {
			e := apperr.Invalid("invalid_scopes", "Scopes of this token kind are "+strings.Join(allowed, " and "))
			e.Details = map[string]any{"scope": sc, "allowed": allowed}
			return nil, e
		}
		held[sc] = true
	}
	if held[allowed[1]] {
		held[allowed[0]] = true
	}
	out := make([]string, 0, 2)
	for _, sc := range allowed {
		if held[sc] {
			out = append(out, sc)
		}
	}
	return out, nil
}

func checkNameDays(name string, days int32) (string, int32, error) {
	name = strings.TrimSpace(name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.ContainsAny(name, "\r\n\x00") {
		return "", 0, errBadName
	}
	if days == 0 {
		days = DefaultDays
	}
	if days < 1 || days > MaxDays {
		return "", 0, errBadExpiry
	}
	return name, days, nil
}

// snapshot is a token's audited form: never the secret or its digest.
func snapshot(t dbgen.AutomationToken) map[string]any {
	return map[string]any{"name": t.Name, "kind": t.Kind, "prefix": t.Prefix, "scopes": t.Scopes, "expiresAt": t.ExpiresAt}
}

func displayName(u dbgen.User) string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Email
}

// CreatePlatform makes a platform-admin token (platform admins, in a
// browser session; at most MaxActive active ones). Audited as
// automation_token.create, without the secret.
func (s *Service) CreatePlatform(ctx context.Context, a authz.Actor, in CreateInput) (Created, error) {
	if a.IsToken() {
		return Created{}, errSessionNeeded
	}
	if !a.IsPlatformAdmin() {
		return Created{}, errAdminOnly
	}
	name, days, err := checkNameDays(in.Name, in.Days)
	if err != nil {
		return Created{}, err
	}
	scopes, err := NormalizeScopes(authz.TokenPlatformAdmin, in.Scopes)
	if err != nil {
		return Created{}, err
	}
	return s.create(ctx, a, authz.TokenPlatformAdmin, credentials.PlatformPrefix, nil, name, days, scopes)
}

// CreateTeam makes a team publisher token (the team's owners and admins, in
// a browser session; at most MaxActive active ones per team; 409
// team_archived). Platform roles don't create team tokens. Audited as
// automation_token.create.
func (s *Service) CreateTeam(ctx context.Context, a authz.Actor, ref string, in CreateInput) (Created, error) {
	if a.IsToken() {
		return Created{}, errSessionNeeded
	}
	name, days, err := checkNameDays(in.Name, in.Days)
	if err != nil {
		return Created{}, err
	}
	scopes, err := NormalizeScopes(authz.TokenTeamPublisher, in.Scopes)
	if err != nil {
		return Created{}, err
	}
	return s.create(ctx, a, authz.TokenTeamPublisher, credentials.PublisherPrefix, &ref, name, days, scopes)
}

func (s *Service) create(ctx context.Context, a authz.Actor, kind, prefix string, teamRef *string, name string, days int32, scopes []string) (Created, error) {
	secret := prefix + httpx.NewID(32) // 32 random bytes: 43 URL-safe characters
	var out Created
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		creator, err := q.GetUser(ctx, a.UserID)
		if err != nil {
			return err
		}
		var team dbgen.Team
		var teamID uuid.NullUUID
		if teamRef != nil {
			t, err := teams.Resolve(ctx, q, *teamRef)
			if err != nil {
				return err
			}
			// Locking the team serialises its creates, so the limit holds.
			if team, err = q.LockTeam(ctx, t.ID); err != nil {
				return err
			}
			role, err := teams.MemberRole(ctx, q, team.ID, a.UserID)
			if err != nil {
				return err
			}
			switch {
			case role == "" && !a.CanReadPlatform():
				return errTeamNotFound
			case !authz.RoleAtLeast(role, authz.RoleAdmin):
				return apperr.Forbidden("Only team owners and admins can create the team's automation tokens")
			case team.Status != teams.StatusActive:
				return errArchived
			}
			teamID = uuid.NullUUID{UUID: team.ID, Valid: true}
			n, err := q.CountActiveTeamAutomationTokens(ctx, teamID)
			if err != nil {
				return err
			}
			if n >= MaxActive {
				return errTooManyTeam
			}
		} else {
			if err := q.LockPlatformAutomationTokens(ctx); err != nil {
				return err
			}
			n, err := q.CountActivePlatformAutomationTokens(ctx)
			if err != nil {
				return err
			}
			if n >= MaxActive {
				return errTooManyAdmin
			}
		}
		by := displayName(creator)
		row, err := q.InsertAutomationToken(ctx, dbgen.InsertAutomationTokenParams{
			Kind: kind, TeamID: teamID, Name: name, Prefix: secret[:credentials.StoredPrefixLen], Digest: Digest(s.pepper, secret),
			PepperID: apikeys.PepperID(s.pepper), Scopes: scopes, CreatedBy: uuid.NullUUID{UUID: a.UserID, Valid: true},
			CreatedByName: &by, Days: days,
		})
		if err != nil {
			return err
		}
		out = Created{Token: view(row, team.Slug, team.Name, team.Status, true), Secret: secret}
		e := a.Audit("automation_token.create", "automation_token", row.ID.String())
		e.TeamID = team.ID
		e.After = snapshot(row)
		e.Metadata = map[string]any{"name": row.Name, "kind": row.Kind, "scopes": row.Scopes, "expiresAt": row.ExpiresAt}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// ListPlatform lists the platform's tokens, newest first (platform admins
// and auditors).
func (s *Service) ListPlatform(ctx context.Context, a authz.Actor) ([]Token, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	return s.list(ctx, uuid.NullUUID{})
}

// ListTeam lists a team's tokens, newest first (the team's owners and
// admins; platform admins and auditors). Members and editors get 403.
func (s *Service) ListTeam(ctx context.Context, a authz.Actor, ref string) ([]Token, error) {
	t, err := teams.Resolve(ctx, s.q, ref)
	if err != nil {
		return nil, err
	}
	role, err := teams.MemberRole(ctx, s.q, t.ID, a.UserID)
	if err != nil {
		return nil, err
	}
	switch {
	case role == "" && !a.CanReadPlatform():
		return nil, errTeamNotFound
	case !authz.RoleAtLeast(role, authz.RoleAdmin) && !a.CanReadPlatform():
		return nil, apperr.Forbidden("Only team owners and admins can see the team's automation tokens")
	}
	return s.list(ctx, uuid.NullUUID{UUID: t.ID, Valid: true})
}

func (s *Service) list(ctx context.Context, team uuid.NullUUID) ([]Token, error) {
	rows, err := s.q.ListAutomationTokens(ctx, team)
	if err != nil {
		return nil, err
	}
	out := make([]Token, len(rows))
	for i, r := range rows {
		out[i] = view(r.AutomationToken, r.TeamSlug, r.TeamName, r.TeamStatus, r.CreatorIsAdmin)
	}
	return out, nil
}

// RevokePlatform revokes a platform token (platform admins, in a browser
// session). Revoking a revoked or expired token changes nothing; 404
// token_not_found for a team token. Audited as automation_token.revoke.
func (s *Service) RevokePlatform(ctx context.Context, a authz.Actor, id uuid.UUID) error {
	if a.IsToken() {
		return errSessionNeeded
	}
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return s.revoke(ctx, a, nil, id)
}

// RevokeTeam revokes one of a team's tokens (the team's owners and admins,
// in a browser session; also while the team is archived). 404
// token_not_found for another team's token.
func (s *Service) RevokeTeam(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) error {
	if a.IsToken() {
		return errSessionNeeded
	}
	return s.revoke(ctx, a, &ref, id)
}

func (s *Service) revoke(ctx context.Context, a authz.Actor, teamRef *string, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		var team dbgen.Team
		if teamRef != nil {
			t, err := teams.Resolve(ctx, q, *teamRef)
			if err != nil {
				return err
			}
			team = t
			role, err := teams.MemberRole(ctx, q, t.ID, a.UserID)
			if err != nil {
				return err
			}
			switch {
			case role == "" && !a.CanReadPlatform():
				return errTeamNotFound
			case !authz.RoleAtLeast(role, authz.RoleAdmin):
				return apperr.Forbidden("Only team owners and admins can revoke the team's automation tokens")
			}
		}
		cur, err := q.GetAutomationToken(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		t := cur.AutomationToken
		if (teamRef == nil && t.Kind != authz.TokenPlatformAdmin) || (teamRef != nil && (!t.TeamID.Valid || t.TeamID.UUID != team.ID)) {
			return errNotFound
		}
		if t.RevokedAt != nil || !t.ExpiresAt.After(time.Now()) {
			return nil
		}
		row, err := q.RevokeAutomationToken(ctx, dbgen.RevokeAutomationTokenParams{ID: id, RevokedBy: uuid.NullUUID{UUID: a.UserID, Valid: true}})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil // revoked concurrently
		} else if err != nil {
			return err
		}
		e := a.Audit("automation_token.revoke", "automation_token", row.ID.String())
		e.TeamID = team.ID
		e.Before = snapshot(t)
		e.Metadata = map[string]any{"name": row.Name, "kind": row.Kind}
		return audit.Record(ctx, q, e)
	})
}

// Principal is who a token authenticates.
type Principal struct {
	Token
}

// Actor is the principal as the authorization rules see it: a platform
// token with platform:write acts as a platform admin and one with only
// platform:read as an auditor; a publisher token acts in its own team
// (authz.Actor.TeamRole). No user ID.
func (p Principal) Actor(requestID, clientIP string) authz.Actor {
	t := p.Row
	a := authz.Actor{Kind: authz.KindAutomationToken, PlatformRole: authz.PlatformNone, RequestID: requestID, ClientIP: clientIP,
		TokenID: t.ID, TokenName: t.Name, TokenKind: t.Kind, TokenScopes: slices.Clone(t.Scopes)}
	switch t.Kind {
	case authz.TokenPlatformAdmin:
		if slices.Contains(t.Scopes, authz.ScopePlatformWrite) {
			a.PlatformRole = authz.PlatformAdmin
		} else if slices.Contains(t.Scopes, authz.ScopePlatformRead) {
			a.PlatformRole = authz.PlatformAuditor
		}
	case authz.TokenTeamPublisher:
		a.TokenTeamID = t.TeamID.UUID
	}
	return a
}

// Authentication results (the omp_automation_token_auth_total label).
const (
	ResultOK           = "ok"
	ResultUnknown      = "unknown"
	ResultExpired      = "expired"
	ResultRevoked      = "revoked"
	ResultCreatorGone  = "creator_not_admin"
	ResultWrongShape   = "bad_shape"
	ResultMCPKey       = "mcp_credential"
	ResultRateLimited  = "rate_limited"
	ResultAmbiguous    = "ambiguous"
	ResultNotAllowed   = "not_allowed"
	ResultSessionOnly  = "session_required"
	ResultTeamMismatch = "other_team"
)

func (s *Service) observe(result string) { s.Count(result) }

// Count records an authentication outcome (the middleware's refusals too).
func (s *Service) Count(result string) {
	if s.Observe != nil {
		s.Observe(result)
	}
}

// Authenticate checks a token: its shape, then the lookup by digest (the
// current pepper, then the previous one, re-digesting on use); it must be
// unrevoked and unexpired and, for a platform token, its creator an active
// platform admin. Every failure is ErrInvalid.
func (s *Service) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if !credentials.Classify(secret).IsAutomationToken() {
		s.observe(ResultWrongShape)
		return Principal{}, ErrInvalid
	}
	digest := Digest(s.pepper, secret)
	row, err := s.q.GetAutomationTokenByDigest(ctx, digest)
	previous := false
	if errors.Is(store.NotFound(err), store.ErrNotFound) && s.previous != nil {
		// Made before the pepper rotation: re-digested below.
		digest, previous = Digest(s.previous, secret), true
		row, err = s.q.GetAutomationTokenByDigest(ctx, digest)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		s.observe(ResultUnknown)
		return Principal{}, ErrInvalid
	} else if err != nil {
		return Principal{}, err
	}
	t := view(row.AutomationToken, row.TeamSlug, row.TeamName, row.TeamStatus, row.CreatorIsAdmin)
	// The digest lookup is exact; compare again in constant time anyway.
	if !hmac.Equal([]byte(t.Row.Digest), []byte(digest)) {
		s.observe(ResultUnknown)
		return Principal{}, ErrInvalid
	}
	now := time.Now()
	switch t.Status(now) {
	case StatusRevoked:
		s.observe(ResultRevoked)
		return Principal{}, ErrInvalid
	case StatusExpired:
		s.observe(ResultExpired)
		return Principal{}, ErrInvalid
	}
	if t.BlockedReason(now) != "" {
		s.observe(ResultCreatorGone)
		return Principal{}, ErrInvalid
	}
	if previous {
		if err := s.rehash(ctx, t, digest, Digest(s.pepper, secret)); err != nil {
			return Principal{}, err
		}
	}
	s.observe(ResultOK)
	return Principal{Token: t}, nil
}

// rehash moves a token found with the previous pepper to the current one.
// Audited as automation_token.pepper_rehash by the system.
func (s *Service) rehash(ctx context.Context, t Token, old, digest string) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		n, err := q.RehashAutomationToken(ctx, dbgen.RehashAutomationTokenParams{ID: t.Row.ID, OldDigest: old, Digest: digest, PepperID: apikeys.PepperID(s.pepper)})
		if err != nil || n == 0 {
			return err // n == 0: another request did it
		}
		return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "automation_token.pepper_rehash",
			TargetType: "automation_token", TargetID: t.Row.ID.String(), TeamID: t.Row.TeamID.UUID,
			Metadata: map[string]any{"name": t.Row.Name, "kind": t.Row.Kind, "prefix": t.Row.Prefix}})
	})
}

// Touch records that a token was used (at most once a minute).
func (s *Service) Touch(ctx context.Context, t dbgen.AutomationToken) error {
	if !store.TouchDue(t.LastUsedAt) {
		return nil
	}
	return s.q.TouchAutomationToken(ctx, t.ID)
}

// Get returns one token by ID (for introspection of the acting token).
func (s *Service) Get(ctx context.Context, id uuid.UUID) (Token, error) {
	r, err := s.q.GetAutomationToken(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Token{}, errNotFound
	} else if err != nil {
		return Token{}, err
	}
	return view(r.AutomationToken, r.TeamSlug, r.TeamName, r.TeamStatus, r.CreatorIsAdmin), nil
}

// Cleanup deletes tokens that expired or were revoked more than 30 days
// ago. Safe to run on several replicas at once.
func (s *Service) Cleanup(ctx context.Context) (int64, error) {
	return s.q.DeleteOldAutomationTokens(ctx)
}
