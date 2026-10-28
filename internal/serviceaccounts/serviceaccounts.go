// Package serviceaccounts manages team service accounts (docs/phase4-
// client-auth.md; decisions 12, 22 and 23): team-owned identities for
// headless agents, CI and scripts, whose keys don't depend on a person
// staying on the team.
//
// A service account belongs to a team, has a name unique in the team, a team
// role of member or editor (used for capabilities' minimum roles) and can be
// turned off. The team's owners and admins manage it; its members see it.
// It may use the team's own gateways and platform gateways granted to its
// team.
//
// Keys are "omp_sa_" and 43 random URL-safe characters (32 bytes), stored
// only as HMAC-SHA256 digests keyed with API_KEY_PEPPER (like personal
// keys, internal/apikeys), shown once. They always expire (at most 365
// days); an account has at most MaxActiveKeys active keys so a key can be
// rotated without downtime. A key may be limited to gateways the account
// can use when it is created. A turned-off or deleted account, an archived
// team, or a revoked or expired key is refused at the next request.
package serviceaccounts

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"regexp"
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
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// KeyPrefix starts every service account key.
const KeyPrefix = "omp_sa_"

// Limits.
const (
	// MaxPerTeam is how many service accounts a team may have.
	MaxPerTeam = 100
	// MaxActiveKeys is how many active keys an account may have (two, to
	// rotate without downtime).
	MaxActiveKeys = 2
	// prefixLen is how much of a key is stored in the clear: "omp_sa_" and 8.
	prefixLen = len(KeyPrefix) + 8
	// secretLen is the length of a key: "omp_sa_" and 43 characters.
	secretLen = len(KeyPrefix) + 43
)

var (
	errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")
	errPlatformRead = apperr.Forbidden("Only platform admins and auditors can see this")
	errNotFound     = apperr.NotFound("service_account_not_found", "Service account not found")
	errKeyNotFound  = apperr.NotFound("key_not_found", "Key not found")
	errTeamArchived = apperr.Conflict("team_archived", "This team is archived and read-only")
	errNameTaken    = apperr.Conflict("name_taken", "The team already has a service account with that name")
	errTooMany      = apperr.Conflict("too_many_service_accounts", "A team can have at most 100 service accounts")
	errTooManyKeys  = apperr.Conflict("too_many_keys", "This service account has 2 active keys. Revoke one first.")
	errRetired      = apperr.Conflict("service_account_retired", "This legacy relay account is permanently retired. Create a new ordinary service account and key.")
	errDisabled     = apperr.Conflict("disabled", "This service account is turned off. Turn it on first.")
	errBadName      = apperr.Invalid("invalid_name", "Name must be 1-64 lower-case letters, digits or dashes, not starting or ending with a dash")
	errBadDesc      = apperr.Invalid("invalid_description", "Description must be at most 2000 characters")
	errBadRole      = apperr.Invalid("invalid_role", "A service account's role is member or editor")
	errBadKeyName   = apperr.Invalid("invalid_name", "Name must be 1-100 characters on one line")
	errBadExpiry    = apperr.Invalid("invalid_expiry", "expiresInDays must be between 1 and 365")
	errTooManyGw    = apperr.Invalid("too_many_gateways", "A key can be limited to at most 50 gateways")
	// ErrInvalid is any key that doesn't authenticate: unknown, revoked,
	// expired, its account turned off, or its team archived.
	ErrInvalid = errors.New("invalid service account key")
	nameRE     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$`)
)

// Gateways says which gateways a service account may use now
// (internal/gateways).
type Gateways interface {
	UsableByServiceAccount(ctx context.Context, teamID uuid.UUID, role string, ids []uuid.UUID) ([]dbgen.Gateway, []uuid.UUID, error)
	ListForServiceAccount(ctx context.Context, teamID uuid.UUID, role string, accountID uuid.UUID, scope []byte) ([]gateways.Mine, error)
}

// Service manages service accounts.
type Service struct {
	pool     *pgxpool.Pool
	q        *dbgen.Queries
	pepper   []byte
	previous []byte
	gateways Gateways
}

// SetPreviousPepper accepts keys digested with API_KEY_PEPPER_PREVIOUS
// (decoded) and re-digests them with the current pepper when used.
func (s *Service) SetPreviousPepper(p []byte) { s.previous = p }

// New returns a Service; pepper is API_KEY_PEPPER (decoded).
func New(pool *pgxpool.Pool, pepper []byte, gateways Gateways) *Service {
	var q *dbgen.Queries
	if pool != nil {
		q = dbgen.New(pool)
	}
	return &Service{pool: pool, q: q, pepper: pepper, gateways: gateways}
}

// LooksLikeKey reports whether s has the shape of a service account key.
func LooksLikeKey(s string) bool {
	if len(s) != secretLen || !strings.HasPrefix(s, KeyPrefix) {
		return false
	}
	for _, r := range s[len(KeyPrefix):] {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// View is an account with its team, active keys and creator.
type View struct {
	Account       dbgen.ServiceAccount
	TeamSlug      string
	ActiveKeys    int64
	CreatedByName *string
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
	if role == "" && !a.CanReadPlatform() {
		return teamAccess{}, errTeamNotFound
	}
	return teamAccess{team: t, role: role}, nil
}

// readKeys: the team's owners and admins, and platform staff.
func (ta teamAccess) readKeys(a authz.Actor) error {
	if a.CanReadPlatform() {
		return nil
	}
	return authz.CheckServiceAccountEdit(ta.role)
}

// writable: owners and admins of an active team.
func (ta teamAccess) writable() error {
	if err := authz.CheckServiceAccountEdit(ta.role); err != nil {
		return err
	}
	if ta.team.Status != teams.StatusActive {
		return errTeamArchived
	}
	return nil
}

func by(a authz.Actor) uuid.NullUUID {
	return uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}
}

// snapshot is an account's audited configuration.
func snapshot(sa dbgen.ServiceAccount) map[string]any {
	return map[string]any{"name": sa.Name, "description": sa.Description, "role": sa.Role, "enabled": sa.Enabled, "toolScope": toolscope.Stored(sa.ToolScope)}
}

func (s *Service) view(ctx context.Context, q *dbgen.Queries, t dbgen.Team, id uuid.UUID) (View, error) {
	row, err := q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: id, TeamID: t.ID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return View{}, errNotFound
	} else if err != nil {
		return View{}, err
	}
	return View{Account: row.ServiceAccount, TeamSlug: t.Slug, ActiveKeys: row.ActiveKeys, CreatedByName: row.CreatedByName}, nil
}

// List lists the team's service accounts by name (members; platform admins
// and auditors).
func (s *Service) List(ctx context.Context, a authz.Actor, ref string) ([]View, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	rows, err := s.q.ListServiceAccounts(ctx, ta.team.ID)
	if err != nil {
		return nil, err
	}
	out := make([]View, len(rows))
	for i, r := range rows {
		out[i] = View{Account: r.ServiceAccount, TeamSlug: ta.team.Slug, ActiveKeys: r.ActiveKeys, CreatedByName: r.CreatedByName}
	}
	return out, nil
}

// Get returns one of the team's service accounts.
func (s *Service) Get(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) (View, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return View{}, err
	}
	return s.view(ctx, s.q, ta.team, id)
}

// Gateways lists the gateways one of the team's service accounts may use
// now (members; platform admins and auditors): its team's gateways, with its
// role, and platform gateways granted to its team. A key can be limited to
// these.
func (s *Service) Gateways(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) ([]gateways.Mine, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	sa, err := s.account(ctx, s.q, ta, id, false)
	if err != nil {
		return nil, err
	}
	return s.gateways.ListForServiceAccount(ctx, ta.team.ID, sa.Role, sa.ID, sa.ToolScope)
}

// AdminListParams narrows and pages the list of every team's accounts.
type AdminListParams struct {
	Search    *string // raw; LIKE-escaped here
	Team      string  // a team slug or ID ("" for all)
	AfterName *string
	AfterID   *uuid.UUID
	Limit     int32
}

// AdminList lists every team's service accounts by name (platform admins
// and auditors). An unknown team lists nothing.
func (s *Service) AdminList(ctx context.Context, a authz.Actor, p AdminListParams) ([]View, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	qp := dbgen.AdminListServiceAccountsParams{AfterName: p.AfterName, PageSize: p.Limit}
	if p.Search != nil {
		escaped := store.EscapeLike(*p.Search)
		qp.Search = &escaped
	}
	if p.AfterID != nil {
		qp.AfterID = uuid.NullUUID{UUID: *p.AfterID, Valid: true}
	}
	if p.Team != "" {
		t, err := teams.Resolve(ctx, s.q, p.Team)
		if e, ok := apperr.As(err); ok && e.Status == http.StatusNotFound {
			return []View{}, nil
		} else if err != nil {
			return nil, err
		}
		qp.TeamID = uuid.NullUUID{UUID: t.ID, Valid: true}
	}
	rows, err := s.q.AdminListServiceAccounts(ctx, qp)
	if err != nil {
		return nil, err
	}
	out := make([]View, len(rows))
	for i, r := range rows {
		out[i] = View{Account: r.ServiceAccount, TeamSlug: r.TeamSlug, ActiveKeys: r.ActiveKeys, CreatedByName: r.CreatedByName}
	}
	return out, nil
}

// CreateInput is a new service account.
type CreateInput struct {
	ToolScope               []byte
	Name, Description, Role string
	Enabled                 bool
}

func checkFields(name, description, role string) error {
	switch {
	case !nameRE.MatchString(name):
		return errBadName
	case utf8.RuneCountInString(description) > 2000:
		return errBadDesc
	case !authz.ValidServiceAccountRole(role):
		return errBadRole
	}
	return nil
}

// Create makes a service account (team owners and admins; at most
// MaxPerTeam). Audited as service_account.create.
func (s *Service) Create(ctx context.Context, a authz.Actor, ref string, in CreateInput) (View, error) {
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return View{}, err
	}
	in.Name = strings.TrimSpace(in.Name)
	if in.Role == "" {
		in.Role = authz.RoleMember
	}
	if err := checkFields(in.Name, in.Description, in.Role); err != nil {
		return View{}, err
	}
	var out View
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if _, err := q.LockTeam(ctx, ta.team.ID); err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		n, err := q.CountServiceAccounts(ctx, ta.team.ID)
		if err != nil {
			return err
		}
		if n >= MaxPerTeam {
			return errTooMany
		}
		sa, err := q.InsertServiceAccount(ctx, dbgen.InsertServiceAccountParams{
			TeamID: ta.team.ID, Name: in.Name, Description: in.Description, Role: in.Role, Enabled: in.Enabled, CreatedBy: by(a), ToolScope: toolScope,
		})
		if apperr.IsUniqueViolation(err, "service_accounts_team_name_key") {
			return errNameTaken
		} else if err != nil {
			return err
		}
		e := a.Audit("service_account.create", "service_account", sa.ID.String())
		e.TeamID, e.After = ta.team.ID, snapshot(sa)
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.view(ctx, q, ta.team, sa.ID)
		return err
	})
	return out, err
}

// UpdateInput holds optional changes.
type UpdateInput struct {
	// ToolScope nil retains; non-nil JSON null clears.
	ToolScope               []byte
	Name, Description, Role *string
	Enabled                 *bool
}

// Update changes a service account (team owners and admins), If-Match on
// its revision. Turning it off stops its keys at the next request. Audited
// as service_account.update.
func (s *Service) Update(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in UpdateInput, expectedRevision int64) (View, error) {
	var out View
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		cur, err := q.LockServiceAccount(ctx, dbgen.LockServiceAccountParams{ID: id, TeamID: ta.team.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		if cur.RelayPlatformID.Valid {
			return errRetired
		}
		if cur.Revision != expectedRevision {
			return apperr.Stale()
		}
		p := dbgen.UpdateServiceAccountParams{ID: cur.ID, Name: cur.Name, Description: cur.Description, Role: cur.Role,
			Enabled: cur.Enabled, UpdatedBy: by(a), ToolScope: cur.ToolScope}
		if in.ToolScope != nil {
			p.ToolScope, err = toolscope.Canonical(in.ToolScope)
			if err != nil {
				return err
			}
		}
		if in.Name != nil {
			p.Name = strings.TrimSpace(*in.Name)
		}
		if in.Description != nil {
			p.Description = *in.Description
		}
		if in.Role != nil {
			p.Role = *in.Role
		}
		if in.Enabled != nil {
			p.Enabled = *in.Enabled
		}
		if err := checkFields(p.Name, p.Description, p.Role); err != nil {
			return err
		}
		row, err := q.UpdateServiceAccount(ctx, p)
		if apperr.IsUniqueViolation(err, "service_accounts_team_name_key") {
			return errNameTaken
		} else if err != nil {
			return err
		}
		e := a.Audit("service_account.update", "service_account", cur.ID.String())
		e.TeamID, e.Before, e.After = ta.team.ID, snapshot(cur), snapshot(row)
		if err := audit.Record(ctx, q, e); err != nil {
			return err
		}
		out, err = s.view(ctx, q, ta.team, id)
		return err
	})
	return out, err
}

// Delete deletes a service account and its keys (team owners and admins);
// its call records stay. Audited as service_account.delete.
func (s *Service) Delete(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		cur, err := q.LockServiceAccount(ctx, dbgen.LockServiceAccountParams{ID: id, TeamID: ta.team.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNotFound
		} else if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		if cur.RelayPlatformID.Valid {
			return errRetired
		}
		if err := q.DeleteServiceAccount(ctx, cur.ID); err != nil {
			return err
		}
		e := a.Audit("service_account.delete", "service_account", cur.ID.String())
		e.TeamID, e.Before = ta.team.ID, snapshot(cur)
		return audit.Record(ctx, q, e)
	})
}

// KeyView is a key with the gateways it is limited to (none: every gateway
// the account may use).
type KeyView struct {
	Key           dbgen.ServiceAccountKey
	CreatedByName *string
	Gateways      []apikeys.GatewayRef
}

// CreatedKey is a new key and its secret (shown once).
type CreatedKey struct {
	KeyView
	Secret string
}

// KeyStatus says whether a key is active, expired or revoked at now.
func KeyStatus(k dbgen.ServiceAccountKey, now time.Time) string {
	switch {
	case k.RevokedAt != nil:
		return apikeys.StatusRevoked
	case !k.ExpiresAt.After(now):
		return apikeys.StatusExpired
	}
	return apikeys.StatusActive
}

// keySnapshot is a key's audited form: never the secret or its digest.
func keySnapshot(k dbgen.ServiceAccountKey, sa dbgen.ServiceAccount, gatewayIDs []uuid.UUID) map[string]any {
	ids := make([]string, len(gatewayIDs))
	for i, id := range gatewayIDs {
		ids[i] = id.String()
	}
	return map[string]any{"name": k.Name, "prefix": k.Prefix, "expiresAt": k.ExpiresAt, "gatewayIds": ids,
		"serviceAccountId": sa.ID.String(), "serviceAccount": sa.Name, "toolScope": toolscope.Stored(k.ToolScope)}
}

// account returns one of the team's accounts after the read check.
func (s *Service) account(ctx context.Context, q *dbgen.Queries, ta teamAccess, id uuid.UUID, lock bool) (dbgen.ServiceAccount, error) {
	var (
		sa  dbgen.ServiceAccount
		err error
	)
	if lock {
		sa, err = q.LockServiceAccount(ctx, dbgen.LockServiceAccountParams{ID: id, TeamID: ta.team.ID})
	} else {
		var row dbgen.GetServiceAccountViewRow
		row, err = q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: id, TeamID: ta.team.ID})
		sa = row.ServiceAccount
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return sa, errNotFound
	}
	return sa, err
}

// ListKeys lists an account's keys, newest first: active ones, and those
// revoked or expired in the last 30 days (team owners and admins; platform
// admins and auditors).
func (s *Service) ListKeys(ctx context.Context, a authz.Actor, ref string, id uuid.UUID) ([]KeyView, error) {
	ta, err := access(ctx, s.q, a, ref)
	if err != nil {
		return nil, err
	}
	sa, err := s.account(ctx, s.q, ta, id, false)
	if err != nil {
		return nil, err
	}
	if err := ta.readKeys(a); err != nil {
		return nil, err
	}
	rows, err := s.q.ListServiceAccountKeys(ctx, sa.ID)
	if err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ServiceAccountKey.ID
	}
	scopes, err := s.scopes(ctx, s.q, ids)
	if err != nil {
		return nil, err
	}
	out := make([]KeyView, len(rows))
	for i, r := range rows {
		out[i] = KeyView{Key: r.ServiceAccountKey, CreatedByName: r.CreatedByName, Gateways: scopes[r.ServiceAccountKey.ID]}
		if out[i].Gateways == nil {
			out[i].Gateways = []apikeys.GatewayRef{}
		}
	}
	return out, nil
}

func (s *Service) scopes(ctx context.Context, q *dbgen.Queries, keyIDs []uuid.UUID) (map[uuid.UUID][]apikeys.GatewayRef, error) {
	rows, err := q.ListServiceAccountKeyGateways(ctx, keyIDs)
	if err != nil {
		return nil, err
	}
	out := map[uuid.UUID][]apikeys.GatewayRef{}
	for _, r := range rows {
		out[r.KeyID] = append(out[r.KeyID], apikeys.GatewayRef{ID: r.GatewayID, Slug: r.Slug, Name: r.Name, Exists: r.GatewayExists})
	}
	return out, nil
}

// CreateKeyInput is a new key.
type CreateKeyInput struct {
	ToolScope []byte
	Name      string
	// Days is its lifetime (0: apikeys.DefaultDays).
	Days int32
	// GatewayIDs limits it to these gateways (empty: every gateway the
	// account may use). Each must be one the account may use now.
	GatewayIDs []uuid.UUID
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// CreateKey makes a key for an account (team owners and admins; at most
// MaxActiveKeys active; the account must be on). Audited as
// service_account_key.create, without the secret.
func (s *Service) CreateKey(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, in CreateKeyInput) (CreatedKey, error) {
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return CreatedKey{}, err
	}
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 1 || n > 100 || strings.ContainsAny(name, "\r\n\x00") {
		return CreatedKey{}, errBadKeyName
	}
	days := in.Days
	if days == 0 {
		days = apikeys.DefaultDays
	}
	if days < 1 || days > apikeys.MaxDays {
		return CreatedKey{}, errBadExpiry
	}
	gatewayIDs := dedupe(in.GatewayIDs)
	if len(gatewayIDs) > apikeys.MaxGateways {
		return CreatedKey{}, errTooManyGw
	}
	secret := KeyPrefix + httpx.NewID(32)
	var out CreatedKey
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		// Locking the account serialises its key creation, so the limit holds.
		sa, err := s.account(ctx, q, ta, id, true)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		if sa.RelayPlatformID.Valid {
			return errRetired
		}
		if !sa.Enabled {
			return errDisabled
		}
		var scope []dbgen.Gateway
		if len(gatewayIDs) > 0 {
			usable, refused, err := s.gateways.UsableByServiceAccount(ctx, ta.team.ID, sa.Role, gatewayIDs)
			if err != nil {
				return err
			}
			if len(refused) > 0 {
				e := apperr.New(http.StatusUnprocessableEntity, "gateway_not_usable",
					"A key can only be limited to gateways the service account can use now")
				e.Details = map[string]any{"gatewayIds": refused}
				return e
			}
			scope = usable
		}
		n, err := q.CountActiveServiceAccountKeys(ctx, sa.ID)
		if err != nil {
			return err
		}
		if n >= MaxActiveKeys {
			return errTooManyKeys
		}
		k, err := q.InsertServiceAccountKey(ctx, dbgen.InsertServiceAccountKeyParams{
			ServiceAccountID: sa.ID, Name: name, Prefix: secret[:prefixLen], Digest: apikeys.Digest(s.pepper, secret), ToolScope: toolScope,
			PepperID:  apikeys.PepperID(s.pepper),
			CreatedBy: by(a), ExpiresAt: time.Now().Add(time.Duration(days) * 24 * time.Hour),
		})
		if err != nil {
			return err
		}
		refs := make([]apikeys.GatewayRef, 0, len(scope))
		for _, g := range scope {
			if err := q.InsertServiceAccountKeyGateway(ctx, dbgen.InsertServiceAccountKeyGatewayParams{
				KeyID: k.ID, GatewayID: g.ID, GatewaySlug: g.Slug, GatewayName: g.Name,
			}); err != nil {
				return err
			}
			refs = append(refs, apikeys.GatewayRef{ID: g.ID, Slug: g.Slug, Name: g.Name, Exists: true})
		}
		slices.SortFunc(refs, func(x, y apikeys.GatewayRef) int { return strings.Compare(x.Name, y.Name) })
		row, err := q.GetServiceAccountKey(ctx, dbgen.GetServiceAccountKeyParams{ID: k.ID, ServiceAccountID: sa.ID})
		if err != nil {
			return err
		}
		out = CreatedKey{KeyView: KeyView{Key: k, CreatedByName: row.CreatedByName, Gateways: refs}, Secret: secret}
		e := a.Audit("service_account_key.create", "service_account_key", k.ID.String())
		e.TeamID, e.After = ta.team.ID, keySnapshot(k, sa, gatewayIDs)
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// RevokeKey revokes one of an account's keys (team owners and admins); it
// stops working at the next request. Revoking a revoked key changes
// nothing. Audited as service_account_key.revoke.
func (s *Service) RevokeKey(ctx context.Context, a authz.Actor, ref string, id, keyID uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		ta, err := access(ctx, q, a, ref)
		if err != nil {
			return err
		}
		sa, err := s.account(ctx, q, ta, id, true)
		if err != nil {
			return err
		}
		if err := ta.writable(); err != nil {
			return err
		}
		cur, err := q.GetServiceAccountKey(ctx, dbgen.GetServiceAccountKeyParams{ID: keyID, ServiceAccountID: sa.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errKeyNotFound
		} else if err != nil {
			return err
		}
		if cur.ServiceAccountKey.RevokedAt != nil {
			return nil
		}
		k, err := q.RevokeServiceAccountKey(ctx, dbgen.RevokeServiceAccountKeyParams{ID: keyID, ServiceAccountID: sa.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return nil // revoked concurrently
		} else if err != nil {
			return err
		}
		scope, err := q.ListServiceAccountKeyGatewayIDs(ctx, k.ID)
		if err != nil {
			return err
		}
		e := a.Audit("service_account_key.revoke", "service_account_key", k.ID.String())
		e.TeamID, e.Before = ta.team.ID, keySnapshot(cur.ServiceAccountKey, sa, scope)
		e.Metadata = map[string]any{"name": sa.Name + " · " + k.Name}
		return audit.Record(ctx, q, e)
	})
}

// Principal is who a service account key authenticates.
type Principal struct {
	Key     dbgen.ServiceAccountKey
	Account dbgen.ServiceAccount
	Team    dbgen.Team
	// Gateways limits the key to these gateways (empty: every gateway the
	// account may use).
	Gateways []uuid.UUID
}

// InScope reports whether the key may be used on a gateway (the account's
// access is checked separately).
func (p Principal) InScope(gatewayID uuid.UUID) bool {
	return len(p.Gateways) == 0 || slices.Contains(p.Gateways, gatewayID)
}

// Authenticate checks a key: it must exist, be unrevoked and unexpired, and
// belong to an enabled account of an active team. Every failure is
// ErrInvalid.
func (s *Service) Authenticate(ctx context.Context, secret string) (Principal, error) {
	if !LooksLikeKey(secret) {
		return Principal{}, ErrInvalid
	}
	d := apikeys.Digest(s.pepper, secret)
	row, err := s.q.GetServiceAccountKeyByDigest(ctx, d)
	previous := false
	if errors.Is(store.NotFound(err), store.ErrNotFound) && s.previous != nil {
		// Made before the pepper rotation: re-digested below.
		d, previous = apikeys.Digest(s.previous, secret), true
		row, err = s.q.GetServiceAccountKeyByDigest(ctx, d)
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return Principal{}, ErrInvalid
	} else if err != nil {
		return Principal{}, err
	}
	if !hmac.Equal([]byte(row.ServiceAccountKey.Digest), []byte(d)) ||
		KeyStatus(row.ServiceAccountKey, time.Now()) != apikeys.StatusActive ||
		row.ServiceAccount.RelayPlatformID.Valid || !row.ServiceAccount.Enabled || row.Team.Status != teams.StatusActive {
		return Principal{}, ErrInvalid
	}
	if previous {
		if err := s.rehash(ctx, row, d, apikeys.Digest(s.pepper, secret)); err != nil {
			return Principal{}, err
		}
	}
	scope, err := s.q.ListServiceAccountKeyGatewayIDs(ctx, row.ServiceAccountKey.ID)
	if err != nil {
		return Principal{}, err
	}
	return Principal{Key: row.ServiceAccountKey, Account: row.ServiceAccount, Team: row.Team, Gateways: scope}, nil
}

// rehash moves a key found with the previous pepper to the current one.
// Audited as service_account_key.pepper_rehash by the system.
func (s *Service) rehash(ctx context.Context, row dbgen.GetServiceAccountKeyByDigestRow, old, digest string) error {
	k := row.ServiceAccountKey
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		n, err := q.RehashServiceAccountKey(ctx, dbgen.RehashServiceAccountKeyParams{ID: k.ID, OldDigest: old, Digest: digest,
			PepperID: apikeys.PepperID(s.pepper)})
		if err != nil || n == 0 {
			return err // n == 0: another request did it
		}
		return audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, TeamID: row.Team.ID, Action: "service_account_key.pepper_rehash",
			TargetType: "service_account_key", TargetID: k.ID.String(), Metadata: map[string]any{"name": k.Name, "prefix": k.Prefix,
				"serviceAccountId": row.ServiceAccount.ID.String()}})
	})
}

// Touch records that a key and its account were used (at most once a
// minute each).
func (s *Service) Touch(ctx context.Context, p Principal) error {
	if err := s.q.TouchServiceAccountKey(ctx, p.Key.ID); err != nil {
		return err
	}
	return s.q.TouchServiceAccount(ctx, p.Account.ID)
}
