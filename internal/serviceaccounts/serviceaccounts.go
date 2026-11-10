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
	"errors"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
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
