// Package platform implements platform administration of user access:
// listing users, changing platform roles and suspending accounts. Team
// administration lives in package teams.
package platform

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

var (
	errAdminOnly  = apperr.Forbidden("Only platform admins can do this")
	errReadOnly   = apperr.Forbidden("Only platform admins and auditors can see this")
	errUserAbsent = apperr.NotFound("user_not_found", "User not found")
)

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, q: dbgen.New(pool)}
}

// UserListParams page the user list by (email, id).
type UserListParams struct {
	Search *string
	// Role and Status filter exactly (nil = any).
	Role, Status *string
	AfterEmail   *string
	AfterID      *uuid.UUID
	Limit        int32
}

func (s *Service) ListUsers(ctx context.Context, a authz.Actor, p UserListParams) ([]dbgen.User, error) {
	if !a.CanReadPlatform() {
		return nil, errReadOnly
	}
	params := dbgen.ListUsersParams{Search: p.Search, PlatformRole: p.Role, Status: p.Status, AfterEmail: p.AfterEmail, PageSize: p.Limit}
	if p.Search != nil {
		escaped := store.EscapeLike(*p.Search)
		params.Search = &escaped
	}
	if p.AfterID != nil {
		params.AfterID = uuid.NullUUID{UUID: *p.AfterID, Valid: true}
	}
	return s.q.ListUsers(ctx, params)
}

// UserTeamCounts returns how many teams each of the users belongs to.
func (s *Service) UserTeamCounts(ctx context.Context, a authz.Actor, ids []uuid.UUID) (map[uuid.UUID]int64, error) {
	if !a.CanReadPlatform() {
		return nil, errReadOnly
	}
	rows, err := s.q.UserTeamCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := make(map[uuid.UUID]int64, len(rows))
	for _, r := range rows {
		out[r.UserID] = r.Teams
	}
	return out, nil
}

// UserDetail is a user with their team memberships.
type UserDetail struct {
	User  dbgen.User
	Teams []dbgen.ListTeamsForUserRow
}

func (s *Service) GetUser(ctx context.Context, a authz.Actor, id uuid.UUID) (UserDetail, error) {
	if !a.CanReadPlatform() {
		return UserDetail{}, errReadOnly
	}
	u, err := s.q.GetUser(ctx, id)
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return UserDetail{}, errUserAbsent
	} else if err != nil {
		return UserDetail{}, err
	}
	teams, err := s.q.ListTeamsForUser(ctx, id)
	return UserDetail{User: u, Teams: teams}, err
}

// UserUpdate holds optional access changes.
type UserUpdate struct {
	PlatformRole *string
	Status       *string
}

var validPlatformRoles = map[string]bool{authz.PlatformNone: true, authz.PlatformAdmin: true, authz.PlatformAuditor: true}

// UpdateUser changes a user's platform role or suspends/reactivates them.
// The last active platform admin can never be demoted or suspended.
// Suspension ends all of the user's sessions immediately.
func (s *Service) UpdateUser(ctx context.Context, a authz.Actor, id uuid.UUID, in UserUpdate, expectedRevision int64) (dbgen.User, error) {
	if !a.IsPlatformAdmin() {
		return dbgen.User{}, errAdminOnly
	}
	var out dbgen.User
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		// Lock admins before the target so every writer takes locks in the
		// same order.
		admins, err := q.LockActivePlatformAdmins(ctx)
		if err != nil {
			return err
		}
		u, err := q.GetUserForUpdate(ctx, id)
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errUserAbsent
		} else if err != nil {
			return err
		}
		if u.Revision != expectedRevision {
			return apperr.Stale()
		}
		role, status, err := userAccess(u, in)
		if err != nil {
			return err
		}
		if role == u.PlatformRole && status == u.ManualStatus {
			out = u
			return nil
		}
		wasActiveAdmin := u.PlatformRole == authz.PlatformAdmin && u.Status == "active"
		staysActiveAdmin := role == authz.PlatformAdmin && status == "active"
		if wasActiveAdmin && !staysActiveAdmin && len(admins) <= 1 {
			return apperr.Conflict("last_admin", "This is the last active platform admin. Make someone else an admin first.")
		}
		if out, err = q.UpdateUserAccess(ctx, dbgen.UpdateUserAccessParams{ID: id, PlatformRole: role, Status: status}); err != nil {
			return err
		}
		if status == "suspended" {
			if err := q.DeleteUserSessions(ctx, id); err != nil {
				return err
			}
		}
		e := a.Audit(userAction(u, role, status), "user", id.String())
		e.Before = map[string]any{"platformRole": u.PlatformRole, "status": u.Status, "manualStatus": u.ManualStatus}
		e.After = map[string]any{"platformRole": out.PlatformRole, "status": out.Status, "manualStatus": out.ManualStatus}
		if u.DirectoryStanding != "none" {
			e.Metadata = map[string]any{"directoryStanding": out.DirectoryStanding}
		}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

// userAccess applies a role and manual-status change to the user's current
// ones. A directory restriction is separate and never lifted here.
func userAccess(u dbgen.User, in UserUpdate) (role, status string, err error) {
	role, status = u.PlatformRole, u.ManualStatus
	if in.PlatformRole != nil {
		if !validPlatformRoles[*in.PlatformRole] {
			return "", "", apperr.Invalid("invalid_role", "Platform role must be none, platform_admin or platform_auditor")
		}
		role = *in.PlatformRole
	}
	if in.Status != nil {
		if *in.Status != "active" && *in.Status != "suspended" {
			return "", "", apperr.Invalid("invalid_status", "Status must be active or suspended")
		}
		status = *in.Status
	}
	return role, status, nil
}

// userAction is the audit action of a user access change.
func userAction(u dbgen.User, role, status string) string {
	switch {
	case u.ManualStatus != status && status == "suspended":
		return "platform.user_suspend"
	case u.ManualStatus != status:
		return "platform.user_reactivate"
	case u.PlatformRole != role:
		return "platform.user_role_change"
	}
	return "platform.user_update"
}
