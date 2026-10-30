// Package teams manages teams (the tenant), memberships and email invites.
//
// Every mutation locks the team row first, so owner counting, role changes
// and invites for one team are serialised, and writes its audit entry in the
// same transaction. Invites send no email in this release: an open invite is
// accepted when someone signs in with the invited, verified address.
package teams

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// InviteTTL is how long an email invite stays valid.
const InviteTTL = 30 * 24 * time.Hour

// Team statuses.
const (
	StatusActive   = "active"
	StatusArchived = "archived"
)

var slugRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// reservedSlugs would collide with fixed URL segments in the API and the UI.
var reservedSlugs = map[string]bool{
	"id": true, "admin": true, "api": true, "v1": true, "new": true, "auth": true,
	"assets": true, "static": true, "me": true, "teams": true, "mcp": true,
	"oauth": true, "catalog": true, "gateways": true, "servers": true,
}

// ValidateSlug checks a team slug.
func ValidateSlug(slug string) error {
	if !slugRE.MatchString(slug) {
		return apperr.Invalid("invalid_slug", "Slug must be 1-63 lowercase letters, digits or hyphens, and cannot start or end with a hyphen")
	}
	if reservedSlugs[slug] {
		return apperr.Invalid("invalid_slug", "That slug is reserved")
	}
	if _, err := uuid.Parse(slug); err == nil {
		return apperr.Invalid("invalid_slug", "Slug cannot look like an ID")
	}
	return nil
}

// NormalizeEmail lower-cases and validates an email address.
func NormalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || len(email) > 254 {
		return "", apperr.Invalid("invalid_email", "Enter a valid email address")
	}
	return email, nil
}

type Service struct {
	pool *pgxpool.Pool
	q    *dbgen.Queries
}

func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool, q: dbgen.New(pool)} }

var errTeamNotFound = apperr.NotFound("team_not_found", "Team not found")

// resolve finds a team by UUID or slug.
func resolve(ctx context.Context, q *dbgen.Queries, ref string) (dbgen.Team, error) {
	var (
		t   dbgen.Team
		err error
	)
	if id, perr := uuid.Parse(ref); perr == nil {
		t, err = q.GetTeamByID(ctx, id)
	} else {
		t, err = q.GetTeamBySlug(ctx, strings.ToLower(ref))
	}
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return t, errTeamNotFound
	}
	return t, err
}

// Resolve finds a team by UUID or slug (404 team_not_found), for other
// modules' queries, such as inside their transactions.
func Resolve(ctx context.Context, q *dbgen.Queries, ref string) (dbgen.Team, error) {
	return resolve(ctx, q, ref)
}

// MemberRole returns the user's role in the team, or "" when not a member.
func MemberRole(ctx context.Context, q *dbgen.Queries, teamID, userID uuid.UUID) (string, error) {
	return memberRole(ctx, q, teamID, userID)
}

func memberRole(ctx context.Context, q *dbgen.Queries, teamID, userID uuid.UUID) (string, error) {
	m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: teamID, UserID: userID})
	if errors.Is(store.NotFound(err), store.ErrNotFound) {
		return "", nil
	}
	return m.Role, err
}

// Access is a team as seen by an actor.
type Access struct {
	Team dbgen.Team
	Role string // the actor's team role, or "" when not a member
}

// Get returns a team the actor may see: members see their teams; platform
// admins and auditors see all team metadata. Others get 404 so team
// existence is not revealed.
func (s *Service) Get(ctx context.Context, a authz.Actor, ref string) (Access, error) {
	t, err := resolve(ctx, s.q, ref)
	if err != nil {
		return Access{}, err
	}
	role, err := memberRole(ctx, s.q, t.ID, a.UserID)
	if err != nil {
		return Access{}, err
	}
	if role == "" && !a.CanReadPlatform() {
		return Access{}, errTeamNotFound
	}
	return Access{Team: t, Role: role}, nil
}

// ListMine returns the actor's team memberships.
func (s *Service) ListMine(ctx context.Context, userID uuid.UUID) ([]dbgen.ListTeamsForUserRow, error) {
	return s.q.ListTeamsForUser(ctx, userID)
}

// Member is a membership joined with its user.
type Member = dbgen.ListMembersRow

// ListMembers returns a team's members. Members, and platform admins and
// auditors (membership is metadata, not content), may list them.
func (s *Service) ListMembers(ctx context.Context, a authz.Actor, ref string) ([]Member, error) {
	acc, err := s.Get(ctx, a, ref)
	if err != nil {
		return nil, err
	}
	return s.q.ListMembers(ctx, acc.Team.ID)
}

// ListInvites returns open invites. Team owners/admins and platform
// admins/auditors may see them.
func (s *Service) ListInvites(ctx context.Context, a authz.Actor, ref string) ([]dbgen.TeamInvite, error) {
	acc, err := s.Get(ctx, a, ref)
	if err != nil {
		return nil, err
	}
	if !authz.RoleAtLeast(acc.Role, authz.RoleAdmin) && !a.CanReadPlatform() {
		return nil, apperr.Forbidden("Only team owners and admins can see invites")
	}
	return s.q.ListOpenInvites(ctx, acc.Team.ID)
}

// lockForMembership locks the team and returns the actor's role. Archived
// teams are read-only.
func lockForMembership(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string) (dbgen.Team, string, error) {
	t, err := resolve(ctx, q, ref)
	if err != nil {
		return t, "", err
	}
	if t, err = q.LockTeam(ctx, t.ID); err != nil {
		return t, "", err
	}
	role, err := memberRole(ctx, q, t.ID, a.UserID)
	if err != nil {
		return t, "", err
	}
	if role == "" && !a.CanReadPlatform() {
		return t, "", errTeamNotFound
	}
	if t.Status != StatusActive {
		return t, role, apperr.Conflict("team_archived", "This team is archived and read-only")
	}
	return t, role, nil
}

// AddResult reports what adding a member by email did.
type AddResult struct {
	Status string // "added" or "invited"
	Member *Member
	Invite *dbgen.TeamInvite
}

// AddMember adds a user by email, or invites the address if nobody with it
// has signed in yet.
func (s *Service) AddMember(ctx context.Context, a authz.Actor, ref, email, role string) (AddResult, error) {
	var res AddResult
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, actorRole, err := lockForMembership(ctx, q, a, ref)
		if err != nil {
			return err
		}
		if err := authz.CheckMemberChange(actorRole, "", role); err != nil {
			return err
		}
		res, err = addOrInvite(ctx, q, a, t, email, role, "team.member_add")
		return err
	})
	return res, err
}

// addOrInvite adds an existing user or creates/refreshes an invite. The team
// must already be locked and the change authorised.
func addOrInvite(ctx context.Context, q *dbgen.Queries, a authz.Actor, t dbgen.Team, rawEmail, role, action string) (AddResult, error) {
	email, err := NormalizeEmail(rawEmail)
	if err != nil {
		return AddResult{}, err
	}
	if !authz.ValidTeamRole(role) {
		return AddResult{}, apperr.Invalid("invalid_role", "Role must be owner, admin, editor or member")
	}
	users, err := q.ListUsersByEmail(ctx, email)
	if err != nil {
		return AddResult{}, err
	}
	switch len(users) {
	case 0:
		return invite(ctx, q, a, t, email, role)
	case 1:
	default:
		return AddResult{}, apperr.Conflict("ambiguous_email", "More than one account uses this email address. Contact a platform admin.")
	}
	u := users[0]
	if _, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: u.ID}); err == nil {
		return AddResult{}, apperr.Conflict("already_member", "That person is already a member of this team")
	} else if !errors.Is(store.NotFound(err), store.ErrNotFound) {
		return AddResult{}, err
	}
	m, err := q.InsertMember(ctx, dbgen.InsertMemberParams{
		TeamID: t.ID, UserID: u.ID, Role: role, AddedBy: uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil},
	})
	if err != nil {
		return AddResult{}, err
	}
	e := a.Audit(action, "user", u.ID.String())
	e.TeamID, e.After = t.ID, map[string]any{"role": role}
	if err := audit.Record(ctx, q, e); err != nil {
		return AddResult{}, err
	}
	return AddResult{Status: "added", Member: &Member{TeamMember: m, User: u}}, nil
}

// invite creates (or refreshes) the open invite for an address nobody has
// signed in with yet.
func invite(ctx context.Context, q *dbgen.Queries, a authz.Actor, t dbgen.Team, email, role string) (AddResult, error) {
	inv, err := q.UpsertInvite(ctx, dbgen.UpsertInviteParams{
		TeamID: t.ID, Email: email, Role: role,
		InvitedBy: uuid.NullUUID{UUID: a.UserID, Valid: a.UserID != uuid.Nil}, ExpiresAt: time.Now().Add(InviteTTL),
	})
	if err != nil {
		return AddResult{}, err
	}
	e := a.Audit("team.invite_create", "team_invite", inv.ID.String())
	e.TeamID, e.After = t.ID, map[string]any{"email": email, "role": role, "expiresAt": inv.ExpiresAt}
	if err := audit.Record(ctx, q, e); err != nil {
		return AddResult{}, err
	}
	return AddResult{Status: "invited", Invite: &inv}, nil
}

// UpdateMember changes a member's role. expectedRevision must match the
// membership's current revision.
func (s *Service) UpdateMember(ctx context.Context, a authz.Actor, ref string, userID uuid.UUID, role string, expectedRevision int64) (Member, error) {
	var out Member
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, actorRole, err := lockForMembership(ctx, q, a, ref)
		if err != nil {
			return err
		}
		target, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: userID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return apperr.NotFound("member_not_found", "That person is not a member of this team")
		} else if err != nil {
			return err
		}
		if err := authz.CheckMemberChange(actorRole, target.Role, role); err != nil {
			return err
		}
		if target.Revision != expectedRevision {
			return apperr.Stale()
		}
		if before := target.Role; before != role {
			if role != authz.RoleOwner {
				if err := ensureAnotherOwner(ctx, q, t.ID, before); err != nil {
					return err
				}
			}
			if target, err = q.UpdateMemberRole(ctx, dbgen.UpdateMemberRoleParams{TeamID: t.ID, UserID: userID, Role: role}); err != nil {
				return err
			}
			e := a.Audit("team.member_role_change", "user", userID.String())
			e.TeamID = t.ID
			e.Before, e.After = map[string]any{"role": before}, map[string]any{"role": role}
			if err := audit.Record(ctx, q, e); err != nil {
				return err
			}
		}
		u, err := q.GetUser(ctx, userID)
		out = Member{TeamMember: target, User: u}
		return err
	})
	return out, err
}

// RemoveMember removes a member. Anyone may remove themselves (leave the
// team); otherwise the normal member-management rules apply.
func (s *Service) RemoveMember(ctx context.Context, a authz.Actor, ref string, userID uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, actorRole, err := lockForMembership(ctx, q, a, ref)
		if err != nil {
			return err
		}
		target, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: userID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return apperr.NotFound("member_not_found", "That person is not a member of this team")
		} else if err != nil {
			return err
		}
		action := "team.member_leave"
		if userID != a.UserID {
			action = "team.member_remove"
			if err := authz.CheckMemberChange(actorRole, target.Role, ""); err != nil {
				return err
			}
		}
		if err := ensureAnotherOwner(ctx, q, t.ID, target.Role); err != nil {
			return err
		}
		if err := q.DeleteMember(ctx, dbgen.DeleteMemberParams{TeamID: t.ID, UserID: userID}); err != nil {
			return err
		}
		e := a.Audit(action, "user", userID.String())
		e.TeamID, e.Before = t.ID, map[string]any{"role": target.Role}
		return audit.Record(ctx, q, e)
	})
}

// ensureAnotherOwner blocks removing or demoting the last owner. The team
// row must be locked.
func ensureAnotherOwner(ctx context.Context, q *dbgen.Queries, teamID uuid.UUID, currentRole string) error {
	if currentRole != authz.RoleOwner {
		return nil
	}
	n, err := q.CountOwners(ctx, teamID)
	if err != nil {
		return err
	}
	if n <= 1 {
		return apperr.Conflict("last_owner", "A team must keep at least one owner. Add another owner first.")
	}
	return nil
}

// RevokeInvite cancels an open invite.
func (s *Service) RevokeInvite(ctx context.Context, a authz.Actor, ref string, inviteID uuid.UUID) error {
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		t, actorRole, err := lockForMembership(ctx, q, a, ref)
		if err != nil {
			return err
		}
		inv, err := q.GetOpenInvite(ctx, dbgen.GetOpenInviteParams{ID: inviteID, TeamID: t.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return apperr.NotFound("invite_not_found", "Invite not found")
		} else if err != nil {
			return err
		}
		// Platform admins revoke any open invite, such as an owner invite they
		// sent from Admin -> Teams; auditors can't.
		if err := authz.CheckMemberChange(actorRole, inv.Role, ""); err != nil && !a.IsPlatformAdmin() {
			return err
		}
		if err := q.RevokeInvite(ctx, inv.ID); err != nil {
			return err
		}
		e := a.Audit("team.invite_revoke", "team_invite", inv.ID.String())
		e.TeamID, e.Before = t.ID, map[string]any{"email": inv.Email, "role": inv.Role}
		return audit.Record(ctx, q, e)
	})
}

// AcceptInvites turns open, unexpired invites for a verified email into
// memberships. It runs inside the sign-in transaction. Existing memberships
// keep their current role. Like manual invite/membership writers, it locks the
// team before any invite. Candidate teams are sorted; invites are re-read after
// the team lock, so a concurrent revocation, expiry or role change is honoured.
// An invite for a new candidate team arriving after discovery waits until the
// next sign-in; it is never consumed without the corresponding team lock.
func AcceptInvites(ctx context.Context, q *dbgen.Queries, user dbgen.User, requestID, clientIP string) error {
	teamIDs, err := q.ListInviteTeamsForEmail(ctx, user.Email)
	if err != nil {
		return err
	}
	lockedTeams := make([]uuid.UUID, 0, len(teamIDs))
	for _, teamID := range teamIDs {
		if _, err := q.LockTeam(ctx, teamID); errors.Is(err, pgx.ErrNoRows) {
			continue // a removed candidate team cannot grant membership
		} else if err != nil {
			return err
		}
		lockedTeams = append(lockedTeams, teamID)
	}
	for _, teamID := range lockedTeams {
		invites, err := q.ClaimTeamInvitesForEmail(ctx, dbgen.ClaimTeamInvitesForEmailParams{TeamID: teamID, Email: user.Email})
		if err != nil {
			return err
		}
		if err := acceptTeamInvites(ctx, q, user, invites, requestID, clientIP); err != nil {
			return err
		}
	}
	return nil
}

func acceptTeamInvites(ctx context.Context, q *dbgen.Queries, user dbgen.User, invites []dbgen.ClaimTeamInvitesForEmailRow, requestID, clientIP string) error {
	for _, inv := range invites {
		n, err := q.InsertMemberIfAbsent(ctx, dbgen.InsertMemberIfAbsentParams{
			TeamID: inv.TeamID, UserID: user.ID, Role: inv.Role, AddedBy: inv.InvitedBy,
		})
		if err != nil {
			return err
		}
		if err := q.AcceptInvite(ctx, dbgen.AcceptInviteParams{ID: inv.ID, UserID: uuid.NullUUID{UUID: user.ID, Valid: true}}); err != nil {
			return err
		}
		if err := audit.Record(ctx, q, audit.Entry{
			ActorKind: audit.ActorUser, ActorUserID: user.ID, TeamID: inv.TeamID,
			Action: "team.invite_accept", TargetType: "team_invite", TargetID: inv.ID.String(),
			After:     map[string]any{"role": inv.Role},
			Metadata:  map[string]any{"alreadyMember": n == 0},
			RequestID: requestID, ClientIP: clientIP,
		}); err != nil {
			return err
		}
	}
	return nil
}
