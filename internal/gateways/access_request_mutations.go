package gateways

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func requestTeam(ctx context.Context, q *dbgen.Queries, requester uuid.UUID, team uuid.NullUUID) (dbgen.Team, error) {
	if !team.Valid {
		return dbgen.Team{}, nil
	}
	t, err := q.LockTeam(ctx, team.UUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, errTeamNotFound
	}
	if err != nil {
		return t, err
	}
	m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: requester})
	if errors.Is(err, pgx.ErrNoRows) {
		return t, errTeamNotFound
	}
	if err != nil {
		return t, err
	}
	if !authz.RoleAtLeast(m.Role, authz.RoleAdmin) {
		return t, apperr.Forbidden("Only a team's current owners and admins may request its access")
	}
	if t.Status != "active" {
		return t, errTeamArchived
	}
	return t, nil
}

func requestGateway(ctx context.Context, q *dbgen.Queries, id uuid.UUID) (dbgen.Gateway, error) {
	g, err := getGateway(ctx, q, id, true)
	if err != nil {
		return g, err
	}
	if g.OwnerKind != OwnerPlatform || !g.Enabled || !g.AccessRequestsEnabled {
		return g, errNoGateway
	}
	return g, nil
}

func requestAudit(ctx context.Context, q *dbgen.Queries, a authz.Actor, r dbgen.AccessRequest, action string) error {
	g, err := q.GetGateway(ctx, r.GatewayID)
	if err != nil {
		return err
	}
	e := a.Audit("access_request."+action, "access_request", r.ID.String())
	e.Metadata = map[string]any{"name": g.Name, "gatewayId": r.GatewayID.String(), "requesterId": r.RequesterUserID.String(), "subjectKind": r.SubjectKind,
		"status": r.Status, "grantExpiresAt": r.GrantExpiresAt}
	if r.TeamID.Valid {
		e.Metadata["subjectTeamId"] = r.TeamID.UUID.String()
	}
	if r.GrantID.Valid {
		e.Metadata["grantId"] = r.GrantID.UUID.String()
	}
	// Only the gateway's ordinary audit label, IDs, status and expiry are
	// recorded. Never copy request reasons, notes or requester emails.
	return audit.Record(ctx, q, e)
}

func (s *Service) CreateAccessRequest(ctx context.Context, a authz.Actor, gateway uuid.UUID, team *uuid.UUID, reason string) (AccessRequest, error) {
	if err := accessBrowser(a); err != nil {
		return AccessRequest{}, err
	}
	reason, err := accessText(reason, true)
	if err != nil {
		return AccessRequest{}, err
	}
	kind, teamID := SubjectUser, uuid.NullUUID{}
	if team != nil {
		kind, teamID = SubjectTeam, uuid.NullUUID{UUID: *team, Valid: true}
	}
	var out AccessRequest
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		if err := q.LockAccessRequester(ctx, a.UserID); err != nil {
			return err
		}
		actor, users, err := accessActors(ctx, q, a)
		if err != nil {
			return err
		}
		if _, err := requestTeam(ctx, q, actor.UserID, teamID); err != nil {
			return err
		}
		g, err := requestGateway(ctx, q, gateway)
		if err != nil {
			return err
		}
		n, err := q.PendingAccessRequestsForUser(ctx, actor.UserID)
		if err != nil {
			return err
		}
		if n >= 10 {
			return apperr.Conflict("too_many_requests", "At most 10 access requests may be pending")
		}
		cooldown, err := q.AccessRequestCooldown(ctx, dbgen.AccessRequestCooldownParams{GatewayID: gateway, RequesterUserID: actor.UserID, SubjectKind: kind, TeamID: teamID})
		if err != nil {
			return err
		}
		if cooldown {
			return apperr.Conflict("request_cooldown", "Wait 24 hours after a denial before requesting this access again")
		}
		if teamID.Valid {
			grants, err := q.GatewayGrantsForTeam(ctx, dbgen.GatewayGrantsForTeamParams{GatewayID: gateway, TeamID: teamID})
			if err != nil {
				return err
			}
			if len(grants) > 0 {
				return errGrantExists
			}
		} else {
			caller, err := callerOf(ctx, q, g, users[actor.UserID])
			if err != nil {
				return err
			}
			if caller.Allowed() {
				return errGrantExists
			}
		}
		r, err := q.InsertAccessRequest(ctx, dbgen.InsertAccessRequestParams{GatewayID: gateway, RequesterUserID: actor.UserID, SubjectKind: kind, TeamID: teamID, Reason: reason})
		if apperr.IsUniqueViolation(err, "") {
			return apperr.Conflict("request_pending", "This access request is already pending")
		}
		if err != nil {
			return err
		}
		if err := requestAudit(ctx, q, actor, r, "create"); err != nil {
			return err
		}
		if s.AccessNotice != nil {
			s.AccessNotice(ctx, q, r, true)
		}
		out, err = accessView(ctx, q, actor, r)
		return err
	})
	return out, err
}

func (s *Service) DecideAccessRequest(ctx context.Context, a authz.Actor, id uuid.UUID, in AccessDecision) (AccessRequest, error) {
	if err := accessBrowser(a); err != nil {
		return AccessRequest{}, err
	}
	if in.Decision != "approve" && in.Decision != "deny" {
		return AccessRequest{}, apperr.Invalid("invalid_decision", "Choose approve or deny")
	}
	if in.Decision == "deny" && in.ExpiresInDays != nil {
		return AccessRequest{}, apperr.Invalid("invalid_expiry", "Only an approved grant can expire")
	}
	note, err := accessText(in.Note, false)
	if err != nil {
		return AccessRequest{}, err
	}
	initial, err := s.q.GetAccessRequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, errAccessRequest
	}
	if err != nil {
		return AccessRequest{}, err
	}
	if initial.RequesterUserID == a.UserID {
		return AccessRequest{}, apperr.Forbidden("You cannot decide your own access request")
	}
	eligible, err := s.q.AccessRequestReviewer(ctx, dbgen.AccessRequestReviewerParams{UserID: a.UserID, GatewayID: initial.GatewayID})
	if err != nil {
		return AccessRequest{}, err
	}
	if !eligible {
		return AccessRequest{}, errAccessRequest
	}
	var out AccessRequest
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		actor, users, err := accessActors(ctx, q, a, initial.RequesterUserID)
		if err != nil {
			return err
		}
		requester, ok := users[initial.RequesterUserID]
		if !ok || requester.Status != "active" {
			return apperr.Conflict("requester_inactive", "The requester is no longer active")
		}
		team, err := requestTeam(ctx, q, initial.RequesterUserID, initial.TeamID)
		if err != nil {
			return err
		}
		g, err := requestGateway(ctx, q, initial.GatewayID)
		if err != nil {
			return err
		}
		reviewer, err := q.AccessRequestReviewer(ctx, dbgen.AccessRequestReviewerParams{UserID: actor.UserID, GatewayID: g.ID})
		if err != nil {
			return err
		}
		if !reviewer {
			return errAccessRequest
		}
		r, err := q.LockAccessRequest(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return errAccessRequest
		}
		if err != nil {
			return err
		}
		if r.Status != "pending" {
			return apperr.Conflict("request_decided", "This request is no longer pending")
		}
		p := dbgen.DecideAccessRequestParams{ID: id, Status: "denied", DecidedBy: by(actor), DecisionNote: note}
		if in.Decision == "approve" {
			expires, err := grantExpiry(ctx, q, in.ExpiresInDays)
			if err != nil {
				return err
			}
			grant := dbgen.InsertGatewayGrantParams{GatewayID: g.ID, SubjectKind: r.SubjectKind, TeamID: r.TeamID, AddedBy: by(actor), ExpiresAt: expires}
			subject := team.Slug
			if r.SubjectKind == SubjectUser {
				grant.UserID = uuid.NullUUID{UUID: r.RequesterUserID, Valid: true}
				subject = requester.Email // exact requester ID, never ambiguous email lookup
			}
			row, err := insertGrant(ctx, q, actor, g, grant, subject)
			if err != nil {
				return err
			}
			p.Status, p.GrantID, p.GrantExpiresAt = "approved", uuid.NullUUID{UUID: row.ID, Valid: true}, row.ExpiresAt
		}
		r, err = q.DecideAccessRequest(ctx, p)
		if err != nil {
			return err
		}
		if err := requestAudit(ctx, q, actor, r, in.Decision); err != nil {
			return err
		}
		if s.AccessNotice != nil {
			s.AccessNotice(ctx, q, r, false)
		}
		out, err = accessView(ctx, q, actor, r)
		return err
	})
	return out, err
}

func (s *Service) WithdrawAccessRequest(ctx context.Context, a authz.Actor, id uuid.UUID) (AccessRequest, error) {
	if err := accessBrowser(a); err != nil {
		return AccessRequest{}, err
	}
	var out AccessRequest
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		actor, _, err := accessActors(ctx, q, a)
		if err != nil {
			return err
		}
		r, err := q.LockAccessRequest(ctx, id)
		if errors.Is(err, pgx.ErrNoRows) {
			return errAccessRequest
		}
		if err != nil {
			return err
		}
		if r.RequesterUserID != actor.UserID {
			return errAccessRequest
		}
		if r.Status != "pending" {
			return apperr.Conflict("request_decided", "This request is no longer pending")
		}
		r, err = q.DecideAccessRequest(ctx, dbgen.DecideAccessRequestParams{ID: id, Status: "withdrawn"})
		if err != nil {
			return err
		}
		if err := requestAudit(ctx, q, actor, r, "withdraw"); err != nil {
			return err
		}
		out, err = accessView(ctx, q, actor, r)
		return err
	})
	return out, err
}
