package gateways

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

var errAccessRequest = apperr.NotFound("access_request_not_found", "Access request not found")

// AccessRequest is an authorized private projection, never a database-row dump.
type AccessRequest struct {
	ID             uuid.UUID  `json:"id"`
	GatewayID      uuid.UUID  `json:"gatewayId"`
	GatewayName    string     `json:"gatewayName"`
	RequesterID    uuid.UUID  `json:"requesterId"`
	RequesterName  string     `json:"requesterName"`
	SubjectKind    string     `json:"subjectKind"`
	TeamID         *uuid.UUID `json:"teamId,omitempty"`
	TeamName       string     `json:"teamName,omitempty"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"createdAt"`
	DecidedAt      *time.Time `json:"decidedAt"`
	DecisionNote   string     `json:"decisionNote"`
	GrantID        *uuid.UUID `json:"grantId"`
	GrantExpiresAt *time.Time `json:"grantExpiresAt"`
	CanDecide      bool       `json:"canDecide"`
}

type AccessSettings struct {
	Enabled    bool        `json:"enabled"`
	StewardIDs []uuid.UUID `json:"stewardIds"`
	Revision   int64       `json:"revision"`
}

type AccessDecision struct {
	Decision, Note string
	ExpiresInDays  *int32
}

func accessBrowser(a authz.Actor) error {
	if a.IsToken() || a.UserID == uuid.Nil {
		return apperr.New(403, "session_required", "A browser session is required")
	}
	return nil
}

// Lock users in UUID order so reciprocal requests/reviews cannot deadlock by
// taking requester and reviewer locks in opposite orders. SHARE prevents live
// suspension/demotion through commit. No user row is mutated here.
func accessActors(ctx context.Context, q *dbgen.Queries, a authz.Actor, ids ...uuid.UUID) (authz.Actor, map[uuid.UUID]dbgen.User, error) {
	if err := accessBrowser(a); err != nil {
		return a, nil, err
	}
	ids = append(ids, a.UserID)
	rows, err := q.LockAccessRequestActors(ctx, ids)
	if err != nil {
		return a, nil, err
	}
	users := make(map[uuid.UUID]dbgen.User, len(rows))
	for _, u := range rows {
		users[u.ID] = u
	}
	u, ok := users[a.UserID]
	if !ok || u.Status != "active" {
		return a, nil, apperr.Forbidden("An active browser identity is required")
	}
	a.PlatformRole = u.PlatformRole
	return a, users, nil
}

func accessText(value string, required bool) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 1000 || (required && value == "") ||
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) >= 0 {
		code := "invalid_reason"
		if !required {
			code = "invalid_note"
		}
		return "", apperr.Invalid(code, "Use plain text of at most 1000 characters; a request reason cannot be empty")
	}
	return value, nil
}

func (s *Service) Requestable(ctx context.Context, a authz.Actor, offset, limit int32) ([]dbgen.ListRequestableGatewaysRow, error) {
	if err := accessBrowser(a); err != nil {
		return nil, err
	}
	return s.q.ListRequestableGateways(ctx, dbgen.ListRequestableGatewaysParams{ActorID: a.UserID, PageOffset: offset, PageLimit: limit})
}

func accessSettings(ctx context.Context, q *dbgen.Queries, g dbgen.Gateway) (AccessSettings, error) {
	rows, err := q.ListGatewayStewards(ctx, g.ID)
	v := AccessSettings{Enabled: g.AccessRequestsEnabled, Revision: g.Revision, StewardIDs: []uuid.UUID{}}
	for _, row := range rows {
		v.StewardIDs = append(v.StewardIDs, row.ID)
	}
	return v, err
}

func (s *Service) AccessSettings(ctx context.Context, a authz.Actor, id uuid.UUID) (AccessSettings, error) {
	if err := accessBrowser(a); err != nil {
		return AccessSettings{}, err
	}
	u, err := s.q.GetUser(ctx, a.UserID)
	if err != nil {
		return AccessSettings{}, err
	}
	if u.Status != "active" || (u.PlatformRole != authz.PlatformAdmin && u.PlatformRole != authz.PlatformAuditor) {
		return AccessSettings{}, errPlatformRead
	}
	g, err := getGateway(ctx, s.q, id, false)
	if err != nil {
		return AccessSettings{}, err
	}
	if g.OwnerKind != OwnerPlatform {
		return AccessSettings{}, errTeamGateway
	}
	return accessSettings(ctx, s.q, g)
}

func (s *Service) SetAccessSettings(ctx context.Context, a authz.Actor, id uuid.UUID, revision int64, enabled bool, stewards []uuid.UUID) (AccessSettings, error) {
	if len(stewards) > 50 {
		return AccessSettings{}, apperr.Invalid("too_many_stewards", "At most 50 stewards may be named")
	}
	var out AccessSettings
	err := store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		actor, users, err := accessActors(ctx, q, a, stewards...)
		if err != nil {
			return err
		}
		if !actor.IsPlatformAdmin() {
			return errAdminOnly
		}
		seen := map[uuid.UUID]bool{}
		for _, id := range stewards {
			u, ok := users[id]
			if !ok || u.Status != "active" || seen[id] {
				return apperr.Invalid("invalid_stewards", "Name distinct active people as stewards")
			}
			seen[id] = true
		}
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if g.OwnerKind != OwnerPlatform {
			return errTeamGateway
		}
		if g.Revision != revision {
			return apperr.Stale()
		}
		before, err := accessSettings(ctx, q, g)
		if err != nil {
			return err
		}
		if err := q.DeleteGatewayStewards(ctx, id); err != nil {
			return err
		}
		for _, user := range stewards {
			if err := q.InsertGatewaySteward(ctx, dbgen.InsertGatewayStewardParams{GatewayID: id, UserID: user}); err != nil {
				return err
			}
		}
		g, err = q.SetGatewayAccessRequests(ctx, dbgen.SetGatewayAccessRequestsParams{GatewayID: id, Enabled: enabled, ActorID: by(actor)})
		if err != nil {
			return err
		}
		out, err = accessSettings(ctx, q, g)
		if err != nil {
			return err
		}
		e := actor.Audit("gateway.access_settings_update", "gateway", id.String())
		e.Before, e.After = map[string]any{"enabled": before.Enabled, "stewardIds": before.StewardIDs}, map[string]any{"enabled": out.Enabled, "stewardIds": out.StewardIDs}
		return audit.Record(ctx, q, e)
	})
	return out, err
}

func requestActionable(ctx context.Context, q *dbgen.Queries, r dbgen.AccessRequest, actor uuid.UUID) (bool, error) {
	if actor == r.RequesterUserID || r.Status != "pending" {
		return false, nil
	}
	ok, err := q.AccessRequestReviewer(ctx, dbgen.AccessRequestReviewerParams{UserID: actor, GatewayID: r.GatewayID})
	if err != nil || !ok {
		return false, err
	}
	g, err := q.GetGateway(ctx, r.GatewayID)
	if err != nil {
		return false, err
	}
	u, err := q.GetUser(ctx, r.RequesterUserID)
	if err != nil {
		return false, err
	}
	if g.OwnerKind != OwnerPlatform || !g.Enabled || !g.AccessRequestsEnabled || u.Status != "active" {
		return false, nil
	}
	if r.TeamID.Valid {
		t, err := q.GetTeamByID(ctx, r.TeamID.UUID)
		if err != nil {
			return false, err
		}
		m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: u.ID})
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return t.Status == "active" && authz.RoleAtLeast(m.Role, authz.RoleAdmin), nil
	}
	return true, nil
}

func accessView(ctx context.Context, q *dbgen.Queries, a authz.Actor, r dbgen.AccessRequest) (AccessRequest, error) {
	u, err := q.GetUser(ctx, a.UserID)
	if err != nil {
		return AccessRequest{}, err
	}
	allowed := u.Status == "active" && a.UserID == r.RequesterUserID
	if !allowed && u.Status == "active" {
		allowed, err = q.AccessRequestReviewer(ctx, dbgen.AccessRequestReviewerParams{UserID: a.UserID, GatewayID: r.GatewayID})
		if err != nil {
			return AccessRequest{}, err
		}
	}
	if !allowed {
		return AccessRequest{}, errAccessRequest
	}
	g, err := q.GetGateway(ctx, r.GatewayID)
	if err != nil {
		return AccessRequest{}, err
	}
	requester, err := q.GetUser(ctx, r.RequesterUserID)
	if err != nil {
		return AccessRequest{}, err
	}
	out := AccessRequest{ID: r.ID, GatewayID: r.GatewayID, GatewayName: g.Name, RequesterID: r.RequesterUserID,
		RequesterName: requester.DisplayName, SubjectKind: r.SubjectKind, Reason: r.Reason, Status: r.Status,
		CreatedAt: r.CreatedAt, DecidedAt: r.DecidedAt, DecisionNote: r.DecisionNote, GrantExpiresAt: r.GrantExpiresAt}
	if r.GrantID.Valid {
		out.GrantID = &r.GrantID.UUID
	}
	if r.TeamID.Valid {
		t, err := q.GetTeamByID(ctx, r.TeamID.UUID)
		if err != nil {
			return AccessRequest{}, err
		}
		out.TeamID, out.TeamName = &t.ID, t.Name
	}
	out.CanDecide, err = requestActionable(ctx, q, r, a.UserID)
	return out, err
}

func (s *Service) GetAccessRequest(ctx context.Context, a authz.Actor, id uuid.UUID) (AccessRequest, error) {
	if err := accessBrowser(a); err != nil {
		return AccessRequest{}, err
	}
	r, err := s.q.GetAccessRequest(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return AccessRequest{}, errAccessRequest
	}
	if err != nil {
		return AccessRequest{}, err
	}
	return accessView(ctx, s.q, a, r)
}

func (s *Service) AccessRequests(ctx context.Context, a authz.Actor, review, pending bool, offset, limit int32) ([]AccessRequest, int64, error) {
	if err := accessBrowser(a); err != nil {
		return nil, 0, err
	}
	rows, err := s.q.ListAccessRequests(ctx, dbgen.ListAccessRequestsParams{ActorID: a.UserID, Review: review, PendingOnly: pending, PageOffset: offset, PageLimit: limit})
	if err != nil {
		return nil, 0, err
	}
	out := make([]AccessRequest, 0, len(rows))
	for _, r := range rows {
		v, err := accessView(ctx, s.q, a, r)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	n, err := s.q.CountActionableAccessRequests(ctx, a.UserID)
	return out, n, err
}
