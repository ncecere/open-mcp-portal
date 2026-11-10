package gateways

import (
	"context"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/teams"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// Grants lists a platform gateway's grants (platform admins and auditors);
// a team gateway has none.
func (s *Service) Grants(ctx context.Context, a authz.Actor, id uuid.UUID) ([]dbgen.ListGatewayGrantsRow, error) {
	if !a.CanReadPlatform() {
		return nil, errPlatformRead
	}
	if _, err := getGateway(ctx, s.q, id, false); err != nil {
		return nil, err
	}
	return s.q.ListGatewayGrants(ctx, id)
}

// GrantInput names a grant's subject: exactly one of Team (slug or ID),
// UserEmail or Group, matching Kind.
type GrantInput struct {
	ToolScope              []byte
	Kind                   string
	Team, UserEmail, Group *string
	ExpiresInDays          *int32
}

func validGroup(g string) bool {
	return g != "" && len(g) <= 256 && utf8.ValidString(g) && strings.IndexFunc(g, unicode.IsControl) < 0
}

// AddGrant grants a platform gateway to a team, a person or an SSO group
// (platform admins). Audited as gateway.grant_add.
func (s *Service) AddGrant(ctx context.Context, a authz.Actor, id uuid.UUID, in GrantInput) (dbgen.ListGatewayGrantsRow, error) {
	if !a.IsPlatformAdmin() {
		return dbgen.ListGatewayGrantsRow{}, errAdminOnly
	}
	toolScope, err := toolscope.Canonical(in.ToolScope)
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	set := 0
	for _, p := range []*string{in.Team, in.UserEmail, in.Group} {
		if p != nil {
			set++
		}
	}
	if set != 1 {
		return dbgen.ListGatewayGrantsRow{}, errInvalidGrant
	}
	var grantID uuid.UUID
	err = store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		if g.OwnerKind != OwnerPlatform {
			return errTeamGateway
		}
		expires, err := grantExpiry(ctx, q, in.ExpiresInDays)
		if err != nil {
			return err
		}
		p := dbgen.InsertGatewayGrantParams{GatewayID: g.ID, SubjectKind: in.Kind, AddedBy: by(a), ToolScope: toolScope, ExpiresAt: expires}
		subject := ""
		switch {
		case in.Kind == SubjectTeam && in.Team != nil:
			t, err := teams.Resolve(ctx, q, strings.TrimSpace(*in.Team))
			if e, ok := apperr.As(err); ok && e.Status == 404 {
				return errSubjectNotFound
			} else if err != nil {
				return err
			}
			p.TeamID, subject = uuid.NullUUID{UUID: t.ID, Valid: true}, t.Slug
		case in.Kind == SubjectUser && in.UserEmail != nil:
			email, err := teams.NormalizeEmail(*in.UserEmail)
			if err != nil {
				return err
			}
			users, err := q.ListUsersByEmail(ctx, email)
			if err != nil {
				return err
			}
			if len(users) == 0 {
				return errSubjectNotFound
			}
			p.UserID, subject = uuid.NullUUID{UUID: users[0].ID, Valid: true}, email
		case in.Kind == SubjectGroup && in.Group != nil:
			group := strings.TrimSpace(*in.Group)
			if !validGroup(group) {
				return apperr.Invalid("invalid_group", "The group must be 1-256 characters on one line")
			}
			p.GroupName, subject = &group, group
		default:
			return errInvalidGrant
		}
		row, err := insertGrant(ctx, q, a, g, p, subject)
		grantID = row.ID
		return err
	})
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	rows, err := s.q.ListGatewayGrants(ctx, id)
	if err != nil {
		return dbgen.ListGatewayGrantsRow{}, err
	}
	i := slices.IndexFunc(rows, func(r dbgen.ListGatewayGrantsRow) bool { return r.GatewayGrant.ID == grantID })
	if i < 0 {
		return dbgen.ListGatewayGrantsRow{}, errNoGrant
	}
	return rows[i], nil
}

// RemoveGrant removes a grant (platform admins); the next call is refused.
// Audited as gateway.grant_remove.
func (s *Service) RemoveGrant(ctx context.Context, a authz.Actor, id, grantID uuid.UUID) error {
	if !a.IsPlatformAdmin() {
		return errAdminOnly
	}
	return store.InTx(ctx, s.pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		g, err := getGateway(ctx, q, id, true)
		if err != nil {
			return err
		}
		row, err := q.DeleteGatewayGrant(ctx, dbgen.DeleteGatewayGrantParams{ID: grantID, GatewayID: g.ID})
		if errors.Is(store.NotFound(err), store.ErrNotFound) {
			return errNoGrant
		} else if err != nil {
			return err
		}
		subject, err := grantSubject(ctx, q, row)
		if err != nil {
			return err
		}
		e := a.Audit("gateway.grant_remove", "gateway_grant", row.ID.String())
		e.Before = map[string]any{"subjectKind": row.SubjectKind, "subject": subject, "toolScope": toolscope.Stored(row.ToolScope), "expiresAt": row.ExpiresAt}
		e.Metadata = map[string]any{"name": g.Name + " · " + subject, "gatewayId": g.ID.String(), "gatewayName": g.Name}
		return audit.Record(ctx, q, e)
	})
}

// grantSubject names a grant's subject as audited: a team's slug, a
// person's email or the group.
func grantSubject(ctx context.Context, q *dbgen.Queries, g dbgen.GatewayGrant) (string, error) {
	switch {
	case g.TeamID.Valid:
		t, err := q.GetTeamByID(ctx, g.TeamID.UUID)
		if err != nil {
			return "", err
		}
		return t.Slug, nil
	case g.UserID.Valid:
		u, err := q.GetUser(ctx, g.UserID.UUID)
		if err != nil {
			return "", err
		}
		return u.Email, nil
	case g.GroupName != nil:
		return *g.GroupName, nil
	}
	return "", nil
}
