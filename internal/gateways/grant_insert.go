package gateways

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// insertGrant is the common transactional insert/audit path. The caller must
// lock the platform gateway and validate its actual authority and subject.
// Access-request decisions use the real steward actor, never an invented admin.
// Expired rows may be replaced, but active grants are NEVER widened/extended.
func insertGrant(ctx context.Context, q *dbgen.Queries, a authz.Actor, g dbgen.Gateway, p dbgen.InsertGatewayGrantParams, subject string) (dbgen.GatewayGrant, error) {
	if g.OwnerKind != OwnerPlatform || p.GatewayID != g.ID {
		return dbgen.GatewayGrant{}, errTeamGateway
	}
	expired, err := q.DeleteExpiredSubjectGrant(ctx, dbgen.DeleteExpiredSubjectGrantParams{
		GatewayID: p.GatewayID, SubjectKind: p.SubjectKind, TeamID: p.TeamID, UserID: p.UserID, GroupName: p.GroupName,
	})
	if err != nil {
		return dbgen.GatewayGrant{}, err
	}
	for _, row := range expired {
		if err := audit.Record(ctx, q, audit.Entry{ActorKind: audit.ActorSystem, Action: "gateway.grant_expire", TargetType: "gateway_grant", TargetID: row.ID.String(),
			Metadata: map[string]any{"gatewayId": g.ID.String(), "expiresAt": row.ExpiresAt}}); err != nil {
			return dbgen.GatewayGrant{}, err
		}
	}
	row, err := q.InsertGatewayGrant(ctx, p)
	if apperr.IsUniqueViolation(err, "") {
		return row, errGrantExists
	} else if err != nil {
		return row, err
	}
	e := a.Audit("gateway.grant_add", "gateway_grant", row.ID.String())
	e.After = map[string]any{"subjectKind": row.SubjectKind, "subject": subject, "toolScope": toolscope.Stored(row.ToolScope), "expiresAt": row.ExpiresAt}
	e.Metadata = map[string]any{"name": g.Name + " · " + subject, "gatewayId": g.ID.String(), "gatewayName": g.Name}
	return row, audit.Record(ctx, q, e)
}
