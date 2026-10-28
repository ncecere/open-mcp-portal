package approvals

import (
	"context"

	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/toolscope"
)

// Recheck the requester, not their creator/operator. All of these reads are
// nonlocking under the epoch fence. The runtime has separately established the
// current MCP credential/key/grant ceiling and supplies its absolute deadline;
// the original epoch proves those mutable credential scopes did not change.
func requesterGatewayAccess(ctx context.Context, q *dbgen.Queries, b Binding) (bool, error) {
	g, err := q.GetGateway(ctx, b.GatewayID)
	if err != nil {
		if noRows(err) {
			return false, nil
		}
		return false, err
	}
	minimum, err := q.ApprovalSelectionRole(ctx, dbgen.ApprovalSelectionRoleParams{GatewayID: b.GatewayID, CapabilityID: b.CapabilityID, ExposedName: &b.ExposedName, ToolClass: b.ToolClass})
	if err != nil {
		if noRows(err) {
			return false, nil
		}
		return false, err
	}
	var role string
	var grants []dbgen.GatewayGrant
	switch b.RequesterKind {
	case "user":
		u, e := q.GetUser(ctx, b.RequesterID)
		if e != nil {
			return false, e
		}
		if g.OwnerKind == "team" {
			m, e := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: g.TeamID.UUID, UserID: u.ID})
			if noRows(e) {
				return false, nil
			}
			if e != nil {
				return false, e
			}
			role = m.Role
		} else {
			grants, err = q.GatewayGrantsForUser(ctx, dbgen.GatewayGrantsForUserParams{GatewayID: g.ID, UserID: nullable(u.ID), Groups: u.Groups})
		}
	case "service_account":
		if b.RequesterTeamID == nil {
			return false, nil
		}
		row, e := q.GetServiceAccountView(ctx, dbgen.GetServiceAccountViewParams{ID: b.RequesterID, TeamID: *b.RequesterTeamID})
		if e != nil {
			if noRows(e) {
				return false, nil
			}
			return false, e
		}
		account := row.ServiceAccount
		if !toolscope.Allows(toolscope.Stored(account.ToolScope), toolscope.Class(b.ToolClass), b.ExposedName) {
			return false, nil
		}
		if g.OwnerKind == "team" {
			if g.TeamID.UUID != account.TeamID {
				return false, nil
			}
			role = account.Role
		} else {
			grants, err = q.GatewayGrantsForTeam(ctx, dbgen.GatewayGrantsForTeamParams{GatewayID: g.ID, TeamID: nullable(account.TeamID)})
		}
	default:
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if g.OwnerKind == "team" {
		return authz.MinRoleAllows(role, minimum), nil
	}
	scopes := make([]*toolscope.Scope, 0, len(grants))
	for _, grant := range grants {
		scopes = append(scopes, toolscope.Stored(grant.ToolScope))
	}
	return len(grants) > 0 && toolscope.Union(scopes...).Allows(toolscope.Class(b.ToolClass), b.ExposedName), nil
}
