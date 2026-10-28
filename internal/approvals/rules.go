package approvals

import (
	"context"
	"net/http"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/audit"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func pagination(offset, limit int32) error {
	if offset < 0 || limit < 1 || limit > 200 {
		return apperr.Invalid("invalid_pagination", "Use a nonnegative offset and a limit from 1 to 200")
	}
	return nil
}
func ruleRevision(actual, expected int64) error {
	if expected < 1 {
		return apperr.New(http.StatusPreconditionRequired, "revision_required", "The rule revision is required")
	}
	if actual != expected {
		return apperr.Stale()
	}
	return nil
}
func ruleScope(ctx context.Context, q *dbgen.Queries, a authz.Actor, ref string, write bool) (uuid.NullUUID, error) {
	if ref == "" {
		if (write && !a.IsPlatformAdmin()) || (!write && !a.CanReadPlatform()) {
			return uuid.NullUUID{}, apperr.Forbidden("Platform approval policy requires a platform role")
		}
		return uuid.NullUUID{}, nil
	}
	var t dbgen.Team
	var err error
	if id, e := uuid.Parse(ref); e == nil {
		t, err = q.GetTeamByID(ctx, id)
	} else {
		t, err = q.GetTeamBySlug(ctx, ref)
	}
	if err != nil {
		if noRows(err) {
			return uuid.NullUUID{}, apperr.NotFound("team_not_found", "Team not found")
		}
		return uuid.NullUUID{}, err
	}
	m, err := q.GetMembership(ctx, dbgen.GetMembershipParams{TeamID: t.ID, UserID: a.UserID})
	if err != nil && !noRows(err) {
		return uuid.NullUUID{}, err
	}
	allowed := authz.RoleAtLeast(m.Role, authz.RoleAdmin)
	if !write && a.CanReadPlatform() {
		allowed = true
	}
	if !allowed {
		return uuid.NullUUID{}, apperr.NotFound("team_not_found", "Team not found")
	}
	if write && t.Status != "active" {
		return uuid.NullUUID{}, ErrUnavailable
	}
	return nullable(t.ID), nil
}
func (s *Service) ListRules(ctx context.Context, a authz.Actor, ref string, offset, limit int32) ([]Rule, error) {
	out := []Rule{}
	err := s.transaction(ctx, &a, false, func(q *dbgen.Queries, _ int64) error {
		if e := pagination(offset, limit); e != nil {
			return e
		}
		team, e := ruleScope(ctx, q, a, ref, false)
		if e != nil {
			return e
		}
		var rows []dbgen.ApprovalRule
		// The admin list is metadata oversight across the portal. Admin WRITES
		// below remain strictly limited to platform-owned gateways.
		if ref == "" {
			rows, e = q.ListApprovalRules(ctx, dbgen.ListApprovalRulesParams{PageOffset: offset, PageLimit: limit})
		} else {
			rows, e = q.ApprovalRulesForScope(ctx, dbgen.ApprovalRulesForScopeParams{TeamID: team, PageOffset: offset, PageLimit: limit})
		}
		if e != nil {
			return e
		}
		for _, row := range rows {
			r, e := loadRule(ctx, q, row)
			if e != nil {
				return e
			}
			out = append(out, r)
		}
		return nil
	})
	return out, err
}
func validateRuleTarget(ctx context.Context, q *dbgen.Queries, team uuid.NullUUID, in RuleInput) error {
	target, err := q.ApprovalTarget(ctx, dbgen.ApprovalTargetParams{TargetID: in.TargetID, TargetKind: in.TargetKind})
	if err != nil {
		if noRows(err) {
			return missingRule()
		}
		return err
	}
	if team.Valid {
		if target.TeamID != team.UUID {
			return missingRule()
		}
	} else if in.TargetKind != "gateway" || target.TeamID != uuid.Nil {
		return missingRule()
	}
	if in.CapabilityID != nil {
		ok, e := q.ApprovalCapabilityBelongs(ctx, dbgen.ApprovalCapabilityBelongsParams{TargetID: in.TargetID, TargetKind: in.TargetKind, CapabilityID: *in.CapabilityID})
		if e != nil {
			return e
		}
		if !ok {
			return missingRule()
		}
	}
	for _, a := range in.Approvers {
		if a.UserID != nil {
			u, e := q.GetUser(ctx, *a.UserID)
			if e != nil && !noRows(e) {
				return e
			}
			if e != nil || u.Status != "active" {
				return apperr.New(422, "invalid_approval_rule", "Named approvers must be active humans")
			}
		}
	}
	return nil
}
func ensureNoOverlap(ctx context.Context, q *dbgen.Queries, id uuid.UUID, in RuleInput) error {
	rows, err := q.ApprovalRulesForTarget(ctx, dbgen.ApprovalRulesForTargetParams{TargetKind: in.TargetKind, TargetID: in.TargetID})
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ID == id {
			continue
		}
		other, e := loadRule(ctx, q, row)
		if e != nil {
			return e
		}
		if RulesOverlap(in, other.RuleInput) {
			return ErrUnavailable
		}
	}
	return nil
}
func replaceApprovers(ctx context.Context, q *dbgen.Queries, id uuid.UUID, selectors []Selector) error {
	if err := q.DeleteApprovalRuleApprovers(ctx, id); err != nil {
		return err
	}
	for _, a := range selectors {
		if err := q.InsertApprovalRuleApprover(ctx, dbgen.InsertApprovalRuleApproverParams{RuleID: id, Kind: a.Kind, UserID: optional(a.UserID), GroupName: a.GroupName}); err != nil {
			return err
		}
	}
	return nil
}
func ruleAudit(ctx context.Context, q *dbgen.Queries, a authz.Actor, action string, before *Rule, after *Rule) error {
	r := after
	if r == nil {
		r = before
	}
	e := a.Audit("approval_rule."+action, "approval_rule", r.ID.String())
	if r.TeamID != nil {
		e.TeamID = *r.TeamID
	}
	if before != nil {
		e.Before = *before
	}
	if after != nil {
		e.After = *after
	}
	return audit.Record(ctx, q, e)
}
func (s *Service) CreateRule(ctx context.Context, a authz.Actor, ref string, input RuleInput) (Rule, error) {
	var out Rule
	err := s.transaction(ctx, &a, true, func(q *dbgen.Queries, _ int64) error {
		team, e := ruleScope(ctx, q, a, ref, true)
		if e != nil {
			return e
		}
		in, e := NormalizeRule(input)
		if e != nil {
			return e
		}
		if e = validateRuleTarget(ctx, q, team, in); e != nil {
			return e
		}
		if e = ensureNoOverlap(ctx, q, uuid.Nil, in); e != nil {
			return e
		}
		row, e := q.InsertApprovalRule(ctx, dbgen.InsertApprovalRuleParams{ID: uuid.New(), Name: in.Name, TeamID: team, TargetKind: in.TargetKind, TargetID: in.TargetID, CapabilityID: optional(in.CapabilityID), Classes: in.Classes, Enabled: in.Enabled, PendingMinutes: in.PendingMinutes, ValidMinutes: in.ValidMinutes, AllowServiceAccountAdmins: in.AllowServiceAccountAdmins, CreatedBy: a.UserID})
		if e != nil {
			return e
		}
		if e = replaceApprovers(ctx, q, row.ID, in.Approvers); e != nil {
			return e
		}
		out, e = loadRule(ctx, q, row)
		if e != nil {
			return e
		}
		return ruleAudit(ctx, q, a, "created", nil, &out)
	})
	if err != nil {
		return Rule{}, err
	}
	return out, nil
}
func (s *Service) ReplaceRule(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, revision int64, input RuleInput) (Rule, error) {
	var out Rule
	err := s.transaction(ctx, &a, true, func(q *dbgen.Queries, _ int64) error {
		team, e := ruleScope(ctx, q, a, ref, true)
		if e != nil {
			return e
		}
		row, e := q.LockApprovalRule(ctx, id)
		if e != nil {
			if noRows(e) {
				return missingRule()
			}
			return e
		}
		if row.TeamID != team {
			return missingRule()
		}
		before, e := loadRule(ctx, q, row)
		if e != nil {
			return e
		}
		if e = ruleRevision(row.Revision, revision); e != nil {
			return e
		}
		in, e := NormalizeRule(input)
		if e != nil {
			return e
		}
		if in.TargetKind != row.TargetKind || in.TargetID != row.TargetID {
			return missingRule()
		}
		if e = validateRuleTarget(ctx, q, team, in); e != nil {
			return e
		}
		if e = ensureNoOverlap(ctx, q, id, in); e != nil {
			return e
		}
		row, e = q.UpdateApprovalRule(ctx, dbgen.UpdateApprovalRuleParams{ID: id, ExpectedRevision: revision, Name: in.Name, CapabilityID: optional(in.CapabilityID), Classes: in.Classes, Enabled: in.Enabled, PendingMinutes: in.PendingMinutes, ValidMinutes: in.ValidMinutes, AllowServiceAccountAdmins: in.AllowServiceAccountAdmins})
		if e != nil {
			return e
		}
		if e = replaceApprovers(ctx, q, id, in.Approvers); e != nil {
			return e
		}
		out, e = loadRule(ctx, q, row)
		if e != nil {
			return e
		}
		return ruleAudit(ctx, q, a, "replaced", &before, &out)
	})
	if err != nil {
		return Rule{}, err
	}
	return out, nil
}
func (s *Service) DeleteRule(ctx context.Context, a authz.Actor, ref string, id uuid.UUID, revision int64) error {
	return s.transaction(ctx, &a, true, func(q *dbgen.Queries, _ int64) error {
		team, e := ruleScope(ctx, q, a, ref, true)
		if e != nil {
			return e
		}
		row, e := q.LockApprovalRule(ctx, id)
		if e != nil {
			if noRows(e) {
				return missingRule()
			}
			return e
		}
		if row.TeamID != team {
			return missingRule()
		}
		before, e := loadRule(ctx, q, row)
		if e != nil {
			return e
		}
		if e = ruleRevision(row.Revision, revision); e != nil {
			return e
		}
		n, e := q.DeleteApprovalRule(ctx, dbgen.DeleteApprovalRuleParams{ID: id, Revision: revision})
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrUnavailable
		}
		return ruleAudit(ctx, q, a, "deleted", &before, nil)
	})
}
