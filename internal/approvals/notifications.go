package approvals

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// NotificationRecipients resolves private workflow audiences from live authority.
// q belongs to the dispatcher's transaction: do NOT call s.transaction here (its
// NOWAIT table fence conflicts with the dispatcher's event/team row locks).
// Reads are nonlocking and bracketed by committed context reads; an authority
// edit while resolving, or a stale receipt, suppresses the notice. Notifications
// are hints only; receipt reads and decisions always enforce their own fence.
func (s *Service) NotificationRecipients(ctx context.Context, q *dbgen.Queries, requestID uuid.UUID, requested bool) ([]uuid.UUID, error) {
	epoch, err := q.GetApprovalContext(ctx)
	if err != nil {
		return nil, err
	}
	row, err := q.GetApprovalNotificationRequest(ctx, requestID)
	if noRows(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r := dbgen.ApprovalRequest{ID: row.ID, RuleID: row.RuleID, RuleRevision: row.RuleRevision,
		ContextEpoch: row.ContextEpoch, RequesterKind: row.RequesterKind, RequesterID: row.RequesterID,
		RequesterTeamID: row.RequesterTeamID, GatewayID: row.GatewayID, ServerID: row.ServerID,
		CapabilityID: row.CapabilityID, ExposedName: row.ExposedName, ToolClass: row.ToolClass,
		CapabilityFingerprint: row.CapabilityFingerprint, ServerOrigin: row.ServerOrigin,
		Status: row.Status, ExpiresAt: row.ExpiresAt, ValidUntil: row.ValidUntil}
	if requested {
		if r.Status != Pending || !liveDeadline(r, s.clock()) {
			return nil, nil
		}
	} else if r.Status != Approved && r.Status != Denied {
		return nil, nil
	}
	rule, err := s.currentRequestRule(ctx, q, r, epoch)
	if errors.Is(err, ErrContextChanged) || errors.Is(err, ErrUnavailable) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ids []uuid.UUID
	if requested {
		ids, err = reviewers(ctx, q, *rule, requestBinding(r))
	} else {
		ids, err = q.ApprovalDecisionRecipients(ctx, dbgen.ApprovalDecisionRecipientsParams{
			RequesterKind: r.RequesterKind, RequesterID: r.RequesterID, RequesterTeamID: r.RequesterTeamID})
	}
	if err != nil {
		return nil, err
	}
	current, err := q.GetApprovalContext(ctx)
	if err != nil {
		return nil, err
	}
	if current != epoch {
		return nil, nil
	}
	return ids, nil
}
