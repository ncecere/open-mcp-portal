package notify

import (
	"context"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// approvalNotificationData is an explicit allowlist, NOT a serialized receipt.
// Previews, digests, arguments, notes, credentials and origin URLs must never
// enter the notification event, inbox, email or outbox.
type approvalNotificationData struct {
	ApprovalID  uuid.UUID `json:"approvalId"`
	ExposedName string    `json:"exposedName"`
	Status      string    `json:"status"`
}

// ApprovalNotice is the approvals.Service.EmitNotice callback. Emit uses the
// caller's registered transaction savepoint: a broken best-effort outbox cannot
// roll back the approval transition or its audit. Each renewal has a new ID;
// ordinary binding dedup does not call this hook.
func ApprovalNotice(ctx context.Context, q *dbgen.Queries, r approvals.Receipt, requested bool) {
	if r.ID == uuid.Nil || (requested && r.Status != approvals.Pending) ||
		(!requested && r.Status != approvals.Approved && r.Status != approvals.Denied) {
		return
	}
	event := ApprovalDecided
	if requested {
		event = ApprovalRequested
	}
	Emit(ctx, q, Event{Type: event, DedupKey: event + ":" + r.ID.String(),
		SubjectType: "approval_request", SubjectID: r.ID.String(),
		Data: approvalNotificationData{ApprovalID: r.ID, ExposedName: clip(r.ExposedName, 200), Status: r.Status}})
}

func isApprovalEvent(event string) bool {
	return event == ApprovalRequested || event == ApprovalDecided
}

// approvalRecipients deliberately fails closed when wiring is absent or an
// event is malformed. Neither a static recipient nor platform observer roles
// can bypass the approval service's live audience resolution.
func (s *Service) approvalRecipients(ctx context.Context, q *dbgen.Queries, ev dbgen.NotificationEvent) ([]recipient, error) {
	if s.ApprovalRecipients == nil || ev.SubjectType != "approval_request" {
		return nil, nil
	}
	id, err := uuid.Parse(ev.SubjectID)
	if err != nil || id == uuid.Nil {
		return nil, nil
	}
	ids, err := s.ApprovalRecipients(ctx, q, id, ev.Event == ApprovalRequested)
	if err != nil {
		return nil, err
	}
	out := make([]recipient, 0, len(ids))
	seen := make(map[uuid.UUID]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		u, err := q.GetActiveRecipient(ctx, id)
		if err != nil {
			if err = ignoreNoRows(err); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, recipient{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Verified: u.EmailVerified})
	}
	return out, nil
}
