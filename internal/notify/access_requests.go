package notify

import (
	"context"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// accessNotificationData is deliberately not the access-request projection.
// No reasons, decision notes, names, emails or grant scope enter the outbox.
type accessNotificationData struct {
	RequestID uuid.UUID `json:"accessRequestId"`
	Status    string    `json:"status"`
}

func AccessNotice(ctx context.Context, q *dbgen.Queries, r dbgen.AccessRequest, requested bool) {
	if r.ID == uuid.Nil || (requested && r.Status != "pending") || (!requested && r.Status != "approved" && r.Status != "denied") {
		return
	}
	event := AccessDecided
	if requested {
		event = AccessRequested
	}
	Emit(ctx, q, Event{Type: event, DedupKey: event + ":" + r.ID.String(), SubjectType: "access_request", SubjectID: r.ID.String(),
		Data: accessNotificationData{RequestID: r.ID, Status: r.Status}})
}

func isAccessEvent(event string) bool { return event == AccessRequested || event == AccessDecided }

func (s *Service) accessRecipients(ctx context.Context, q *dbgen.Queries, ev dbgen.NotificationEvent) ([]recipient, error) {
	if ev.SubjectType != "access_request" {
		return nil, nil
	}
	id, err := uuid.Parse(ev.SubjectID)
	if err != nil || id == uuid.Nil {
		return nil, nil
	}
	ids, err := q.AccessRequestRecipients(ctx, dbgen.AccessRequestRecipientsParams{RequestID: id, Requested: ev.Event == AccessRequested})
	if err != nil {
		return nil, err
	}
	out := make([]recipient, 0, len(ids))
	for _, id := range ids {
		u, err := q.GetActiveRecipient(ctx, id)
		if err != nil {
			if err := ignoreNoRows(err); err != nil {
				return nil, err
			}
			continue
		}
		out = append(out, recipient{ID: u.ID, Email: u.Email, DisplayName: u.DisplayName, Verified: u.EmailVerified})
	}
	return out, nil
}
