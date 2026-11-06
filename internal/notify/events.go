package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/observability"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Event is something that happened, for the dispatcher to tell people about.
type Event struct {
	Type string
	// DedupKey makes emission idempotent: the same key is stored once
	// (at most 200 characters; docs/notifications.md lists each event's).
	DedupKey string
	// TeamID is the team the event belongs to (uuid.Nil: none).
	TeamID uuid.UUID
	// SubjectType and SubjectID name the object (a server, a key).
	SubjectType, SubjectID string
	// Recipient is the person of a personal event.
	Recipient uuid.UUID
	// Actor is the person who caused a manual event: they are not told.
	Actor uuid.UUID
	// Data is the event's payload data: names, counts and times, never
	// secrets, call contents or addresses.
	Data any
}

func nullUUID(id uuid.UUID) uuid.NullUUID { return uuid.NullUUID{UUID: id, Valid: id != uuid.Nil} }

// Emit stores an event in the caller's transaction (q is bound to it), under
// a savepoint, with ON CONFLICT (dedup_key) DO NOTHING. It reports whether
// the event is new. A failure is logged and counted
// (omp_notification_emit_errors_total) and never fails the change it
// reports on: the savepoint rolls back, leaving the caller's transaction
// usable.
func Emit(ctx context.Context, q *dbgen.Queries, ev Event) bool {
	fail := func(reason string, err error) bool {
		observability.NotificationEmitErrors.Inc()
		slog.WarnContext(ctx, "could not emit a notification event", "event", ev.Type, "reason", reason, "err", err)
		return false
	}
	if !ValidEvent(ev.Type) || ev.DedupKey == "" || len(ev.DedupKey) > 200 {
		return fail("invalid_event", nil)
	}
	raw, err := json.Marshal(ev.Data)
	if err != nil {
		return fail("marshal", err)
	}
	if len(raw) > MaxPayload {
		return fail("payload_too_large", nil)
	}
	p := dbgen.InsertNotificationEventParams{Event: ev.Type, DedupKey: ev.DedupKey, TeamID: nullUUID(ev.TeamID), SubjectType: ev.SubjectType,
		SubjectID: ev.SubjectID, RecipientUserID: nullUUID(ev.Recipient), ActorUserID: nullUUID(ev.Actor), Payload: raw}
	var n int64
	if tx, ok := store.TxOf(q); ok {
		sp, err := tx.Begin(ctx) // a savepoint
		if err != nil {
			return fail("savepoint", err)
		}
		if n, err = dbgen.New(sp).InsertNotificationEvent(ctx, p); err != nil {
			_ = sp.Rollback(ctx)
			return fail("insert", err)
		}
		if err := sp.Commit(ctx); err != nil {
			return fail("release", err)
		}
	} else if n, err = q.InsertNotificationEvent(ctx, p); err != nil {
		return fail("insert", err)
	}
	if n > 0 {
		observability.NotificationsEmitted.WithLabelValues(ev.Type).Inc()
	}
	return n > 0
}

// InsertStrict stores an event in the caller's transaction. A duplicate is
// (false, nil); every other failure must abort the caller's transition.
// Unlike Emit it never creates a savepoint or suppresses an insertion error.
func InsertStrict(ctx context.Context, q *dbgen.Queries, ev Event) (bool, error) {
	if !ValidEvent(ev.Type) || ev.DedupKey == "" || len(ev.DedupKey) > 200 {
		return false, fmt.Errorf("invalid notification event")
	}
	raw, err := json.Marshal(ev.Data)
	if err != nil {
		return false, err
	}
	if len(raw) > MaxPayload {
		return false, fmt.Errorf("notification payload too large")
	}
	n, err := q.InsertNotificationEvent(ctx, dbgen.InsertNotificationEventParams{Event: ev.Type, DedupKey: ev.DedupKey, TeamID: nullUUID(ev.TeamID), SubjectType: ev.SubjectType, SubjectID: ev.SubjectID, RecipientUserID: nullUUID(ev.Recipient), ActorUserID: nullUUID(ev.Actor), Payload: raw})
	return n > 0, err
}
