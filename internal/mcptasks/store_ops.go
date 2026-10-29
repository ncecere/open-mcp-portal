package mcptasks

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// ErrBusy means another operation holds the task, the snapshot is stale or
// the poll interval has not elapsed. Nothing was sent; a caller may answer a
// get from the snapshot's last known (non-terminal) status without a result.
var ErrBusy = errors.New("Task is busy")

const (
	MinOperationTimeout = time.Second
	MaxOperationTimeout = 5 * time.Minute
)

func terminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

// Operation is a short persisted claim on one task exchange: NOT a database
// lease, lock or authorization. It is fenced by a random UUID and the row
// revision; a stale or expired claim cannot commit state.
type Operation struct {
	snap Snapshot
	id   uuid.UUID
}

func (o Operation) Snapshot() Snapshot { return o.snap }
func (Operation) String() string       { return "private task operation" }
func (Operation) GoString() string     { return "private task operation" }

// Begin claims the task for one upstream exchange. poll=true applies the
// stored poll interval to unfinished tasks. The caller must already have
// re-resolved current authority for the snapshot's binding.
func (s *Store) Begin(ctx context.Context, snap Snapshot, poll bool, timeout time.Duration) (Operation, error) {
	if s == nil || s.pool == nil || snap.row.ID == uuid.Nil || timeout < MinOperationTimeout || timeout > MaxOperationTimeout {
		return Operation{}, ErrUnavailable
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return Operation{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	row, err := dbgen.New(s.pool).AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{
		ID: snap.row.ID, Column2: snap.row.Revision, OperationID: uuid.NullUUID{UUID: id, Valid: true},
		Column4: timeout.Milliseconds(), Column5: poll,
	})
	if err != nil {
		if err = storeError(err); errors.Is(err, ErrNotFound) {
			return Operation{}, ErrBusy
		}
		return Operation{}, err
	}
	next := snap
	next.row = row
	return Operation{snap: next, id: id}, nil
}

func (s *Store) reseal(op Operation, p Payload) ([]byte, error) {
	return SealState(s.box, op.snap.row.ID, op.snap.row.HandleDigest, op.snap.binding, p)
}

// CommitInput consumes the client's responses BEFORE the single update send.
// count==0: nothing may be forwarded (the operation remains claimed; Release
// it). The returned body is keyed by the server's private keys.
func (s *Store) CommitInput(ctx context.Context, op Operation, responses json.RawMessage) (Operation, json.RawMessage, int, error) {
	fail := func(err error) (Operation, json.RawMessage, int, error) { return Operation{}, nil, 0, err }
	if s == nil || s.pool == nil || op.id == uuid.Nil {
		return fail(ErrUnavailable)
	}
	p := clonePayload(op.snap.payload)
	ledger, serverBody, n, err := SelectInputResponses(p.Inputs, responses)
	if err != nil {
		return fail(err)
	}
	if n == 0 {
		return op, nil, 0, nil
	}
	p.Inputs = ledger
	cipher, err := s.reseal(op, p)
	if err != nil {
		return fail(ErrUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	row, err := dbgen.New(s.pool).CommitMCPTaskInputState(ctx, dbgen.CommitMCPTaskInputStateParams{
		ID: op.snap.row.ID, Column2: op.snap.row.Revision, OperationID: uuid.NullUUID{UUID: op.id, Valid: true}, StateCipher: cipher,
	})
	if err != nil {
		if err = storeError(err); errors.Is(err, ErrNotFound) {
			return fail(ErrBusy)
		}
		return fail(err)
	}
	op.snap.row, op.snap.payload = row, p
	return op, serverBody, n, nil
}

// Finish records a validated tasks/get observation and releases the claim.
// The observed ID and creation time must match the stored mapping; terminal
// state is sticky; lifetime only shrinks. inputRequests (input_required only)
// is rewritten to portal keys. A fenced/stale claim returns ErrBusy and
// commits nothing — the caller must not reveal the observation's payload then.
func (s *Store) Finish(ctx context.Context, op Operation, observed Observation, inputRequests json.RawMessage) (Snapshot, json.RawMessage, error) {
	fail := func(err error) (Snapshot, json.RawMessage, error) { return Snapshot{}, nil, err }
	if s == nil || s.pool == nil || op.id == uuid.Nil || !observed.valid() {
		return fail(ErrUnavailable)
	}
	row, p := op.snap.row, clonePayload(op.snap.payload)
	if observed.ID != p.UpstreamID || row.UpstreamCreatedAt == nil || !observed.CreatedAt.Equal(*row.UpstreamCreatedAt) {
		return fail(ErrUnavailable)
	}
	if terminal(row.Status) && observed.Status != row.Status {
		return fail(ErrUnavailable)
	}
	var portalRequests json.RawMessage
	if observed.Status == "input_required" {
		ledger, mapped, err := MapInputRequests(p.Inputs, inputRequests, randomReader)
		if err != nil {
			return fail(err)
		}
		p.Inputs, portalRequests = ledger, mapped
	} else if len(inputRequests) != 0 {
		return fail(ErrUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	q := dbgen.New(s.pool)
	now, err := q.MCPTaskClock(ctx)
	if err != nil {
		return fail(storeError(err))
	}
	if observed.UpdatedAt.After(now.Add(5 * time.Minute)) {
		return fail(ErrUnavailable)
	}
	deadline, err := Deadline(now, row.ExpiresAt, *row.UpstreamCreatedAt, observed.TTLMillis)
	if err != nil {
		return fail(err)
	}
	poll, err := PollInterval(observed.PollMillis)
	if err != nil {
		return fail(err)
	}
	cipher, err := s.reseal(op, p)
	if err != nil {
		return fail(ErrUnavailable)
	}
	updated := observed.UpdatedAt.UTC()
	if row.UpstreamUpdatedAt != nil && updated.Before(*row.UpstreamUpdatedAt) {
		updated = *row.UpstreamUpdatedAt // eventual consistency never rewinds the timeline
	}
	row, err = q.FinishMCPTaskOperation(ctx, dbgen.FinishMCPTaskOperationParams{
		ID: row.ID, Column2: row.Revision, OperationID: uuid.NullUUID{UUID: op.id, Valid: true},
		Status: observed.Status, StateCipher: cipher, UpstreamUpdatedAt: &updated, Column7: deadline, PollIntervalMs: int32(poll),
	})
	if err != nil {
		if err = storeError(err); errors.Is(err, ErrNotFound) {
			return fail(ErrBusy)
		}
		return fail(err)
	}
	return Snapshot{row: row, binding: op.snap.binding, payload: p}, portalRequests, nil
}

// Release ends a claim without changing task status (update/cancel acks,
// failed or ambiguous sends). Committed input attempts are NOT restored.
func (s *Store) Release(ctx context.Context, op Operation) error {
	if s == nil || s.pool == nil || op.id == uuid.Nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), storeSQLBudget)
	defer cancel()
	n, err := dbgen.New(s.pool).ReleaseMCPTaskOperation(ctx, dbgen.ReleaseMCPTaskOperationParams{
		ID: op.snap.row.ID, Column2: op.snap.row.Revision, OperationID: uuid.NullUUID{UUID: op.id, Valid: true},
	})
	if err != nil {
		return storeError(err)
	}
	if n != 1 {
		return ErrBusy
	}
	return nil
}
