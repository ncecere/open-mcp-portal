package mcptasks

import (
	"context"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Observation is only validated upstream task metadata, not arbitrary raw JSON,
// a tool result, input requests or a permission to resume work. Wire parsing is
// prior; storage independently bounds association/timeline/status/lifetime.
type Observation struct {
	ID                    string
	Status                string
	CreatedAt, UpdatedAt  time.Time
	TTLMillis, PollMillis *int64
}

func (o Observation) valid() bool {
	if o.ID == "" || len(o.ID) > MaxUpstreamIDBytes || !utf8.ValidString(o.ID) || o.CreatedAt.IsZero() ||
		o.UpdatedAt.IsZero() || o.UpdatedAt.Before(o.CreatedAt) {
		return false
	}
	switch o.Status {
	case "working", "input_required", "completed", "failed", "cancelled":
		return true
	default:
		return false
	}
}

// Activate atomically persists the actual sealed upstream ID and bounded
// lifetime, commits, THEN returns the portal handle. Failure/ack loss may leave
// upstream work; it never proves cancellation or authorizes a retry/failover.
// The caller must recheck live authority before exposing the returned handle.
func (s *Store) Activate(ctx context.Context, r Reservation, observed Observation) (string, Snapshot, error) {
	fail := func(err error) (string, Snapshot, error) { return "", Snapshot{}, err }
	if s == nil || s.pool == nil || s.box == nil || r.row.ID == uuid.Nil || !observed.valid() {
		return fail(ErrUnavailable)
	}
	handleDigest, err := DigestHandle(r.handle)
	if err != nil || handleDigest != r.row.HandleDigest {
		return fail(ErrNotFound)
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fail(storeError(err))
	}
	defer rollbackTaskTransaction(tx)
	q := dbgen.New(tx)
	row, err := q.GetMCPTaskForUpdate(ctx, r.row.ID)
	if err != nil {
		return fail(storeError(err))
	}
	binding, err := bindingOf(row)
	if err != nil || binding != r.binding || row.Status != "reserved" || row.Revision != r.row.Revision || row.HandleDigest != handleDigest {
		return fail(ErrNotFound)
	}
	belongs, err := q.MCPTaskRootBelongsToPrincipal(ctx, rootParams(rootOf(binding)))
	if err != nil {
		return fail(storeError(err))
	}
	if !belongs {
		return fail(ErrNotFound)
	}
	payload, err := OpenState(s.box, row.ID, handleDigest, binding, row.StateCipher)
	if err != nil || payload.UpstreamID != "" {
		return fail(ErrNotFound)
	}
	now, err := q.MCPTaskClock(ctx)
	if err != nil {
		return fail(storeError(err))
	}
	if observed.UpdatedAt.After(now.Add(5 * time.Minute)) {
		return fail(ErrUnavailable)
	}
	deadline, err := Deadline(now, row.ExpiresAt, observed.CreatedAt, observed.TTLMillis)
	if err != nil {
		return fail(err)
	}
	poll, err := PollInterval(observed.PollMillis)
	if err != nil {
		return fail(err)
	}
	payload.UpstreamID = observed.ID
	cipher, err := SealState(s.box, row.ID, handleDigest, binding, payload)
	if err != nil {
		return fail(ErrUnavailable)
	}
	created, updated := observed.CreatedAt.UTC(), observed.UpdatedAt.UTC()
	row, err = q.ActivateMCPTaskReservation(ctx, dbgen.ActivateMCPTaskReservationParams{
		ID: row.ID, Column2: row.Revision, Status: observed.Status, StateCipher: cipher,
		UpstreamCreatedAt: &created, UpstreamUpdatedAt: &updated, Column7: deadline, PollIntervalMs: int32(poll),
	})
	if err != nil {
		return fail(storeError(err))
	}
	if err := tx.Commit(ctx); err != nil {
		return fail(storeError(err))
	}
	return r.handle, Snapshot{row: row, binding: binding, payload: payload}, nil
}

// Lookup checks the original principal/credential/gateway association and
// sealed row/handle/binding, NOT live policy. A handle does not authenticate.
// Foreign, expired or inconsistent state is uniformly private not-found.
func (s *Store) Lookup(ctx context.Context, handle string, root Root) (Snapshot, error) {
	fail := func(err error) (Snapshot, error) { return Snapshot{}, err }
	if s == nil || s.pool == nil || s.box == nil {
		return fail(ErrUnavailable)
	}
	digest, err := DigestHandle(handle)
	if err != nil || !root.valid() {
		return fail(ErrNotFound)
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	q := dbgen.New(s.pool)
	row, err := q.GetMCPTaskByDigest(ctx, digest)
	if err != nil {
		return fail(storeError(err))
	}
	if rowRoot(row) != root {
		return fail(ErrNotFound)
	}
	binding, err := bindingOf(row)
	if err != nil {
		return fail(ErrNotFound)
	}
	belongs, err := q.MCPTaskRootBelongsToPrincipal(ctx, rootParams(root))
	if err != nil {
		return fail(storeError(err))
	}
	if !belongs {
		return fail(ErrNotFound)
	}
	payload, err := OpenState(s.box, row.ID, digest, binding, row.StateCipher)
	if err != nil || payload.UpstreamID == "" {
		return fail(ErrNotFound)
	}
	now, err := q.MCPTaskClock(ctx)
	if err != nil {
		return fail(storeError(err))
	}
	if !now.Before(row.ExpiresAt) {
		return fail(ErrNotFound)
	}
	return Snapshot{row: row, binding: binding, payload: payload}, nil
}
