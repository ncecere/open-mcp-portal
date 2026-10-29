package mcptasks

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

const (
	storeSQLBudget = 5 * time.Second
	reservationTTL = 5 * time.Minute
)

// Store persists associations, not authority or upstream work. It contains no
// client/transport callback: no SQL lease can escape into upstream network I/O.
type Store struct {
	pool    *pgxpool.Pool
	box     *secrets.Box
	maxTTL  time.Duration
	maxOpen int
}

func NewStore(pool *pgxpool.Pool, box *secrets.Box, maxTTL time.Duration, maxOpen int) (*Store, error) {
	if pool == nil || box == nil || ValidateLimits(maxTTL, maxOpen) != nil {
		return nil, ErrUnavailable
	}
	return &Store{pool: pool, box: box, maxTTL: maxTTL, maxOpen: maxOpen}, nil
}

func rollbackTaskTransaction(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

// Reserve seals the effective original arguments and redaction-only secrets
// before reserving shared principal capacity. It accepts no upstream ID and
// returns no handle; only Activate may expose a committed durable mapping.
// Live policy/credential/offer/deadline checks remain the serving layer's job.
func (s *Store) Reserve(ctx context.Context, binding Binding, payload Payload) (Reservation, error) {
	fail := func(err error) (Reservation, error) { return Reservation{}, err }
	if s == nil || payload.UpstreamID != "" || len(payload.Inputs) != 0 {
		return fail(ErrUnavailable)
	}
	digest, err := DigestBinding(binding)
	if err != nil {
		return fail(ErrUnavailable)
	}
	handle, handleDigest, err := NewHandle()
	if err != nil {
		return fail(ErrUnavailable)
	}
	id, err := uuid.NewRandom()
	if err != nil {
		return fail(ErrUnavailable)
	}
	// Reserve enough encoding space for a maximum-size actual ID, including
	// worst-case JSON escaping and a full input ledger, BEFORE any upstream job
	// can have been created: later transitions can never become unsealable.
	probe := clonePayload(payload)
	probe.UpstreamID = string(make([]byte, MaxUpstreamIDBytes))
	probe.Inputs = worstCaseLedger()
	if _, err := SealState(s.box, id, handleDigest, binding, probe); err != nil {
		return fail(ErrUnavailable)
	}
	cipher, err := SealState(s.box, id, handleDigest, binding, payload)
	if err != nil {
		return fail(ErrUnavailable)
	}
	rawBinding, err := json.Marshal(binding)
	if err != nil || len(rawBinding) > 8192 {
		return fail(ErrUnavailable)
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fail(storeError(err))
	}
	defer rollbackTaskTransaction(tx)
	q := dbgen.New(tx)
	root := rootOf(binding)
	belongs, err := q.MCPTaskRootBelongsToPrincipal(ctx, rootParams(root))
	if err != nil {
		return fail(storeError(err))
	}
	if !belongs {
		return fail(ErrNotFound)
	}
	if err := q.LockMCPTaskPrincipal(ctx, capacityKey(root)); err != nil {
		return fail(storeError(err))
	}
	var open int64
	principal := uuid.NullUUID{UUID: root.PrincipalID, Valid: true}
	if root.PrincipalKind == PrincipalUser {
		open, err = q.CountUserOpenMCPTasks(ctx, principal)
	} else {
		open, err = q.CountServiceAccountOpenMCPTasks(ctx, principal)
	}
	if err != nil {
		return fail(storeError(err))
	}
	if open >= int64(s.maxOpen) {
		return fail(ErrCapacity)
	}
	p := dbgen.InsertMCPTaskReservationParams{ID: id, HandleDigest: handleDigest,
		PrincipalKind: root.PrincipalKind, CredentialKind: root.CredentialKind,
		GatewayID: binding.GatewayID, ServerID: binding.ServerID, CapabilityID: binding.CapabilityID,
		Column13: s.maxTTL.Milliseconds(), Column14: reservationTTL.Milliseconds()}
	if root.PrincipalKind == PrincipalUser {
		p.Column4 = root.PrincipalID
	} else {
		p.Column5 = root.PrincipalID
	}
	switch root.CredentialKind {
	case CredentialAPIKey:
		p.Column7 = root.CredentialID
	case CredentialOAuthGrant:
		p.Column8 = root.CredentialID
	case CredentialServiceKey:
		p.Column9 = root.CredentialID
	}
	row, err := q.InsertMCPTaskReservation(ctx, p)
	if err != nil {
		return fail(storeError(err))
	}
	row, err = q.PrepareMCPTaskReservation(ctx, dbgen.PrepareMCPTaskReservationParams{
		ID: row.ID, Column2: row.Revision, Binding: rawBinding, BindingDigest: &digest, StateCipher: cipher,
	})
	if err != nil {
		return fail(storeError(err))
	}
	if err := tx.Commit(ctx); err != nil {
		return fail(storeError(err))
	}
	return Reservation{row: row, handle: handle, binding: binding}, nil
}

// AbandonReservation releases only a still-reserved matching revision. It is
// NOT cancellation of upstream work, and can never delete an active mapping.
func (s *Store) AbandonReservation(ctx context.Context, r Reservation) error {
	if s == nil || s.pool == nil || r.row.ID == uuid.Nil {
		return ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, storeSQLBudget)
	defer cancel()
	n, err := dbgen.New(s.pool).DeleteMCPTaskReservation(ctx, dbgen.DeleteMCPTaskReservationParams{ID: r.row.ID, Column2: r.row.Revision})
	if err != nil {
		return storeError(err)
	}
	if n != 1 {
		return ErrNotFound
	}
	return nil
}
