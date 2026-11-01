package authoritytx

import (
	"context"
	"fmt"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// TryPrelocked tries G without waiting on the exact registered transaction that
// already owns a caller-validated resource prefix. It neither opens a pool
// connection nor begins, commits or rolls back that transaction. The name does
// not prove that the caller locked the correct resources or checked authority.
//
// A false, nil result leaves the transaction usable and does not call fn or
// alter its lock timeout. A caller may then perform only its separately proved,
// exact-existing-row nonpublication completion, or roll back. This is never
// permission to insert, reconnect, reactivate, rebind or publish credentials.
//
// A true result means ONLY that this transaction acquired G. fn must validate
// original admission/standing/lifetime/session/resource bindings. G remains held
// until the OWNER commits or rolls back, even after this function returns. The
// owner must return any error to roll back, perform no subsequent network I/O,
// and publish nothing unless its own commit succeeds. This borrowed entry does
// not provide Run's commit-confirmed result guarantee. Do not treat its boolean
// as an authentication result or a dispatch permit.
//
// Bounds cover this final DB-only phase; the original prelock/provider phase
// needs its own bounded context. They never extend an existing deadline. A
// nested gated entry is rejected; helpers must reuse the supplied scope.
func TryPrelocked(ctx context.Context, q *dbgen.Queries, mode Mode, bounds Bounds, fn func(context.Context, *Scope) error) (bool, error) {
	if q == nil || fn == nil || (mode != Shared && mode != Exclusive) || bounds.Total <= 0 || bounds.LockWait <= 0 || bounds.LockWait > bounds.Total {
		return false, ErrInvalid
	}
	if ctx.Value(contextKey{}) != nil {
		return false, ErrNested
	}
	tx, ok := store.TxOf(q)
	if !ok {
		return false, ErrUnregistered
	}
	ctx, cancel := context.WithTimeout(ctx, bounds.Total)
	defer cancel()
	statement := "SELECT pg_try_advisory_xact_lock_shared($1)"
	if mode == Exclusive {
		statement = "SELECT pg_try_advisory_xact_lock($1)"
	}
	var acquired bool
	if err := tx.QueryRow(ctx, statement, gateKey).Scan(&acquired); err != nil {
		return false, fmt.Errorf("try authority gate: %w", err)
	}
	if !acquired {
		return false, ctx.Err()
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", lockWaitText(bounds.LockWait)); err != nil {
		return true, fmt.Errorf("set prelocked authority lock wait: %w", err)
	}
	scope := &Scope{q: q, mode: mode}
	scopedCtx := context.WithValue(ctx, contextKey{}, scope)
	scope.ctx = scopedCtx
	defer scope.closed.Store(true)
	if err := fn(scopedCtx, scope); err != nil {
		return true, err
	}
	return true, ctx.Err()
}
