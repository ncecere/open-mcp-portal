// Package authoritytx provides the transaction-scoped global authority gate.
//
// This is an unwired primitive for the SCIM lifecycle implementation. Holding a
// gate is NOT authentication, standing, request-epoch, session, lifetime, group,
// resource or publication validation. Callers must supply those checks. No
// caller may perform network I/O while holding a scope. This package neither
// enables directory enforcement nor advertises SCIM support.
package authoritytx

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// Mode is selected at entry, never upgraded inside a resource transaction.
type Mode uint8

const (
	Shared Mode = iota + 1
	Exclusive
)

// gateKey is the fixed, portal-wide OMP_AUTH advisory-lock namespace.
// Every authority entry must use this same key and transaction-scoped locks.
const gateKey int64 = 0x4f4d505f41555448

var (
	ErrInvalid      = errors.New("invalid authority transaction options")
	ErrNested       = errors.New("authority transaction already present: use its scoped helpers")
	ErrClosed       = errors.New("authority transaction scope ended")
	ErrUnregistered = errors.New("authority prelock entry requires registered transaction queries")
)

// Bounds are one total DB-only deadline and a per-lock wait bound. Values are
// supplied explicitly: this primitive does not choose an enforcement policy or
// reset a deadline at a nested helper. It does not change test-suite budgets.
type Bounds struct {
	Total    time.Duration
	LockWait time.Duration
}

// Scope contains queries registered to the actual transaction, not a pool.
// It must not escape the callback or be used by another goroutine. Queries is
// checked against scope/context lifetime; retaining its raw result is not an
// independent authorization capability.
type Scope struct {
	q      *dbgen.Queries
	mode   Mode
	ctx    context.Context
	closed atomic.Bool
}

type contextKey struct{}

// Mode returns the mode selected for this transaction. It confers no standing.
func (s *Scope) Mode() Mode { return s.mode }

// Queries returns the registered transaction queries while the scope is live.
func (s *Scope) Queries() (*dbgen.Queries, error) {
	if s == nil || s.closed.Load() {
		return nil, ErrClosed
	}
	if err := s.ctx.Err(); err != nil {
		return nil, err
	}
	return s.q, nil
}

// Run performs one transaction and releases no result until commit succeeds.
// Callback, cancellation and uncertain-commit errors return T's zero value;
// none is retried. Nested public entries are rejected before pool acquisition:
// internal helpers must receive the existing scope instead of reopening a pool.
//
// Run is the canonical gate-before-resources entry only. It must NOT wrap a
// connection wait, refresh HTTP exchange, or an existing prelocked transaction.
// Existing-row paths use TryPrelocked in their registered owning transaction;
// neither entry supplies eligibility or publication validation.
func Run[T any](ctx context.Context, pool *pgxpool.Pool, mode Mode, bounds Bounds, fn func(context.Context, *Scope) (T, error)) (T, error) {
	var zero T
	if pool == nil || fn == nil || (mode != Shared && mode != Exclusive) || bounds.Total <= 0 || bounds.LockWait <= 0 || bounds.LockWait > bounds.Total {
		return zero, ErrInvalid
	}
	if ctx.Value(contextKey{}) != nil {
		return zero, ErrNested
	}
	ctx, cancel := context.WithTimeout(ctx, bounds.Total)
	defer cancel()
	var out T
	err := store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		// Set before G as well as before resource locks: the total context is
		// not reset, and gate admission itself must not wait indefinitely.
		if _, err := tx.Exec(ctx, "SELECT set_config('lock_timeout', $1, true)", lockWaitText(bounds.LockWait)); err != nil {
			return fmt.Errorf("set authority lock wait: %w", err)
		}
		statement := "SELECT pg_advisory_xact_lock_shared($1)"
		if mode == Exclusive {
			statement = "SELECT pg_advisory_xact_lock($1)"
		}
		if _, err := tx.Exec(ctx, statement, gateKey); err != nil {
			return fmt.Errorf("acquire authority gate: %w", err)
		}
		scope := &Scope{q: q, mode: mode}
		scopedCtx := context.WithValue(ctx, contextKey{}, scope)
		scope.ctx = scopedCtx
		defer scope.closed.Store(true)
		var err error
		out, err = fn(scopedCtx, scope)
		if err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return zero, err
	}
	return out, nil
}

// lockWaitText rounds up to a PostgreSQL millisecond bound; a positive value
// below one millisecond must not accidentally become zero (unlimited).
func lockWaitText(d time.Duration) string {
	ms := d / time.Millisecond
	if d%time.Millisecond != 0 {
		ms++
	}
	return strconv.FormatInt(int64(ms), 10) + "ms"
}
