package authoritytx

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Primitive-only evidence: a false TRY neither waits for G nor poisons its
// registered owner. SELECT below is not a model of allowed dormant writes.
func TestAuthorityTryBusyLeavesOwnerUsableAndSettingsUnchanged(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	finished := make(chan error, 1)
	go func() {
		_, err := Run(ctx, pool, Exclusive, Bounds{Total: 4 * time.Second, LockWait: 100 * time.Millisecond}, func(c context.Context, _ *Scope) (int, error) {
			close(entered)
			select {
			case <-release:
				return 1, nil
			case <-c.Done():
				return 0, c.Err()
			}
		})
		finished <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("exclusive holder did not reach the barrier")
	}
	for _, mode := range []Mode{Shared, Exclusive} {
		err := store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout='17s'"); err != nil {
				return err
			}
			called := false
			acquired, err := TryPrelocked(ctx, q, mode, Bounds{Total: time.Second, LockWait: time.Millisecond}, func(context.Context, *Scope) error {
				called = true
				return nil
			})
			if err != nil || acquired || called {
				t.Fatalf("busy TRY: acquired=%v called=%v err=%v", acquired, called, err)
			}
			var one int
			var setting string
			if err := tx.QueryRow(ctx, "SELECT 1,current_setting('lock_timeout')").Scan(&one, &setting); err != nil || one != 1 || setting != "17s" {
				t.Fatalf("busy TRY poisoned/changed owner: one=%d setting=%q err=%v", one, setting, err)
			}
			return nil
		})
		if err != nil {
			t.Fatal("busy owner could not commit:", err)
		}
	}
	unblock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("holder did not finish")
	}
}

func TestAuthorityTryUsesExactOwnerAndHoldsGateUntilOwnerCommit(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var escaped *Scope
	err := store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		var originalPID int
		if err := tx.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&originalPID); err != nil {
			return err
		}
		acquired, err := TryPrelocked(ctx, q, Shared, Bounds{Total: time.Second, LockWait: 50 * time.Millisecond}, func(c context.Context, s *Scope) error {
			escaped = s
			bound, err := s.Queries()
			if err != nil {
				return err
			}
			owner, ok := store.TxOf(bound)
			if !ok || bound != q || owner != tx || s.Mode() != Shared {
				t.Fatal("TRY used a different transaction/queries/mode")
			}
			var actualPID int
			if err := owner.QueryRow(c, "SELECT pg_backend_pid()").Scan(&actualPID); err != nil || actualPID != originalPID {
				t.Fatal("TRY opened a different backend")
			}
			if _, err := Run(c, pool, Shared, Bounds{Total: time.Second, LockWait: time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); !errors.Is(err, ErrNested) {
				t.Fatal("nested public gate not rejected")
			}
			return nil
		})
		if err != nil || !acquired {
			t.Fatalf("uncontended TRY did not acquire: acquired=%v err=%v", acquired, err)
		}
		if _, err := escaped.Queries(); !errors.Is(err, ErrClosed) {
			t.Fatal("finalization scope escaped its callback")
		}
		_, err = Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 50 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil })
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "55P03" {
			t.Fatalf("TRY released G before its owner's commit: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); err != nil {
		t.Fatal("owner commit failed to release G:", err)
	}
}

func TestAuthorityTryRejectsUnregisteredQueriesAndNestedEntry(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	callback := func(context.Context, *Scope) error { t.Fatal("invalid entry called finalizer"); return nil }
	if acquired, err := TryPrelocked(ctx, dbgen.New(pool), Shared, Bounds{Total: time.Second, LockWait: time.Millisecond}, callback); acquired || !errors.Is(err, ErrUnregistered) {
		t.Fatal("pool-backed queries accepted as prelocked")
	}
	var expired *dbgen.Queries
	if err := store.InTx(ctx, pool, func(q *dbgen.Queries, _ pgx.Tx) error { expired = q; return nil }); err != nil {
		t.Fatal(err)
	}
	if acquired, err := TryPrelocked(ctx, expired, Shared, Bounds{Total: time.Second, LockWait: time.Millisecond}, callback); acquired || !errors.Is(err, ErrUnregistered) {
		t.Fatal("expired transaction queries accepted")
	}
	_, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(c context.Context, s *Scope) (int, error) {
		q, err := s.Queries()
		if err != nil {
			return 0, err
		}
		if acquired, err := TryPrelocked(c, q, Shared, Bounds{Total: time.Second, LockWait: time.Millisecond}, callback); acquired || !errors.Is(err, ErrNested) {
			t.Fatal("nested TRY attempted mode reacquisition")
		}
		return 1, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAuthorityTryCallbackErrorRollsBackOwningTransaction(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	refused := errors.New("owned prelocked finalizer refusal")
	called := false
	err := store.InTx(ctx, pool, func(q *dbgen.Queries, _ pgx.Tx) error {
		acquired, err := TryPrelocked(ctx, q, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) error {
			called = true
			return refused
		})
		if !acquired || !called || !errors.Is(err, refused) {
			t.Fatal("finalizer refusal not returned to owner")
		}
		return err // owner, not TRY, is responsible for rollback
	})
	if !called || !errors.Is(err, refused) {
		t.Fatal("owner did not propagate finalizer refusal")
	}
	if _, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); err != nil {
		t.Fatal("owner rollback leaked G:", err)
	}
}
