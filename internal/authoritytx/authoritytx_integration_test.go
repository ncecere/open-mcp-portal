package authoritytx

// These exercise the gate/transaction primitive against real PostgreSQL. They
// do NOT prove application lifecycle eligibility, complete writer coverage,
// provider/cache nonpublication, first-fence progress or SCIM functionality.

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestAuthorityTxSharedConcurrentExclusiveRefusesBusy(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	finished := make(chan error, 1)
	go func() {
		_, err := Run(ctx, pool, Shared, Bounds{Total: 4 * time.Second, LockWait: 100 * time.Millisecond}, func(c context.Context, _ *Scope) (int, error) {
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
		t.Fatal("first shared entry did not reach explicit barrier")
	}
	if v, err := Run(ctx, pool, Shared, Bounds{Total: time.Second, LockWait: 50 * time.Millisecond}, func(_ context.Context, s *Scope) (int, error) {
		if s.Mode() != Shared {
			t.Error("wrong shared mode")
		}
		return 2, nil
	}); err != nil || v != 2 {
		t.Fatalf("independent shared transaction could not proceed: value=%d err=%v", v, err)
	}
	var called atomic.Bool
	value, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 50 * time.Millisecond}, func(context.Context, *Scope) (int, error) {
		called.Store(true)
		return 3, nil
	})
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" || value != 0 || called.Load() {
		t.Fatalf("busy exclusive admission: value=%d callback=%v err=%v", value, called.Load(), err)
	}
	unblock()
	select {
	case err := <-finished:
		if err != nil {
			t.Fatal("shared transaction did not commit:", err)
		}
	case <-ctx.Done():
		t.Fatal("shared transaction did not release its gate")
	}
	if v, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 4, nil }); err != nil || v != 4 {
		t.Fatalf("exclusive gate unavailable after shared commit: value=%d err=%v", v, err)
	}
}

func TestAuthorityTxExactRegisteredScopeNoNestedPoolAndLocalSettings(t *testing.T) {
	_, dsn := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns, cfg.MinConns = 1, 0
	tiny, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer tiny.Close()
	var original string
	if err := tiny.QueryRow(ctx, "SHOW lock_timeout").Scan(&original); err != nil {
		t.Fatal(err)
	}
	var saved *Scope
	got, err := Run(ctx, tiny, Exclusive, Bounds{Total: 2 * time.Second, LockWait: 50 * time.Millisecond}, func(c context.Context, s *Scope) (int, error) {
		saved = s
		q, err := s.Queries()
		if err != nil {
			return 0, err
		}
		tx, ok := store.TxOf(q)
		if !ok || s.Mode() != Exclusive {
			t.Fatal("scope not bound to the actual registered exclusive transaction")
		}
		var setting string
		if err := tx.QueryRow(c, "SHOW lock_timeout").Scan(&setting); err != nil || setting != "50ms" {
			t.Fatalf("transaction-local lock bound=%q err=%v", setting, err)
		}
		nestedCalled := false
		if v, err := Run(c, tiny, Shared, Bounds{Total: time.Second, LockWait: time.Millisecond}, func(context.Context, *Scope) (int, error) {
			nestedCalled = true
			return 99, nil
		}); !errors.Is(err, ErrNested) || v != 0 || nestedCalled {
			t.Fatalf("nested public entry opened or joined another pool transaction: value=%d err=%v", v, err)
		}
		return 7, nil
	})
	if err != nil || got != 7 {
		t.Fatalf("registered scope: value=%d err=%v", got, err)
	}
	if _, err := saved.Queries(); !errors.Is(err, ErrClosed) {
		t.Fatal("escaped scope remained usable")
	}
	var after string
	if err := tiny.QueryRow(ctx, "SHOW lock_timeout").Scan(&after); err != nil || after != original {
		t.Fatalf("SET LOCAL leaked beyond transaction: before=%q after=%q err=%v", original, after, err)
	}
}

func TestAuthorityTxFailedCommitPublishesNoValue(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := testutil.OwnerPool(t, pool).Exec(ctx, `
CREATE FUNCTION reject_authority_probe_commit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'owned authority primitive commit failure'; END $$;
CREATE CONSTRAINT TRIGGER reject_authority_probe_commit AFTER INSERT ON users
DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION reject_authority_probe_commit()`); err != nil {
		t.Fatal(err)
	}
	bodySucceeded := false
	value, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(c context.Context, s *Scope) (string, error) {
		q, err := s.Queries()
		if err != nil {
			return "", err
		}
		tx, ok := store.TxOf(q)
		if !ok {
			t.Fatal("unregistered transaction")
		}
		_, err = tx.Exec(c, `INSERT INTO users(email,display_name,oidc_issuer,oidc_subject)
VALUES ('authority-probe@example.test','Authority probe','authority-probe','authority-probe')`)
		bodySucceeded = err == nil
		return "must-not-publish", err
	})
	var pe *pgconn.PgError
	if !bodySucceeded || !errors.As(err, &pe) || pe.Code != "P0001" || pe.Message != "owned authority primitive commit failure" || value != "" {
		t.Fatal("expected exact deferred commit failure after successful body, with no uncommitted value")
	}
	var rows int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM users WHERE oidc_issuer='authority-probe'").Scan(&rows); err != nil || rows != 0 {
		t.Fatal("failed commit left a mutation")
	}
	if _, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); err != nil {
		t.Fatal("failed commit leaked the gate:", err)
	}
}

func TestAuthorityTxCancellationPublishesNoValueAndReleasesGate(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	value, err := Run(ctx, pool, Shared, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) {
		called = true
		cancel()
		return 8, nil
	})
	if !called || !errors.Is(err, context.Canceled) || value != 0 {
		t.Fatal("canceled callback returned a publishable value")
	}
	fresh, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if _, err := Run(fresh, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); err != nil {
		t.Fatal("cancellation leaked gate/transaction:", err)
	}
}

func TestAuthorityTxCallbackRefusalPublishesNoValue(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	refused := errors.New("owned callback refusal")
	called := false
	value, err := Run(ctx, pool, Shared, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (string, error) {
		called = true
		return "must-not-publish", refused
	})
	if !called || !errors.Is(err, refused) || value != "" {
		t.Fatal("callback refusal was hidden or published a value")
	}
	if _, err := Run(ctx, pool, Exclusive, Bounds{Total: time.Second, LockWait: 100 * time.Millisecond}, func(context.Context, *Scope) (int, error) { return 1, nil }); err != nil {
		t.Fatal("callback refusal leaked its gate:", err)
	}
}

func TestLockWaitTextNeverRoundsPositiveBoundToUnlimited(t *testing.T) {
	for duration, want := range map[time.Duration]string{time.Nanosecond: "1ms", time.Millisecond: "1ms", time.Millisecond + 1: "2ms"} {
		if got := lockWaitText(duration); got != want {
			t.Fatalf("lock bound %v: got %q want %q", duration, got, want)
		}
	}
}
