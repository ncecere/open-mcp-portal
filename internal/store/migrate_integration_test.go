package store_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/migrations"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Replicas and the migration Job may start at the same time; migrations must
// be serialised and re-running them must be a no-op.
func TestConcurrentMigrationsAreSafe(t *testing.T) {
	pool, _ := testutil.NewDB(t) // already migrated once
	// A pool smaller than the number of concurrent callers: waiting for the
	// migration lock must not use pool connections (it deadlocked on 2-CPU
	// CI runners, where pgxpool defaults to 4 connections).
	cfg := testutil.OwnerPool(t, pool).Config().Copy()
	cfg.MaxConns = 2
	small, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(small.Close)
	pool = small
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Migrate(context.Background(), pool, testutil.Logger())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate: %v", err)
		}
	}
}

// Several migrators starting together on a database that still has to apply
// 00059 (CREATE INDEX CONCURRENTLY): the waiters must not hold snapshots while
// they wait for the migration lock, or the index build and the lock wait
// deadlock (seen on the three-replica Kubernetes load test).
func TestConcurrentMigrationsWithConcurrentIndex(t *testing.T) {
	pool, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		_, err = provider.UpTo(ctx, 58)
		return err
	})
	owner := testutil.OwnerPool(t, pool)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 4)
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- store.Migrate(ctx, owner, testutil.Logger())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent migrate across 00059: %v", err)
		}
	}
	var valid bool
	if err := owner.QueryRow(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid='public.audit_log_stream_idx'::regclass`).Scan(&valid); err != nil || !valid {
		t.Fatalf("index valid=%v err=%v", valid, err)
	}
}
