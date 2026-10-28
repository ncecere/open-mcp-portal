package store_test

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

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
