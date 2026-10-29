package mcptasks_test

import (
	"context"
	"testing"
)

func TestPruneDeletesOnlyExpiredRowsInBoundedBatches(t *testing.T) {
	f := newTaskStoreFixture(t, 1000)
	ctx := context.Background()
	for range 6 {
		activate(t, f, f.binding)
	}
	count := func() (n int) {
		if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_tasks`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n, err := f.store.Prune(ctx, 2); err != nil || n != 0 || count() != 6 {
		t.Fatalf("nothing expired: pruned=%d err=%v rows=%d", n, err, count())
	}
	// Expire five of them (the table's lifetime constraint needs expires_at >
	// created_at, so move created_at back as well) and abandon a reservation.
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET created_at = clock_timestamp() - interval '3 hours', ceiling_at = clock_timestamp() - interval '1 minute',
		expires_at = clock_timestamp() - interval '1 minute' WHERE id <> (SELECT id FROM mcp_tasks ORDER BY created_at DESC, id LIMIT 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Reserve(ctx, f.binding, f.payload); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE mcp_tasks SET created_at = clock_timestamp() - interval '3 hours', ceiling_at = clock_timestamp() - interval '1 minute',
		expires_at = clock_timestamp() - interval '1 minute', reservation_deadline = clock_timestamp() - interval '2 minutes' WHERE status = 'reserved'`); err != nil {
		t.Fatal(err)
	}
	before := count()
	n, err := f.store.Prune(ctx, 2)
	if err != nil || n == 0 || n > 10*2 || count() != before-int(n) {
		t.Fatalf("pruned=%d err=%v rows %d -> %d", n, err, before, count())
	}
	// Whatever the first call left, the next ones finish it; live rows stay.
	for range 3 {
		if _, err := f.store.Prune(ctx, 1000); err != nil {
			t.Fatal(err)
		}
	}
	var open int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM mcp_tasks WHERE expires_at > clock_timestamp()`).Scan(&open); err != nil || open != 1 || count() != 1 {
		t.Fatalf("remaining rows = %d, live = %d (%v)", count(), open, err)
	}
}
