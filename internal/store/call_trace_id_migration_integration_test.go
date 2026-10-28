package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// Migration 00023 (#34, decision 71) adds mcp_calls.trace_id: calls recorded
// before it have none (not a guess), the previous release's inserts, which do
// not name the column, still work, and Down removes the column and nothing
// else. It names migration 23 explicitly, so later migrations do not change
// what it checks, and then runs them over the same data.
func TestCallTraceIDMigration(t *testing.T) {
	const callTraceID = 23 // 00023_call_trace_id.sql
	runtime, _ := testutil.NewDB(t)
	pool := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	scalar := func(sql string) string {
		t.Helper()
		var out string
		if err := pool.QueryRow(ctx, sql).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	hasColumn := func() bool {
		return scalar(`SELECT count(*)::text FROM information_schema.columns WHERE table_name = 'mcp_calls' AND column_name = 'trace_id'`) == "1"
	}
	if !hasColumn() {
		t.Fatal("the newest schema has no mcp_calls.trace_id")
	}
	// Back to the previous release's schema (this runs the Down of 23 and of
	// every later migration), with a call recorded the way it does.
	if _, err := provider.DownTo(ctx, callTraceID-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasColumn() {
		t.Fatal("Down left the column")
	}
	exec(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('i', 's', 'a@example.com', 'A')`)
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome)
		SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok' FROM users`)

	if _, err := provider.UpTo(ctx, callTraceID); err != nil {
		t.Fatalf("up: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != callTraceID {
		t.Fatalf("schema version after up = %d %v, want %d", v, err, callTraceID)
	}
	if !hasColumn() {
		t.Fatal("Up did not add the column")
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_calls WHERE trace_id IS NULL`); got != "1" {
		t.Errorf("calls recorded before the upgrade with no trace ID = %s, want 1", got)
	}
	// An insert that does not name the column (the previous release) works,
	// and one that does stores it; the table stays append-only.
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome)
		SELECT 'tools/list', gen_random_uuid(), 'g', 'G', id, 'ok' FROM users`)
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome, trace_id)
		SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok', '0af7651916cd43dd8448eb211c80319c' FROM users`)
	want := "null,null,0af7651916cd43dd8448eb211c80319c"
	if got := scalar(`SELECT string_agg(coalesce(trace_id, 'null'), ',' ORDER BY id) FROM mcp_calls`); got != want {
		t.Errorf("trace_id = %s, want %s", got, want)
	}
	if _, err := pool.Exec(ctx, `UPDATE mcp_calls SET trace_id = 'x'`); err == nil {
		t.Error("mcp_calls accepted an update: it is append-only")
	}
	// The newer migrations apply over the same data and keep it.
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	if got := scalar(`SELECT string_agg(coalesce(trace_id, 'null'), ',' ORDER BY id) FROM mcp_calls`); got != want {
		t.Errorf("trace_id after the newer migrations = %s", got)
	}
}
