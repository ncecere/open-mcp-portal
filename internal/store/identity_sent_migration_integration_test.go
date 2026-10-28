package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// The upgrade that adds mcp_calls.identity_sent (decision 64): servers keep
// their stored "Send identity token" value, calls recorded before it have no
// value (not a guess), and the previous release's inserts, which do not name
// the column, still work. Down removes the column and nothing else.
//
// It names migration 19 explicitly (down to 18, up to 19), so later
// migrations don't change what it checks; it then runs the newer ones over the
// same data.
func TestIdentitySentMigrationKeepsWhatExists(t *testing.T) {
	const identitySent = 19 // 00019_call_identity_sent.sql
	runtime, _ := testutil.NewDB(t)
	pool := testutil.OwnerPool(t, runtime) // at the newest schema
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
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
		return scalar(`SELECT count(*)::text FROM information_schema.columns WHERE table_name = 'mcp_calls' AND column_name = 'identity_sent'`) == "1"
	}
	if !hasColumn() {
		t.Fatal("the newest schema has no mcp_calls.identity_sent")
	}

	// Back to the schema of the previous release (this runs the Down of 19 and
	// of every later migration), and make the data look like an installation of
	// it.
	testutil.RemoveRetirementFencesForOldSchema(t, pool)
	if _, err := provider.DownTo(ctx, identitySent-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != identitySent-1 {
		t.Fatalf("schema version after down = %d %v, want %d", v, err, identitySent-1)
	}
	if hasColumn() {
		t.Fatal("Down left the column")
	}
	exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	exec(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('i', 's', 'a@example.com', 'A')`)
	exec(`INSERT INTO mcp_servers (team_id, slug, name, url, send_identity)
		SELECT id, 'on', 'On', 'https://a.example/mcp', true FROM teams`)
	exec(`INSERT INTO mcp_servers (team_id, slug, name, url, send_identity)
		SELECT id, 'off', 'Off', 'https://b.example/mcp', false FROM teams`)
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome)
		SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok' FROM users`)

	if _, err := provider.UpTo(ctx, identitySent); err != nil {
		t.Fatalf("up: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != identitySent {
		t.Fatalf("schema version after up = %d %v, want %d", v, err, identitySent)
	}
	if !hasColumn() {
		t.Fatal("Up did not add the column")
	}
	if got := scalar(`SELECT string_agg(slug || '=' || send_identity::text, ',' ORDER BY slug) FROM mcp_servers`); got != "off=false,on=true" {
		t.Errorf("servers after the upgrade = %s", got)
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_calls WHERE identity_sent IS NULL`); got != "1" {
		t.Errorf("calls recorded before the upgrade with no value = %s, want 1", got)
	}
	// An insert that does not name the column (the previous release) still works.
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome)
		SELECT 'tools/list', gen_random_uuid(), 'g', 'G', id, 'ok' FROM users`)
	exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome, identity_sent)
		SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok', false FROM users`)
	if got := scalar(`SELECT string_agg(coalesce(identity_sent::text, 'null'), ',' ORDER BY id) FROM mcp_calls`); got != "null,null,false" {
		t.Errorf("identity_sent = %s", got)
	}
	// The newer migrations apply over the same data and keep it.
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	if got := scalar(`SELECT string_agg(coalesce(identity_sent::text, 'null'), ',' ORDER BY id) FROM mcp_calls`); got != "null,null,false" {
		t.Errorf("identity_sent after the newer migrations = %s", got)
	}
}
