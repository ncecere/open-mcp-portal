package store_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// Migration 00020 (trusted agent platforms): it adds the mcp_calls columns
// without a CHECK and the length checks NOT VALID then validated, so it never
// scans the call history under an ACCESS EXCLUSIVE lock. The upgrade keeps the
// calls and servers that exist, the previous release's inserts still work, the
// Down works, and running the Up again (after a failure half way) is safe.
func TestAgentPlatformsMigration00020(t *testing.T) {
	const agentPlatforms = 20 // 00020_agent_platforms.sql
	runtime, _ := testutil.NewDB(t)
	pool := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) error {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		return err
	}
	must := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
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
	exists := func(sql string) bool { t.Helper(); return scalar(`SELECT count(*)::text FROM (`+sql+`) x`) != "0" }
	hasTable := func(name string) bool {
		return exists(`SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = '` + name + `'`)
	}
	hasColumn := func(table, column string) bool {
		return exists(`SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = '` + table + `' AND column_name = '` + column + `'`)
	}
	callColumns := []string{"agent_id", "agent_name", "via_platform_id", "via_platform_name", "person_present"}

	if !hasTable("agent_platforms") || !hasColumn("mcp_servers", "requires_present_person") {
		t.Fatal("the newest schema lacks the agent platform tables")
	}
	// The length checks exist, are validated, and are enforced.
	if got := scalar(`SELECT string_agg(conname || '=' || convalidated::text, ',' ORDER BY conname) FROM pg_constraint
		WHERE conrelid = 'mcp_calls'::regclass AND conname IN ('mcp_calls_agent_id_len', 'mcp_calls_agent_name_len', 'mcp_calls_via_platform_name_len')`); got !=
		"mcp_calls_agent_id_len=true,mcp_calls_agent_name_len=true,mcp_calls_via_platform_name_len=true" {
		t.Fatalf("mcp_calls checks = %s", got)
	}
	// No index to build under a write lock: no query filters on the platform.
	if exists(`SELECT 1 FROM pg_indexes WHERE tablename = 'mcp_calls' AND indexname = 'mcp_calls_via_platform_idx'`) {
		t.Error("mcp_calls_via_platform_idx exists")
	}
	insertCall := func(extraCols, extraVals string) error {
		return exec(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome` + extraCols + `)
			SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok'` + extraVals + ` FROM users`)
	}
	must(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('i', 's', 'a@example.com', 'A')`)
	for col, n := range map[string]int{"agent_id": 129, "agent_name": 201, "via_platform_name": 101} {
		if err := insertCall(", "+col, ", '"+strings.Repeat("x", n)+"'"); err == nil {
			t.Errorf("a %d-character %s was stored", n, col)
		}
		if err := insertCall(", "+col, ", '"+strings.Repeat("x", n-1)+"'"); err != nil {
			t.Errorf("a %d-character %s: %v", n-1, col, err)
		}
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v < agentPlatforms {
		t.Fatalf("schema version = %d %v", v, err)
	}

	// Back to the previous release's schema (the Down of 20 and of every later
	// migration), and make the data look like an installation of it.
	testutil.RemoveRetirementFencesForOldSchema(t, pool)
	if _, err := provider.DownTo(ctx, agentPlatforms-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasTable("agent_platforms") || hasTable("agent_token_jtis") || hasColumn("mcp_servers", "requires_present_person") ||
		hasColumn("mcp_capabilities", "requires_present_person") || hasColumn("service_accounts", "relay_platform_id") {
		t.Fatal("Down left something of the migration")
	}
	for _, c := range callColumns {
		if hasColumn("mcp_calls", c) {
			t.Fatalf("Down left mcp_calls.%s", c)
		}
	}
	must(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	must(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 's', 'S', 'https://a.example/mcp' FROM teams`)
	must(`INSERT INTO service_accounts (team_id, name, role) SELECT id, 'sa', 'editor' FROM teams`)
	must(`INSERT INTO mcp_calls (method, gateway_id, gateway_slug, gateway_name, user_id, outcome)
		SELECT 'tools/call', gen_random_uuid(), 'g', 'G', id, 'ok' FROM users`)
	before := scalar(`SELECT count(*)::text FROM mcp_calls`) // the log is append-only: count, don't clear

	if _, err := provider.UpTo(ctx, agentPlatforms); err != nil {
		t.Fatalf("up: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != agentPlatforms {
		t.Fatalf("schema version after up = %d %v, want %d", v, err, agentPlatforms)
	}
	// What existed is kept; the new columns are empty or off.
	if got := scalar(`SELECT count(*)::text FROM mcp_calls WHERE agent_id IS NULL AND agent_name IS NULL AND via_platform_id IS NULL
		AND via_platform_name IS NULL AND person_present IS NULL`); got != before {
		t.Errorf("calls recorded before the upgrade with no agent = %s, want %s", got, before)
	}
	if got := scalar(`SELECT requires_present_person::text FROM mcp_servers`); got != "false" {
		t.Errorf("a server's present-person switch after the upgrade = %s, want false", got)
	}
	if got := scalar(`SELECT count(*)::text FROM service_accounts WHERE relay_platform_id IS NULL`); got != "1" {
		t.Errorf("service accounts without a relay mark = %s, want 1", got)
	}
	// An insert that doesn't name the columns (the previous release) works.
	if err := insertCall("", ""); err != nil {
		t.Errorf("an insert of the previous release: %v", err)
	}

	// Run the Up's statements again, as after a failure half way: nothing
	// fails and nothing is lost.
	raw, err := migrations.FS.ReadFile("00020_agent_platforms.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
	up = up[strings.Index(up, "-- +goose Up")+len("-- +goose Up") : strings.Index(up, "-- +goose Down")]
	for _, stmt := range strings.Split(up, ";\n") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if err := exec(stmt); err != nil {
			t.Fatalf("running the Up again: %v\n%s", err, stmt)
		}
	}
	if got, want := scalar(`SELECT count(*)::text FROM mcp_calls`), scalar(`SELECT (`+before+` + 1)::text`); got != want {
		t.Errorf("calls after running the Up again = %s, want %s", got, want)
	}
	if got := scalar(`SELECT string_agg(convalidated::text, ',') FROM pg_constraint
		WHERE conrelid = 'mcp_calls'::regclass AND conname LIKE 'mcp\_calls\_%\_len'`); got != "true,true,true" {
		t.Errorf("checks after running the Up again = %s", got)
	}
	// And the migration runs the whole way up, then down and up once more.
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	testutil.RemoveRetirementFencesForOldSchema(t, pool)
	if _, err := provider.DownTo(ctx, agentPlatforms-1); err != nil {
		t.Fatalf("second down: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("second up: %v", err)
	}
}
