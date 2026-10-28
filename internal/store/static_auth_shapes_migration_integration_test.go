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

// Migration 00022 (a server's own credential as parts, roadmap #23): a new
// table only. A server that has a static header keeps it in the legacy columns,
// untouched, and the table starts empty (the registry reads the header as one
// part until the credential is saved as a list); the previous release's inserts
// still work; the table's constraints hold; it cascades with the server; the
// Down drops it and nothing else; and it depends on nothing a neighbouring
// migration adds (it applies on a database at 00020, with or without 00021).
func TestStaticAuthShapesMigration00022(t *testing.T) {
	const staticAuth = 22 // 00022_static_auth_shapes.sql
	runtime, _ := newHistoricalDB(t, 22)
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
		_, err := runtime.Exec(ctx, sql, args...)
		return err
	}
	must := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	scalar := func(sql string, args ...any) string {
		t.Helper()
		var out string
		if err := runtime.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	hasTable := func() bool {
		return scalar(`SELECT count(*)::text FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'mcp_server_credentials'`) == "1"
	}

	// The previous release's schema, with a server that has a static header.
	if _, err := provider.DownTo(ctx, staticAuth-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasTable() {
		t.Fatal("Down left the table")
	}
	must(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_header_name, auth_value_cipher, auth_value_hint, auth_mode)
		SELECT id, 'old', 'Old', 'https://a.example/mcp', 'X-Api-Key', '\x0102', 'abcd', 'static_header' FROM teams`)
	must(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 'open', 'Open', 'https://b.example/mcp' FROM teams`)

	if _, err := provider.UpTo(ctx, staticAuth); err != nil {
		t.Fatalf("up: %v", err)
	}
	regrantMigrationFixture(t, runtime)
	if v, err := provider.GetDBVersion(ctx); err != nil || v != staticAuth {
		t.Fatalf("schema version = %d %v", v, err)
	}
	// No data was rewritten: the legacy header is exactly as it was and the table is empty.
	if got := scalar(`SELECT auth_header_name || ' ' || encode(auth_value_cipher, 'hex') || ' ' || auth_value_hint || ' ' || auth_mode
		FROM mcp_servers WHERE slug = 'old'`); got != "X-Api-Key 0102 abcd static_header" {
		t.Errorf("the legacy header after the upgrade = %q", got)
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_server_credentials`); got != "0" {
		t.Errorf("parts after the upgrade = %s, want none", got)
	}
	// An insert of the previous release (it knows nothing of the table) works, and so does its update of the header.
	must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_header_name, auth_value_cipher) SELECT id, 'prev', 'Prev', 'https://c.example/mcp', 'X-K', '\x00' FROM teams`)
	must(`UPDATE mcp_servers SET auth_value_cipher = '\x03' WHERE slug = 'prev'`)

	server := scalar(`SELECT id::text FROM mcp_servers WHERE slug = 'open'`)
	part := func(position int, kind, name, secondary string) error {
		var n, s any
		if name != "" {
			n = name
		}
		if secondary != "" {
			s = []byte(secondary)
		}
		return exec(`INSERT INTO mcp_server_credentials (server_id, position, kind, name, value_cipher, secondary_cipher) VALUES ($1, $2, $3, $4, '\x00', $5)`,
			server, position, kind, n, s)
	}
	for name, c := range map[string]struct {
		pos                       int
		kind, partName, secondary string
	}{
		"a header":            {0, "header", "X-Tenant", ""},
		"a query key":         {1, "query", "api_key", ""},
		"a bearer":            {2, "bearer", "", ""},
		"basic with password": {3, "basic", "", "pw"},
	} {
		if err := part(c.pos, c.kind, c.partName, c.secondary); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, c := range map[string]struct {
		pos                       int
		kind, partName, secondary string
	}{
		"the same name in another case": {4, "header", "x-TENANT", ""},
		"a second bearer":               {5, "bearer", "", ""},
		"the same position":             {0, "header", "X-Other", ""},
		"a ninth position":              {8, "header", "X-Nine", ""},
		"an unknown kind":               {6, "cookie", "c", ""},
		"a header without a name":       {6, "header", "", ""},
		"a bearer with a name":          {6, "bearer", "x", ""},
		"basic without a password":      {6, "basic", "", ""},
		"a header with a second value":  {6, "header", "X-Two", "pw"},
		"a too long name":               {6, "query", strings.Repeat("a", 101), ""},
	} {
		if err := part(c.pos, c.kind, c.partName, c.secondary); err == nil {
			t.Errorf("%s was stored", name)
		}
	}
	// The same name of another kind is another part.
	if err := part(6, "query", "X-Tenant", ""); err != nil {
		t.Errorf("a query part named like a header: %v", err)
	}
	// Parts are the server's: deleting it deletes them.
	must(`DELETE FROM mcp_servers WHERE slug = 'open'`)
	if got := scalar(`SELECT count(*)::text FROM mcp_server_credentials`); got != "0" {
		t.Errorf("parts after the server was deleted = %s", got)
	}

	// Down removes the table and nothing else; the servers and their headers stay.
	if _, err := provider.DownTo(ctx, staticAuth-1); err != nil {
		t.Fatalf("down again: %v", err)
	}
	if hasTable() {
		t.Error("the table survived the Down")
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_servers WHERE auth_header_name IS NOT NULL`); got != "2" {
		t.Errorf("servers with a header after the Down = %s, want 2", got)
	}
	if _, err := provider.UpTo(ctx, 33); err != nil {
		t.Fatalf("up to the last reversible schema: %v", err)
	}
	regrantMigrationFixture(t, runtime)
	if !hasTable() {
		t.Fatal("the table is missing after the reversible migrations")
	}

	// It needs nothing from a neighbouring migration: its statements alone, on
	// the schema of 00020, create the table (what another migration of the same
	// release adds, or doesn't, makes no difference).
	if _, err := provider.DownTo(ctx, 20); err != nil {
		t.Fatalf("down to 20: %v", err)
	}
	raw, err := migrations.FS.ReadFile("00022_static_auth_shapes.sql")
	if err != nil {
		t.Fatal(err)
	}
	up := string(raw)
	up = up[strings.Index(up, "-- +goose Up")+len("-- +goose Up") : strings.Index(up, "-- +goose Down")]
	for _, stmt := range strings.Split(up, ";\n") {
		if strings.TrimSpace(stmt) != "" {
			if _, err := pool.Exec(ctx, stmt); err != nil {
				t.Fatal(err)
			}
		}
	}
	regrantMigrationFixture(t, runtime)
	if !hasTable() {
		t.Error("00022's statements alone did not create the table on a database at 00020")
	}
	if _, err := pool.Exec(ctx, `DROP TABLE mcp_server_credentials`); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up after the manual run: %v", err)
	}
	regrantMigrationFixture(t, runtime)
}
