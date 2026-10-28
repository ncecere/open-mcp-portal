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

// Migration 00025 (#24, decision 73) adds auth_mode machine_oauth and the
// table of a server's machine OAuth client. It depends on no other migration
// of the release (it only touches mcp_servers' auth_mode check and adds a table
// that references mcp_servers and users): it applies on a database at 00023
// whether or not 00024 and 00026 are there. Servers saved before it are
// untouched, the previous release's inserts keep working, the new mode is
// refused a static Authorization header and a requirement, a server's client
// goes with the server, and Down turns machine_oauth servers into servers
// without authentication and removes only what it added.
func TestMachineOAuthMigration(t *testing.T) {
	const machineOAuth = 25 // 00025_machine_oauth.sql
	runtime, _ := newHistoricalDB(t, 25)
	pool := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) error {
		_, err := runtime.Exec(ctx, sql, args...)
		return err
	}
	mustExec := func(sql string, args ...any) {
		t.Helper()
		if err := exec(sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	scalar := func(sql string) string {
		t.Helper()
		var out string
		if err := runtime.QueryRow(ctx, sql).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	hasTable := func() bool {
		return scalar(`SELECT count(*)::text FROM information_schema.tables WHERE table_name = 'mcp_server_machine_oauth'`) == "1"
	}
	if !hasTable() {
		t.Fatal("the historical schema has no mcp_server_machine_oauth")
	}

	// Run the Down of 25 from its historical schema, with servers saved as
	// the previous release would have written them.
	if _, err := provider.DownTo(ctx, machineOAuth-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasTable() {
		t.Fatal("Down left the table")
	}
	mustExec(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	if err := exec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, 'x', 'X', 'https://x.example/mcp', 'machine_oauth' FROM teams`); err == nil {
		t.Fatal("the previous schema accepted auth_mode machine_oauth")
	}
	mustExec(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 'plain', 'Plain', 'https://plain.example/mcp' FROM teams`)
	mustExec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_header_name, auth_value_cipher, auth_value_hint, auth_mode)
		SELECT id, 'static', 'Static', 'https://static.example/mcp', 'X-Api-Key', '\x00', 'abcd', 'static_header' FROM teams`)

	if _, err := provider.UpTo(ctx, machineOAuth); err != nil {
		t.Fatalf("up: %v", err)
	}
	regrantMigrationFixture(t, runtime)
	if v, err := provider.GetDBVersion(ctx); err != nil || v != machineOAuth {
		t.Fatalf("schema version after up = %d %v, want %d", v, err, machineOAuth)
	}
	if !hasTable() {
		t.Fatal("Up did not add the table")
	}
	// Existing servers are untouched.
	if got := scalar(`SELECT string_agg(slug || ':' || auth_mode, ',' ORDER BY slug) FROM mcp_servers`); got != "plain:none,static:static_header" {
		t.Errorf("servers after the migration = %s", got)
	}
	// The previous release's insert (no machine columns anywhere) still works.
	mustExec(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 'old', 'Old', 'https://old.example/mcp' FROM teams`)

	// The new mode and its rules.
	mustExec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, 'machine', 'Machine', 'https://m.example/mcp', 'machine_oauth' FROM teams`)
	if err := exec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, 'bogus', 'B', 'https://b.example/mcp', 'bogus' FROM teams`); err == nil {
		t.Error("an unknown auth mode was accepted")
	}
	if err := exec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode, auth_header_name, auth_value_cipher)
		SELECT id, 'auth', 'A', 'https://a.example/mcp', 'machine_oauth', 'Authorization', '\x00' FROM teams`); err == nil {
		t.Error("machine_oauth with a static Authorization header was accepted")
	}
	mustExec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode, auth_header_name, auth_value_cipher)
		SELECT id, 'tenant', 'T', 'https://t.example/mcp', 'machine_oauth', 'X-Tenant', '\x00' FROM teams`)
	mustExec(`INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url)
		VALUES ('p', 'P', 'c', 'none', true, 'https://a', 'https://t')`)
	if err := exec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode, auth_provider_id)
		SELECT t.id, 'req', 'R', 'https://r.example/mcp', 'machine_oauth', p.id FROM teams t, auth_providers p`); err == nil {
		t.Error("machine_oauth with a user authorization requirement was accepted")
	}

	// The client: one per server, with a sealed secret, a known method, and
	// deleted with its server.
	mustExec(`INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher, client_secret_hint, scopes, resource)
		SELECT id, 'https://idp.example/token', 'client', '\x00', '1234', '{read}', 'https://m.example/mcp' FROM mcp_servers WHERE slug = 'machine'`)
	if got := scalar(`SELECT token_auth_method || ' ' || cardinality(scopes)::text || ' ' || coalesce(audience, 'none') FROM mcp_server_machine_oauth`); got != "client_secret_basic 1 none" {
		t.Errorf("defaults = %s", got)
	}
	for name, sql := range map[string]string{
		"a second client for one server": `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) SELECT id, 'https://i.example/t', 'c', '\x00' FROM mcp_servers WHERE slug = 'machine'`,
		"no secret":                      `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) SELECT id, 'https://i.example/t', 'c', NULL FROM mcp_servers WHERE slug = 'tenant'`,
		"an unknown method":              `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher, token_auth_method) SELECT id, 'https://i.example/t', 'c', '\x00', 'none' FROM mcp_servers WHERE slug = 'tenant'`,
		"an empty client":                `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) SELECT id, 'https://i.example/t', '', '\x00' FROM mcp_servers WHERE slug = 'tenant'`,
		"a long hint":                    `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher, client_secret_hint) SELECT id, 'https://i.example/t', 'c', '\x00', '12345' FROM mcp_servers WHERE slug = 'tenant'`,
		"a missing server":               `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher) VALUES (gen_random_uuid(), 'https://i.example/t', 'c', '\x00')`,
		"too many scopes":                `INSERT INTO mcp_server_machine_oauth (server_id, token_url, client_id, client_secret_cipher, scopes) SELECT id, 'https://i.example/t', 'c', '\x00', array_fill('s'::text, ARRAY[51]) FROM mcp_servers WHERE slug = 'tenant'`,
	} {
		if err := exec(sql); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}

	// Down: machine servers become servers without authentication, the table
	// goes, nothing else changes. The newer migrations apply again over it.
	if _, err := provider.DownTo(ctx, machineOAuth-1); err != nil {
		t.Fatalf("down with data: %v", err)
	}
	if hasTable() {
		t.Fatal("Down left the table")
	}
	if got := scalar(`SELECT string_agg(slug || ':' || auth_mode, ',' ORDER BY slug) FROM mcp_servers`); !strings.Contains(got, "machine:none") ||
		!strings.Contains(got, "plain:none") || !strings.Contains(got, "static:static_header") || strings.Contains(got, "machine_oauth") {
		t.Errorf("servers after Down = %s", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	regrantMigrationFixture(t, runtime)
	if !hasTable() || scalar(`SELECT count(*)::text FROM mcp_server_machine_oauth`) != "0" {
		t.Error("the table after up again")
	}
}
