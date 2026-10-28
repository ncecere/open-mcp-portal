package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// The upgrade that adds the per-provider access list (decision 69, issue
// #27): every provider that exists stays open and keeps narrowing off, so
// nothing changes for a team at the upgrade; the previous release, which does
// not know the columns, still inserts providers (open); the lists cascade with
// the provider, the team and the server; Down removes what the migration added.
//
// It names migration 21 explicitly (down to 20, up to 21), so later migrations
// don't change what it checks.
func TestProviderAccessMigrationKeepsProvidersOpen(t *testing.T) {
	const access = 21 // 00021_provider_access.sql
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
	hasTable := func(name string) bool {
		return scalar(`SELECT count(*)::text FROM information_schema.tables WHERE table_name = '`+name+`'`) == "1"
	}
	if !hasTable("auth_provider_teams") || !hasTable("auth_provider_servers") {
		t.Fatal("the newest schema has no access list tables")
	}

	// The schema of the previous release, with a provider as it would have it.
	if _, err := provider.DownTo(ctx, access-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasTable("auth_provider_teams") || hasTable("auth_provider_servers") {
		t.Fatal("Down left a table")
	}
	if scalar(`SELECT count(*)::text FROM information_schema.columns WHERE table_name = 'auth_providers' AND column_name IN ('access_mode', 'narrow_on_refresh')`) != "0" {
		t.Fatal("Down left a column")
	}
	insert := func(slug string) {
		exec(`INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url)
			VALUES ($1, $1, 'c', 'none', true, 'https://a.example/a', 'https://a.example/t')`, slug)
	}
	insert("github")
	insert("google")

	if _, err := provider.UpTo(ctx, access); err != nil {
		t.Fatalf("up: %v", err)
	}
	if got := scalar(`SELECT string_agg(slug || '=' || access_mode || '/' || narrow_on_refresh::text, ',' ORDER BY slug) FROM auth_providers`); got != "github=open/false,google=open/false" {
		t.Errorf("providers after the upgrade = %s", got)
	}
	// The previous release's insert (no access_mode) still works and is open.
	insert("gitlab")
	if got := scalar(`SELECT access_mode FROM auth_providers WHERE slug = 'gitlab'`); got != "open" {
		t.Errorf("a provider inserted without the column = %s", got)
	}
	if _, err := pool.Exec(ctx, `UPDATE auth_providers SET access_mode = 'sometimes' WHERE slug = 'gitlab'`); err == nil {
		t.Error("an unknown access mode was accepted")
	}

	// The lists cascade with the provider, the team and the server.
	exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	exec(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 's', 'S', 'https://s.example/mcp' FROM teams`)
	exec(`UPDATE auth_providers SET access_mode = 'restricted' WHERE slug = 'github'`)
	exec(`INSERT INTO auth_provider_teams (provider_id, team_id) SELECT p.id, t.id FROM auth_providers p, teams t WHERE p.slug = 'github'`)
	exec(`INSERT INTO auth_provider_servers (provider_id, server_id) SELECT p.id, s.id FROM auth_providers p, mcp_servers s WHERE p.slug = 'github'`)
	exec(`INSERT INTO auth_provider_teams (provider_id, team_id) SELECT p.id, t.id FROM auth_providers p, teams t WHERE p.slug = 'google'`)
	if got := scalar(`SELECT count(*)::text FROM auth_provider_teams`); got != "2" {
		t.Fatalf("team entries = %s", got)
	}
	exec(`DELETE FROM mcp_servers`)
	if got := scalar(`SELECT count(*)::text FROM auth_provider_servers`); got != "0" {
		t.Errorf("server entries after deleting the server = %s", got)
	}
	exec(`DELETE FROM auth_providers WHERE slug = 'google'`)
	if got := scalar(`SELECT count(*)::text FROM auth_provider_teams`); got != "1" {
		t.Errorf("team entries after deleting a provider = %s", got)
	}
	exec(`DELETE FROM teams`)
	if got := scalar(`SELECT count(*)::text FROM auth_provider_teams`); got != "0" {
		t.Errorf("team entries after deleting the team = %s", got)
	}

	// The newer migrations apply over the same data and keep it.
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	if got := scalar(`SELECT string_agg(slug || '=' || access_mode, ',' ORDER BY slug) FROM auth_providers`); got != "github=restricted,gitlab=open" {
		t.Errorf("providers after the newer migrations = %s", got)
	}
}
