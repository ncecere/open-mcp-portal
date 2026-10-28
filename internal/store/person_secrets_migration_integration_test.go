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

// Migration 00024 (#22, decision 72) adds the person_secret auth mode, the
// person_secrets and secret_requests tables and the server's secret settings.
// It applies over a database at 00023 with servers in every older mode and
// leaves them as they are, accepts the previous release's inserts, cascades
// with the person and the server, and its Down puts person_secret servers back
// to none and restores the older check. It names migration 24 explicitly, so
// later migrations do not change what it checks, and then runs them.
func TestPersonSecretsMigration(t *testing.T) {
	const personSecrets = 24 // 00024_person_secrets.sql
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
		_, err := pool.Exec(ctx, sql, args...)
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
		if err := pool.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return out
	}
	if scalar(`SELECT to_regclass('person_secrets')::text`) == "" {
		t.Fatal("the newest schema has no person_secrets")
	}
	// Back to the previous release's schema, with a server in each older mode.
	if _, err := provider.DownTo(ctx, personSecrets-1); err != nil {
		t.Fatalf("down: %v", err)
	}
	if scalar(`SELECT coalesce(to_regclass('person_secrets')::text, '')`) != "" {
		t.Fatal("Down left the table")
	}
	must(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	for i, mode := range []string{"none", "static_header", "oauth"} {
		must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, $1, $1, 'https://x.example/mcp', $2 FROM teams`,
			"srv-"+string(rune('a'+i)), mode)
	}
	if err := exec(`UPDATE mcp_servers SET auth_mode = 'person_secret'`); err == nil {
		t.Fatal("the previous schema accepts person_secret")
	}

	if _, err := provider.UpTo(ctx, personSecrets); err != nil {
		t.Fatalf("up: %v", err)
	}
	if v, err := provider.GetDBVersion(ctx); err != nil || v != personSecrets {
		t.Fatalf("schema version after up = %d %v, want %d", v, err, personSecrets)
	}
	if got := scalar(`SELECT string_agg(auth_mode || ':' || coalesce(secret_placement, '-') || ':' || secret_prefix, ',' ORDER BY slug) FROM mcp_servers`); got != "none:-:,static_header:-:,oauth:-:" {
		t.Errorf("servers after the upgrade = %s", got)
	}
	// The previous release's insert, which names none of the new columns, still works.
	must(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 'old', 'old', 'https://y.example/mcp' FROM teams`)
	// The mode, with its settings; the shape check holds.
	must(`UPDATE mcp_servers SET auth_mode = 'person_secret', secret_placement = 'header', secret_name = 'X-Key' WHERE slug = 'old'`)
	must(`UPDATE mcp_servers SET secret_placement = 'bearer', secret_name = NULL WHERE slug = 'old'`)
	if exec(`UPDATE mcp_servers SET secret_placement = 'bearer', secret_name = 'X' WHERE slug = 'old'`) == nil {
		t.Error("a bearer secret with a name was accepted")
	}
	if exec(`UPDATE mcp_servers SET secret_placement = 'header', secret_name = NULL WHERE slug = 'old'`) == nil {
		t.Error("a header secret without a name was accepted")
	}
	if exec(`UPDATE mcp_servers SET secret_placement = 'cookie', secret_name = 'x' WHERE slug = 'old'`) == nil {
		t.Error("an unknown placement was accepted")
	}
	if exec(`UPDATE mcp_servers SET auth_mode = 'bogus' WHERE slug = 'old'`) == nil {
		t.Error("an unknown mode was accepted")
	}
	// Secrets: one per (person, server), cascading with both, and a request.
	must(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name) VALUES ('i', 's', 'a@example.com', 'A'), ('i', 't', 'b@example.com', 'B')`)
	must(`INSERT INTO person_secrets (user_id, server_id, origin, secret_cipher) SELECT u.id, s.id, 'https://y.example', '\x00' FROM users u, mcp_servers s WHERE s.slug = 'old'`)
	if exec(`INSERT INTO person_secrets (user_id, server_id, origin, secret_cipher) SELECT u.id, s.id, 'https://y.example', '\x00' FROM users u, mcp_servers s WHERE s.slug = 'old' AND u.email = 'a@example.com'`) == nil {
		t.Error("a second secret for one person and server was accepted")
	}
	if exec(`UPDATE person_secrets SET status = 'maybe'`) == nil {
		t.Error("an unknown status was accepted")
	}
	must(`INSERT INTO secret_requests (id_digest, id_cipher, user_id, server_id, server_origin, reason, gateway_id, gateway_slug, gateway_name, capability_id, capability_kind, exposed_name, expires_at)
		SELECT repeat('A', 43), '\x00', u.id, s.id, 'https://y.example', 'secret_missing', gen_random_uuid(), 'g', 'G', gen_random_uuid(), 'tool', 'x', now() + interval '1 hour'
		FROM users u, mcp_servers s WHERE s.slug = 'old' AND u.email = 'a@example.com'`)
	if exec(`UPDATE secret_requests SET reason = 'other'`) == nil {
		t.Error("an unknown reason was accepted")
	}
	must(`DELETE FROM users WHERE email = 'a@example.com'`)
	if got := scalar(`SELECT (SELECT count(*) FROM person_secrets)::text || ',' || (SELECT count(*) FROM secret_requests)::text`); got != "1,0" {
		t.Errorf("deleting a person left secrets,requests = %s, want 1,0", got)
	}
	must(`DELETE FROM mcp_servers WHERE slug = 'old'`)
	if got := scalar(`SELECT count(*)::text FROM person_secrets`); got != "0" {
		t.Errorf("deleting the server left %s secrets", got)
	}

	// Down puts such a server back to none and restores the older check.
	must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode, secret_placement) SELECT id, 'again', 'again', 'https://z.example/mcp', 'person_secret', 'bearer' FROM teams`)
	if _, err := provider.DownTo(ctx, personSecrets-1); err != nil {
		t.Fatalf("down again: %v", err)
	}
	if got := scalar(`SELECT auth_mode FROM mcp_servers WHERE slug = 'again'`); got != "none" {
		t.Errorf("a person_secret server after Down = %s, want none", got)
	}
	if err := exec(`UPDATE mcp_servers SET auth_mode = 'person_secret'`); err == nil || !strings.Contains(err.Error(), "auth_mode_check") {
		t.Errorf("Down left the mode allowed: %v", err)
	}
	// The newer migrations apply over the same data.
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up to the newest: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_servers`); got != "4" {
		t.Errorf("servers after the newer migrations = %s, want 4", got)
	}
}
