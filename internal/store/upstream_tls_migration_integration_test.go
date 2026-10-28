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

// Migration 00026 (#25, decision 74) adds mcp_server_tls and replaces the
// enumerated check on mcp_health_checks.error_class by a length bound, so the
// new class 'tls' can be stored. A database at 00023 takes it (it depends on
// nothing newer, so it applies in any order with the other 0.3.2 migrations),
// health checks written before keep their classes, the previous release's
// inserts work, and Down turns stored 'tls' checks back into 'unavailable'
// before it restores the old check.
func TestUpstreamTLSMigration(t *testing.T) {
	const callTraceID = 23 // the newest schema of v0.3.1
	runtime, _ := newHistoricalDB(t, 26)
	pool := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := runtime.Exec(ctx, sql, args...); err != nil {
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
		return scalar(`SELECT count(*)::text FROM information_schema.tables WHERE table_name = 'mcp_server_tls'`) == "1"
	}
	if !hasTable() {
		t.Fatal("the historical schema has no mcp_server_tls")
	}
	// The previous release's schema, with a server and a failed health check.
	if _, err := provider.DownTo(ctx, callTraceID); err != nil {
		t.Fatalf("down: %v", err)
	}
	if hasTable() {
		t.Fatal("Down left the table")
	}
	exec(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
	exec(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 's', 'S', 'https://x.example/mcp' FROM teams`)
	insertCheck := func(class string) error {
		_, err := runtime.Exec(ctx, `INSERT INTO mcp_health_checks (server_id, ok, trigger, error_class, message, status_since)
			SELECT id, false, 'scheduled', $1, '', now() FROM mcp_servers`, class)
		return err
	}
	if err := insertCheck("unavailable"); err != nil {
		t.Fatal(err)
	}
	if err := insertCheck("tls"); err == nil {
		t.Fatal("the previous release's check accepted 'tls'")
	}

	// Up: the table exists, old checks keep their class, 'tls' is accepted and a
	// class that isn't text of a sane length is not.
	if _, err := provider.UpTo(ctx, 33); err != nil {
		t.Fatalf("up: %v", err)
	}
	regrantMigrationFixture(t, runtime)
	if !hasTable() {
		t.Fatal("Up did not create the table")
	}
	if got := scalar(`SELECT string_agg(error_class, ',') FROM mcp_health_checks`); got != "unavailable" {
		t.Errorf("classes after up = %s", got)
	}
	if err := insertCheck("tls"); err != nil {
		t.Fatalf("a tls check: %v", err)
	}
	if err := insertCheck(strings.Repeat("x", 65)); err == nil {
		t.Error("a 65-character class was accepted")
	}
	if _, err := runtime.Exec(ctx, `INSERT INTO mcp_health_checks (server_id, ok, trigger, error_class, status_since)
		SELECT id, true, 'scheduled', 'tls', now() FROM mcp_servers`); err == nil {
		t.Error("an ok check with an error class was accepted")
	}

	// The table's own rules: one row per server, certificate and key together,
	// a row only while it holds something, the sizes bounded, cascading.
	sha := strings.Repeat("a", 64)
	for name, sql := range map[string]string{
		"a certificate without a key":  `INSERT INTO mcp_server_tls (server_id, client_cert_pem, client_cert_sha256, client_not_after) SELECT id, 'x', '` + sha + `', now() FROM mcp_servers`,
		"a key without a certificate":  `INSERT INTO mcp_server_tls (server_id, client_key_cipher) SELECT id, '\x00' FROM mcp_servers`,
		"an empty row":                 `INSERT INTO mcp_server_tls (server_id) SELECT id FROM mcp_servers`,
		"a CA without its fingerprint": `INSERT INTO mcp_server_tls (server_id, ca_pem) SELECT id, 'x' FROM mcp_servers`,
		"a fingerprint that isn't one": `INSERT INTO mcp_server_tls (server_id, ca_pem, ca_sha256) SELECT id, 'x', 'ZZ' FROM mcp_servers`,
		"a 64 KiB and one CA":          `INSERT INTO mcp_server_tls (server_id, ca_pem, ca_sha256) SELECT id, repeat('x', 65537), '` + sha + `' FROM mcp_servers`,
	} {
		if _, err := runtime.Exec(ctx, sql); err == nil {
			t.Errorf("accepted %s", name)
		}
	}
	exec(`INSERT INTO mcp_server_tls (server_id, ca_pem, ca_sha256) SELECT id, 'x', '` + sha + `' FROM mcp_servers`)
	if _, err := runtime.Exec(ctx, `INSERT INTO mcp_server_tls (server_id, ca_pem, ca_sha256) SELECT id, 'x', '`+sha+`' FROM mcp_servers`); err == nil {
		t.Error("two rows for one server")
	}
	exec(`UPDATE mcp_server_tls SET client_cert_pem = 'x', client_key_cipher = '\x00', client_cert_sha256 = '` + sha + `', client_not_after = now()`)
	exec(`DELETE FROM mcp_servers`)
	if got := scalar(`SELECT count(*)::text FROM mcp_server_tls`); got != "0" {
		t.Errorf("rows after the server went = %s", got)
	}

	// Down: 'tls' checks become 'unavailable', the old check is back, the table
	// is gone.
	exec(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 's2', 'S', 'https://x.example/mcp' FROM teams`)
	if err := insertCheck("tls"); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, callTraceID); err != nil {
		t.Fatalf("down again: %v", err)
	}
	if got := scalar(`SELECT string_agg(error_class, ',' ORDER BY id) FROM mcp_health_checks`); got != "unavailable" {
		t.Errorf("classes after down = %s", got)
	}
	if err := insertCheck("tls"); err == nil {
		t.Error("the old check wasn't restored")
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatalf("up again: %v", err)
	}
	regrantMigrationFixture(t, runtime)
}
