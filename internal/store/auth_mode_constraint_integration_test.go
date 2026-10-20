package store_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// allAuthModes: none, static_header and oauth existed at v0.3.1; person_secret
// (00024) and machine_oauth (00025) are v0.3.2's.
var allAuthModes = []string{"none", "static_header", "oauth", "person_secret", "machine_oauth"}

// Three migrations of v0.3.2 touch the CHECK on mcp_servers.auth_mode or sit
// next to one that does: 00024 adds person_secret, 00025 machine_oauth and
// 00026 widens a different check (mcp_health_checks.error_class). Each of the
// first two reads the check as it stands in the catalog and ADDS its value
// (idempotently), and each Down removes only its own, so every mode survives
// whatever is applied or removed around it.
//
// What a Down does to a server whose mode it removes (documented here and in
// the migrations): it never refuses and never touches a server of another mode.
// A person_secret or machine_oauth server goes back to static_header when it
// still has a static credential of its own (a legacy header or parts), else to
// none: nothing but that credential is sent then, the same as the previous
// release does for a mode it doesn't know. The secrets themselves (people's keys,
// the machine client) are dropped with their tables, which is the data the
// removed feature owned.
func TestAuthModeConstraintAcceptsEveryMode(t *testing.T) {
	const (
		callTraceID  = 23 // v0.3.1's newest schema
		personSecret = 24
		machineOAuth = 25
		upstreamTLS  = 26
	)
	setup := func(t *testing.T) (ctx context.Context, provider *goose.Provider, exec func(string, ...any) error, must func(string, ...any), scalar func(string, ...any) string) {
		pool, _ := testutil.NewDB(t)
		ctx = context.Background()
		db := stdlib.OpenDBFromPool(pool)
		t.Cleanup(func() { _ = db.Close() })
		var err error
		if provider, err = goose.NewProvider(goose.DialectPostgres, db, migrations.FS); err != nil {
			t.Fatal(err)
		}
		exec = func(sql string, args ...any) error {
			_, err := pool.Exec(ctx, sql, args...)
			return err
		}
		must = func(sql string, args ...any) {
			t.Helper()
			if err := exec(sql, args...); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
		}
		scalar = func(sql string, args ...any) string {
			t.Helper()
			var out string
			if err := pool.QueryRow(ctx, sql, args...).Scan(&out); err != nil {
				t.Fatalf("%s: %v", sql, err)
			}
			return out
		}
		must(`INSERT INTO teams (slug, name) VALUES ('t', 'T')`)
		return
	}
	// accepted lists the modes the check lets a server have now, probing with an
	// update that is rolled back by being the same row: a failing UPDATE changes
	// nothing and a passing one is put back.
	accepted := func(t *testing.T, exec func(string, ...any) error, must func(string, ...any)) map[string]bool {
		t.Helper()
		must(`INSERT INTO mcp_servers (team_id, slug, name, url) SELECT id, 'probe', 'probe', 'https://probe.example/mcp' FROM teams`)
		defer must(`DELETE FROM mcp_servers WHERE slug = 'probe'`)
		out := map[string]bool{}
		for _, mode := range append(append([]string{}, allAuthModes...), "bogus", "") {
			out[mode] = exec(`UPDATE mcp_servers SET auth_mode = $1 WHERE slug = 'probe'`, mode) == nil
		}
		return out
	}
	want := func(t *testing.T, got map[string]bool, modes ...string) {
		t.Helper()
		in := map[string]bool{}
		for _, m := range modes {
			in[m] = true
		}
		for _, m := range append(append([]string{}, allAuthModes...), "bogus", "") {
			if got[m] != in[m] {
				t.Errorf("mode %q accepted = %v, want %v (accepting %v)", m, got[m], in[m], got)
			}
		}
	}
	// One server per mode, and the variants a Down has to tell apart.
	seed := func(t *testing.T, must func(string, ...any)) {
		t.Helper()
		for _, mode := range allAuthModes {
			must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, replace($1, '_', '-'), $1, 'https://x.example/mcp', $1 FROM teams`, mode)
		}
		must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode, auth_header_name, auth_value_cipher)
			SELECT id, 'machine-header', 'm', 'https://x.example/mcp', 'machine_oauth', 'X-Tenant', '\x00' FROM teams`)
		must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, 'machine-parts', 'm', 'https://x.example/mcp', 'machine_oauth' FROM teams`)
		must(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) SELECT id, 'secret-parts', 's', 'https://x.example/mcp', 'person_secret' FROM teams`)
		must(`INSERT INTO mcp_server_credentials (server_id, position, kind, name, value_cipher) SELECT id, 0, 'header', 'X-Tenant', '\x00' FROM mcp_servers WHERE slug IN ('machine-parts', 'secret-parts')`)
	}
	modes := func(t *testing.T, scalar func(string, ...any) string) string {
		t.Helper()
		return scalar(`SELECT string_agg(slug || '=' || auth_mode, ' ' ORDER BY slug COLLATE "C") FROM mcp_servers`)
	}

	t.Run("every mode at the newest schema", func(t *testing.T) {
		_, _, exec, must, scalar := setup(t)
		want(t, accepted(t, exec, must), allAuthModes...)
		seed(t, must)
		// A row of each mode can be written, read back and rewritten as another.
		for _, mode := range allAuthModes {
			if got := scalar(`SELECT auth_mode FROM mcp_servers WHERE slug = replace($1, '_', '-')`, mode); got != mode {
				t.Errorf("server %s has mode %q", mode, got)
			}
			for _, to := range allAuthModes {
				if err := exec(`UPDATE mcp_servers SET auth_mode = $1 WHERE slug = replace($2, '_', '-')`, to, mode); err != nil {
					t.Errorf("%s -> %s: %v", mode, to, err)
				}
				must(`UPDATE mcp_servers SET auth_mode = $1 WHERE slug = replace($1, '_', '-')`, mode)
			}
		}
		if exec(`UPDATE mcp_servers SET auth_mode = 'bogus' WHERE slug = 'none'`) == nil {
			t.Error("an unknown mode was accepted")
		}
		// The check is one constraint that names every mode.
		def := scalar(`SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c WHERE c.conrelid = 'mcp_servers'::regclass AND c.conname = 'mcp_servers_auth_mode_check'`)
		for _, mode := range allAuthModes {
			if !strings.Contains(def, "'"+mode+"'") {
				t.Errorf("the check %s does not name %s", def, mode)
			}
		}
		// The two secret modes' own rules still hold next to each other.
		if exec(`UPDATE mcp_servers SET auth_header_name = 'Authorization', auth_value_cipher = '\x00' WHERE slug = 'machine-oauth'`) == nil {
			t.Error("machine_oauth with a static Authorization header was accepted")
		}
		if exec(`UPDATE mcp_servers SET secret_placement = 'bearer', secret_name = 'X' WHERE slug = 'person-secret'`) == nil {
			t.Error("a bearer secret with a name was accepted")
		}
	})

	t.Run("down one at a time and up again, with servers in every mode", func(t *testing.T) {
		ctx, provider, exec, must, scalar := setup(t)
		seed(t, must)
		all := modes(t, scalar)

		// 00026 only widens the health check: no server changes and every mode stays.
		if _, err := provider.DownTo(ctx, machineOAuth); err != nil {
			t.Fatalf("down 00026: %v", err)
		}
		if got := modes(t, scalar); got != all {
			t.Errorf("servers after Down of 00026 = %s, want %s", got, all)
		}
		want(t, accepted(t, exec, must), allAuthModes...)

		// 00025 removes machine_oauth only: its servers become static_header when
		// they still have a credential of their own, else none; person_secret
		// servers and the others are untouched; person_secret is still accepted.
		if _, err := provider.DownTo(ctx, personSecret); err != nil {
			t.Fatalf("down 00025 with machine_oauth and person_secret servers: %v", err)
		}
		if got := scalar(`SELECT string_agg(slug || '=' || auth_mode, ' ' ORDER BY slug COLLATE "C") FROM mcp_servers WHERE slug LIKE 'machine%' OR slug LIKE 'person%' OR slug LIKE 'secret%'`); got !=
			"machine-header=static_header machine-oauth=none machine-parts=static_header person-secret=person_secret secret-parts=person_secret" {
			t.Errorf("servers after Down of 00025 = %s", got)
		}
		want(t, accepted(t, exec, must), "none", "static_header", "oauth", "person_secret")
		if exec(`UPDATE mcp_servers SET auth_mode = 'machine_oauth' WHERE slug = 'none'`) == nil {
			t.Error("Down of 00025 left machine_oauth allowed")
		}
		if scalar(`SELECT coalesce(to_regclass('mcp_server_machine_oauth')::text, '')`) != "" {
			t.Error("Down of 00025 left the machine client table")
		}
		if scalar(`SELECT count(*)::text FROM pg_constraint WHERE conname = 'mcp_servers_machine_single_credential'`) != "0" {
			t.Error("Down of 00025 left its constraint")
		}

		// 00024 removes person_secret only.
		if _, err := provider.DownTo(ctx, callTraceID); err != nil {
			t.Fatalf("down 00024: %v", err)
		}
		if got := scalar(`SELECT string_agg(slug || '=' || auth_mode, ' ' ORDER BY slug COLLATE "C") FROM mcp_servers WHERE slug LIKE 'person%' OR slug LIKE 'secret%'`); got != "person-secret=none secret-parts=static_header" {
			t.Errorf("servers after Down of 00024 = %s", got)
		}
		if got := scalar(`SELECT string_agg(slug || '=' || auth_mode, ' ' ORDER BY slug COLLATE "C") FROM mcp_servers WHERE slug IN ('none', 'static-header', 'oauth')`); got != "none=none oauth=oauth static-header=static_header" {
			t.Errorf("the v0.3.1 modes after the Downs = %s", got)
		}
		want(t, accepted(t, exec, must), "none", "static_header", "oauth")

		// Up one at a time: each adds its own mode to the check as it stands.
		step := func(version int64, accepts ...string) {
			t.Helper()
			if _, err := provider.UpByOne(ctx); err != nil {
				t.Fatalf("up to %d: %v", version, err)
			}
			if v, err := provider.GetDBVersion(ctx); err != nil || v != version {
				t.Fatalf("version = %d %v, want %d", v, err, version)
			}
			want(t, accepted(t, exec, must), accepts...)
		}
		step(personSecret, "none", "static_header", "oauth", "person_secret")
		step(machineOAuth, allAuthModes...)
		step(upstreamTLS, allAuthModes...)
		// And every Down again, now that the rows are only the v0.3.1 ones.
		if _, err := provider.DownTo(ctx, callTraceID); err != nil {
			t.Fatalf("down again: %v", err)
		}
		want(t, accepted(t, exec, must), "none", "static_header", "oauth")
	})

	// The check is added to, never rewritten from a list: 00024 and 00025's
	// blocks give a check with every mode applied in either order and twice.
	for name, order := range map[string][]string{
		"person_secret first": {"00024_person_secrets.sql", "00025_machine_oauth.sql", "00024_person_secrets.sql"},
		"machine_oauth first": {"00025_machine_oauth.sql", "00024_person_secrets.sql", "00025_machine_oauth.sql"},
	} {
		t.Run("the check applies in any order: "+name, func(t *testing.T) {
			ctx, provider, exec, must, scalar := setup(t)
			if _, err := provider.DownTo(ctx, callTraceID); err != nil {
				t.Fatalf("down: %v", err)
			}
			want(t, accepted(t, exec, must), "none", "static_header", "oauth")
			for _, file := range order {
				must(authModeBlock(t, file))
			}
			want(t, accepted(t, exec, must), allAuthModes...)
			if scalar(`SELECT count(*)::text FROM pg_constraint WHERE conrelid = 'mcp_servers'::regclass AND conname = 'mcp_servers_auth_mode_check'`) != "1" {
				t.Error("the check is not one constraint")
			}
		})
	}
}

// authModeBlock is the DO block of a migration's Up section that adds its mode
// to the auth_mode check (the first StatementBegin..StatementEnd of Up).
func authModeBlock(t *testing.T, file string) string {
	t.Helper()
	b, err := fs.ReadFile(migrations.FS, file)
	if err != nil {
		t.Fatal(err)
	}
	up := string(b)
	if i := strings.Index(up, "-- +goose Up"); i >= 0 {
		up = up[i:]
	}
	if i := strings.Index(up, "-- +goose Down"); i >= 0 {
		up = up[:i]
	}
	start := strings.Index(up, "-- +goose StatementBegin")
	end := strings.Index(up, "-- +goose StatementEnd")
	if start < 0 || end < start {
		t.Fatalf("%s has no check block in its Up section", file)
	}
	return up[start+len("-- +goose StatementBegin") : end]
}
