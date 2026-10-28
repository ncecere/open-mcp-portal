package store_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestCredentialScopesMigration(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	// Schema changes use the migration owner; compatibility writes below
	// deliberately remain on the genuinely authenticated runtime pool.
	db := stdlib.OpenDBFromPool(testutil.OwnerPool(t, pool))
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.DownTo(ctx, 28); err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	scalar := func(sql string, args ...any) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	u := scalar(`INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES ('test','old','old@example.com') RETURNING id::text`)
	team := scalar(`INSERT INTO teams(slug,name) VALUES ('old','Old') RETURNING id::text`)
	gateway := scalar(`INSERT INTO gateways(slug,name,owner_kind) VALUES ('old','Old','platform') RETURNING id::text`)
	sa := scalar(`INSERT INTO service_accounts(team_id,name) VALUES ($1,'old') RETURNING id::text`, team)
	// Exactly the original insert columns, as a previous binary would write.
	exec(`INSERT INTO api_keys(user_id,name,prefix,digest,expires_at) VALUES ($1,'old','omp_abcdefgh',$2,now()+interval '1 day')`, u, strings.Repeat("a", 64))
	exec(`INSERT INTO service_account_keys(service_account_id,name,prefix,digest,expires_at) VALUES ($1,'old','omp_sa_abcdefgh',$2,now()+interval '1 day')`, sa, strings.Repeat("b", 64))
	exec(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2)`, gateway, u)
	exec(`INSERT INTO oauth_grants(user_id,gateway_id,client_id,client_kind,client_name,resource) VALUES ($1,$2,'old','registered','Old','http://localhost/mcp/old')`, u, gateway)
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.Regrant(t, pool)
	for _, table := range []string{"api_keys", "service_accounts", "service_account_keys", "oauth_grants", "gateway_grants"} {
		if got := scalar(fmt.Sprintf(`SELECT count(*)::text FROM %s WHERE tool_scope IS NULL`, table)); got != "1" {
			t.Fatalf("%s existing row changed: %s", table, got)
		}
		exec(fmt.Sprintf(`UPDATE %s SET tool_scope='{}'::jsonb`, table))
		if got := scalar(fmt.Sprintf(`SELECT tool_scope::text FROM %s`, table)); got != "{}" {
			t.Fatalf("%s cannot hold deny-all: %s", table, got)
		}
		exec(fmt.Sprintf(`UPDATE %s SET tool_scope=NULL`, table))
	}
	// Old inserts still work against the expanded schema and remain unrestricted.
	exec(`INSERT INTO api_keys(user_id,name,prefix,digest,expires_at) VALUES ($1,'new old binary','omp_ijklmnop',$2,now()+interval '1 day')`, u, strings.Repeat("c", 64))
	if got := scalar(`SELECT count(*)::text FROM api_keys WHERE tool_scope IS NULL`); got != "2" {
		t.Fatalf("old binary inserts: %s", got)
	}
	// The widened reason check is additive; reversal keeps revocation rather
	// than resurrecting grants while forgetting their new reason.
	exec(`UPDATE oauth_grants SET revoked_at=now(),revoked_reason='scope_changed'`)
	if _, err := provider.DownTo(ctx, 28); err != nil {
		t.Fatal(err)
	}
	if got := scalar(`SELECT revoked_reason FROM oauth_grants WHERE revoked_at IS NOT NULL`); got != "client" {
		t.Fatalf("rollback revocation: %s", got)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.Regrant(t, pool)
}
