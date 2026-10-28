package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/apikeys"
	"github.com/ncecere/open-mcp-portal/internal/serviceaccounts"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestPlatformRetirementUpgradeAndOldReplicaFences(t *testing.T) {
	runtime, _ := newHistoricalDB(t, 33)
	owner := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(owner)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	// Start before retirement; its forward-only fences are never rolled back.
	must := func(sql string, args ...any) {
		t.Helper()
		if _, err := runtime.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	scalar := func(sql string) string {
		t.Helper()
		var out string
		if err := runtime.QueryRow(ctx, sql).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	must(`INSERT INTO teams(slug,name) VALUES ('retirement','Retirement')`)
	must(`INSERT INTO agent_platforms(name,issuer,jwks_url,audience) VALUES ('Old platform','https://old.example','https://old.example/jwks','https://portal.example')`)
	must(`INSERT INTO service_accounts(team_id,name,role,relay_platform_id,relay_marked_at)
 SELECT t.id,'legacy','editor',p.id,now() FROM teams t CROSS JOIN agent_platforms p`)
	must(`INSERT INTO service_accounts(team_id,name,role) SELECT id,'ordinary','editor' FROM teams`)
	pepper := []byte(strings.Repeat("p", 32))
	oldKey := serviceaccounts.KeyPrefix + strings.Repeat("a", 43)
	ordinaryKey := serviceaccounts.KeyPrefix + strings.Repeat("b", 43)
	for name, key := range map[string]string{"legacy": oldKey, "ordinary": ordinaryKey} {
		must(`INSERT INTO service_account_keys(service_account_id,name,prefix,digest,expires_at)
   SELECT id,'key',$2,$3,$4 FROM service_accounts WHERE name=$1`, name, key[:15], apikeys.Digest(pepper, key), time.Now().Add(time.Hour))
	}
	must(`INSERT INTO mcp_calls(method,gateway_id,gateway_slug,gateway_name,outcome,principal_kind,service_account_id,agent_id,agent_name,via_platform_name,person_present)
 SELECT 'tools/call',gen_random_uuid(),'old','Old','ok','service_account',id,'agent-history','Historical agent','Old platform',true FROM service_accounts WHERE name='legacy'`)
	auth := serviceaccounts.New(runtime, pepper, nil)
	if _, err := auth.Authenticate(ctx, ordinaryKey); err != nil {
		t.Fatalf("ordinary key before upgrade: %v", err)
	}
	// New auth independently rejects marked relays even before migration.
	if _, err := auth.Authenticate(ctx, oldKey); err != serviceaccounts.ErrInvalid {
		t.Fatalf("marked account authenticated before migration: %v", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	testutil.Regrant(t, runtime)
	if got := scalar(`SELECT enabled::text FROM agent_platforms`); got != "false" {
		t.Fatal(got)
	}
	if got := scalar(`SELECT enabled::text||':'||(relay_platform_id IS NOT NULL)::text FROM service_accounts WHERE name='legacy'`); got != "false:true" {
		t.Fatal(got)
	}
	if got := scalar(`SELECT count(*)::text FROM service_account_keys k JOIN service_accounts a ON a.id=k.service_account_id WHERE a.name='legacy' AND k.revoked_at IS NOT NULL`); got != "1" {
		t.Fatal(got)
	}
	if _, err := auth.Authenticate(ctx, oldKey); err != serviceaccounts.ErrInvalid {
		t.Fatalf("old key after upgrade: %v", err)
	}
	if _, err := auth.Authenticate(ctx, ordinaryKey); err != nil {
		t.Fatalf("ordinary key after upgrade: %v", err)
	}
	if got := scalar(`SELECT count(*)::text FROM mcp_calls WHERE agent_id='agent-history' AND agent_name='Historical agent' AND person_present`); got != "1" {
		t.Fatal("history lost")
	}
	audit := scalar(`SELECT metadata::text FROM audit_log WHERE action='agent_platform.retire' AND actor_kind='system' ORDER BY id DESC LIMIT 1`)
	for _, want := range []string{`"platformCount": 1`, `"accountCount": 1`, `"revokedKeyCount": 1`, scalar(`SELECT id::text FROM service_accounts WHERE name='legacy'`)} {
		if !strings.Contains(audit, want) {
			t.Fatalf("missing audit %s in %s", want, audit)
		}
	}
	for _, secret := range []string{oldKey, ordinaryKey, apikeys.Digest(pepper, oldKey)} {
		if strings.Contains(audit, secret) {
			t.Fatal("retirement audit exposed credential")
		}
	}
	// Run as the authenticated runtime role too: old SQL operations cannot undo
	// retirement. Null-mark ordinary accounts still work normally.
	for _, sql := range []string{
		`INSERT INTO agent_platforms(name,issuer,jwks_url,audience) VALUES ('New','https://new.example','https://new.example/jwks','portal')`,
		`UPDATE agent_platforms SET enabled=true`,
		`UPDATE service_accounts SET enabled=true WHERE name='legacy'`,
		`UPDATE service_accounts SET relay_platform_id=NULL WHERE name='legacy'`,
		`UPDATE service_accounts SET relay_platform_id=gen_random_uuid() WHERE name='legacy'`,
		`UPDATE service_accounts SET relay_platform_id=(SELECT id FROM agent_platforms) WHERE name='ordinary'`,
		`INSERT INTO service_accounts(team_id,name,role,relay_platform_id) SELECT t.id,'new-relay','member',p.id FROM teams t CROSS JOIN agent_platforms p`,
		`UPDATE service_account_keys SET revoked_at=NULL WHERE service_account_id=(SELECT id FROM service_accounts WHERE name='legacy')`,
		`INSERT INTO service_account_keys(service_account_id,name,prefix,digest,expires_at) SELECT id,'new','prefix','digest',now()+interval '1 hour' FROM service_accounts WHERE name='legacy'`,
		`DELETE FROM agent_platforms`, // ON DELETE SET NULL cannot clear a retired mark.
	} {
		_, err := runtime.Exec(ctx, sql)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Errorf("old replica operation was not fenced (23514): %s: %v", sql, err)
		}
	}
	if _, err := runtime.Exec(ctx, `UPDATE service_accounts SET enabled=false WHERE name='ordinary'; UPDATE service_accounts SET enabled=true WHERE name='ordinary'`); err != nil {
		t.Fatal(err)
	}
	// Exercise 34's actual Down SQL: it is a security no-op, not a route to
	// restore old authority. Keep the Goose ledger truthful instead of claiming
	// that forward-only 34/35/36 have been rolled back to schema 33.
	raw, err := migrations.FS.ReadFile("00034_retire_agent_platforms.sql")
	if err != nil {
		t.Fatal(err)
	}
	_, down, ok := strings.Cut(string(raw), "-- +goose Down")
	if !ok {
		t.Fatal("retirement migration has no Down")
	}
	if _, err := owner.Exec(ctx, down); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Exec(ctx, `UPDATE service_accounts SET enabled=true WHERE name='legacy'`); err == nil {
		t.Fatal("Down removed retirement fence")
	}
}
