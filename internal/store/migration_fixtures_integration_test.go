package store_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

// Historical fixtures start at a real old schema, never by rolling back the
// forward-only approval migrations (35/36) or retirement fences (34). Each test
// exercises its reversible migrations before upgrading to the current head.
func newHistoricalDB(t testing.TB, version int64) (*pgxpool.Pool, string) {
	t.Helper()
	if version >= 34 {
		t.Fatal("historical fixture must start before forward-only migrations")
	}
	return testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err := provider.UpTo(ctx, version); err != nil {
			return err
		}
		return grantHistoricalSchema(ctx, owner, role)
	})
}

// Recreated historical tables need runtime grants too. Production reconciliation
// requires current functions/tables, so use the old schema's table boundary until
// the final upgrade, then exercise the real production reconciliation again.
func regrantMigrationFixture(t testing.TB, runtime *pgxpool.Pool) {
	t.Helper()
	owner := testutil.OwnerPool(t, runtime)
	var approvalsExist bool
	if err := owner.QueryRow(context.Background(), `SELECT to_regclass('public.approval_context') IS NOT NULL`).Scan(&approvalsExist); err != nil {
		t.Fatal(err)
	}
	if approvalsExist {
		testutil.Regrant(t, runtime)
		return
	}
	role := ""
	if runtime != owner {
		role = runtime.Config().ConnConfig.User
	}
	if err := grantHistoricalSchema(context.Background(), owner, role); err != nil {
		t.Fatal(err)
	}
}

func grantHistoricalSchema(ctx context.Context, owner *pgxpool.Pool, role string) error {
	if role == "" {
		return nil
	}
	// No owner membership, SET ROLE, DDL or append-only mutation privileges are
	// given to the authenticated runtime connection, even on these old schemas.
	quoted := pgx.Identifier{role}.Sanitize()
	return pgx.BeginFunc(ctx, owner, func(tx pgx.Tx) error {
		for _, sql := range []string{
			"GRANT USAGE ON SCHEMA public TO " + quoted,
			"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO " + quoted,
			"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO " + quoted,
			"REVOKE UPDATE, DELETE ON audit_log, mcp_calls FROM " + quoted,
			"REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM " + quoted,
		} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
		return nil
	})
}
