package store_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestApprovalBindingKeyRuntimeBoundary(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	ctx := context.Background()
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_catalog.pg_proc p
 JOIN pg_catalog.pg_class c ON c.oid='omp_private.approval_binding_keys'::regclass
 WHERE p.oid='omp_private.omp_ensure_approval_binding_key(bytea)'::regprocedure
 AND p.prosecdef AND p.proconfig=ARRAY['search_path=pg_catalog, pg_temp'] AND p.proowner=c.relowner`); n != 1 {
		t.Fatal("bootstrap helper lacks the fixed-path owner-definer boundary")
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM pg_catalog.pg_trigger
 WHERE tgrelid='omp_private.approval_binding_keys'::regclass AND tgfoid='omp_private.approval_authority_changed()'::regprocedure`); n != 0 {
		t.Fatal("ciphertext rewrapping must not be an authority mutation")
	}
	candidate := bytes.Repeat([]byte{0x42}, 69)
	stored, err := dbgen.New(runtime).EnsureApprovalBindingKey(ctx, candidate)
	if err != nil || !bytes.Equal(stored, candidate) {
		t.Fatal("bootstrap failed", err)
	}
	other := bytes.Repeat([]byte{0x43}, 69)
	stored, err = dbgen.New(runtime).EnsureApprovalBindingKey(ctx, other)
	if err != nil || !bytes.Equal(stored, candidate) {
		t.Fatal("helper replaced root", err)
	}
	for _, sql := range []string{
		`INSERT INTO omp_private.approval_binding_keys VALUES(1,decode(repeat('42',69),'hex'))`,
		`UPDATE omp_private.approval_binding_keys SET id=1`,
		`DELETE FROM omp_private.approval_binding_keys`,
		`TRUNCATE omp_private.approval_binding_keys`,
	} {
		roleDenied(t, runtime, sql, "42501")
	}
	// Runtime's sole write privilege supports generic keyrotation's UPDATE.
	roleExec(t, runtime, `UPDATE omp_private.approval_binding_keys SET binding_key_cipher=$1 WHERE id=1`, other)
	roleDenied(t, runtime, `UPDATE omp_private.approval_binding_keys SET binding_key_cipher=NULL`, "23502")
	roleDenied(t, runtime, `UPDATE omp_private.approval_binding_keys SET binding_key_cipher='\x00'`, "23514")
	for _, sql := range []string{`DELETE FROM omp_private.approval_binding_keys`, `TRUNCATE omp_private.approval_binding_keys`, `UPDATE omp_private.approval_binding_keys SET id=2`} {
		roleDenied(t, owner, sql, "P0001")
	}
	outsider, _ := auxiliaryRole(t, owner, "binding_outsider_"+role)
	roleDenied(t, outsider, `SELECT omp_private.omp_ensure_approval_binding_key(decode(repeat('42',69),'hex'))`, "42501")

	// Reconciliation removes accidental direct table/identity privileges.
	roleExec(t, owner, "GRANT ALL ON omp_private.approval_binding_keys TO "+pgx.Identifier{role}.Sanitize())
	roleExec(t, owner, "GRANT UPDATE(id) ON omp_private.approval_binding_keys TO "+pgx.Identifier{role}.Sanitize())
	if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
		t.Fatal(err)
	}
	safety, err := store.InspectRoles(ctx, runtime, "", true)
	if err != nil || !safety.Safe() {
		t.Fatalf("unsafe reconciled root permissions: %+v %v", safety, err)
	}
	roleDenied(t, runtime, `UPDATE omp_private.approval_binding_keys SET id=1`, "42501")
}

func TestApprovalBindingKeyInheritedPrivilegesRejected(t *testing.T) {
	for _, grant := range []string{"INSERT", "UPDATE", "UPDATE(id)", "DELETE"} {
		t.Run(grant, func(t *testing.T) {
			runtime, owner, role := splitFixture(t)
			roleExec(t, owner, "GRANT "+grant+" ON omp_private.approval_binding_keys TO PUBLIC")
			safety, err := store.InspectRoles(context.Background(), runtime, "", true)
			if err != nil || safety.Safe() {
				t.Fatalf("unsafe root grant missed: %+v %v", safety, err)
			}
			if err := store.Migrate(context.Background(), owner, testutil.Logger(), role); err == nil {
				t.Fatal("unsafe inherited root grant accepted")
			}
		})
	}
}

func TestApprovalBindingKeyMigrationInvalidatesLegacyBindings(t *testing.T) {
	ctx := context.Background()
	var before int64
	runtime, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err := provider.UpTo(ctx, 40); err != nil {
			return err
		}
		if err := owner.QueryRow(ctx, `SELECT public.omp_current_approval_context()`).Scan(&before); err != nil {
			return err
		}
		roleExec(t, owner, `INSERT INTO approval_requests(rule_id,rule_revision,context_epoch,requester_kind,requester_id,gateway_id,server_id,capability_id,exposed_name,args_digest,binding_digest,capability_fingerprint,server_origin,expires_at,preview_cipher)
			SELECT gen_random_uuid(),1,$1,'user',gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),name,repeat('a',64),digest,repeat('c',64),'https://test.invalid',now()+interval '1 hour','legacy'::bytea
			FROM (VALUES ('pending',repeat('1',64)),('approved',repeat('2',64)),('denied',repeat('3',64))) AS legacy(name,digest)`, before)
		roleExec(t, owner, `UPDATE approval_requests SET status='approved',review_revision=2,decided_by=gen_random_uuid(),decided_at=now(),valid_until=now()+interval '15 minutes' WHERE exposed_name='approved'`)
		roleExec(t, owner, `UPDATE approval_requests SET status='denied',review_revision=2,decided_by=gen_random_uuid(),decided_at=now(),terminal_at=now() WHERE exposed_name='denied'`)
		return store.Migrate(ctx, owner, testutil.Logger(), role)
	})
	owner := testutil.OwnerPool(t, runtime)
	after := roleCount(t, runtime, `SELECT omp_private.omp_current_approval_context()`)
	if after <= before || roleCount(t, runtime, `SELECT count(*) FROM approval_requests WHERE context_epoch=omp_private.omp_current_approval_context()`) != 0 {
		t.Fatal("legacy binding survived root migration")
	}
	if roleCount(t, runtime, `SELECT count(*) FROM omp_private.approval_binding_keys`) != 0 {
		t.Fatal("DDL required a configured encryption key")
	}
	role := ""
	if owner != runtime {
		role = runtime.Config().ConnConfig.User
	}
	if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
		t.Fatal(err)
	}
	if roleCount(t, runtime, `SELECT omp_private.omp_current_approval_context()`) != after {
		t.Fatal("root migration invalidation repeated")
	}
}

func TestApprovalBindingKeyMigrationRejectsDifferentOwner(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	runtime, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		_, err = provider.UpTo(ctx, 40)
		return err
	})
	owner := testutil.OwnerPool(t, runtime)
	root, err := pgx.ParseConfig(testutil.DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	cfg := owner.Config().ConnConfig.Copy()
	cfg.User, cfg.Password = root.User, root.Password
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	raw, err := migrations.FS.ReadFile("00041_approval_binding_key.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(context.Background(), string(raw)); err == nil || !strings.Contains(err.Error(), "must be owned by the migration role") {
		t.Fatalf("inconsistent root ownership accepted: %v", err)
	}
}
