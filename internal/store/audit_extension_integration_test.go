package store_test

import (
	"context"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"testing"
)

func TestAuditExtensionManifestBoundary(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	ctx := context.Background()
	inspect := func(want bool) {
		t.Helper()
		s, err := store.InspectRoles(ctx, owner, role, true)
		if err != nil {
			t.Fatal(err)
		}
		if s.Safe() != want {
			t.Fatalf("safe=%v want %v: %s", s.Safe(), want, s.Detail())
		}
	}
	reconcile := func() {
		t.Helper()
		c, err := owner.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Release()
		if err := store.ReconcileRuntimeGrants(ctx, c.Conn(), role); err != nil {
			t.Fatal(err)
		}
	}
	inspect(true)
	roleDenied(t, runtime, `UPDATE omp_audit_ext.sinks SET cursor_seq=1`, "42501")
	roleDenied(t, runtime, `DELETE FROM omp_audit_ext.sinks`, "42501")
	roleDenied(t, runtime, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`, "42501")
	roleExec(t, runtime, `UPDATE omp_audit_ext.sinks SET url_cipher='\x01',secret_cipher='\x02',secret_previous_cipher=NULL`)
	roleDenied(t, runtime, `UPDATE omp_audit_ext.manifest SET privileges='{}'`, "42501")
	roleDenied(t, runtime, `SELECT omp_audit_ext.enable_checkpoints('0.15.0')`, "42501")
	roleExec(t, owner, `CREATE TABLE omp_audit_ext.unlisted(x int)`)
	inspect(false)
	c, err := owner.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	err = store.ReconcileRuntimeGrants(ctx, c.Conn(), role)
	c.Release()
	if err == nil {
		t.Fatal("reconciler accepted unlisted table")
	}
	roleExec(t, owner, `DROP TABLE omp_audit_ext.unlisted`)
	q := pgx.Identifier{role}.Sanitize()
	for _, grant := range []string{"UPDATE ON omp_audit_ext.sinks", "UPDATE(cursor_seq) ON omp_audit_ext.sinks", "UPDATE ON omp_audit_ext.sink_settings", "EXECUTE ON FUNCTION omp_audit_ext.set_sinks_enabled(boolean,text)", "UPDATE ON omp_audit_ext.checkpoint_keys", "UPDATE (state) ON omp_audit_ext.checkpoint_keys", "INSERT ON omp_audit_ext.manifest", "EXECUTE ON FUNCTION omp_audit_ext.enable_checkpoints(text)", "SELECT ON omp_audit_ext.checkpoint_keys WITH GRANT OPTION"} {
		// WITH GRANT OPTION belongs after the grantee.
		if grant == "SELECT ON omp_audit_ext.checkpoint_keys WITH GRANT OPTION" {
			roleExec(t, owner, "GRANT SELECT ON omp_audit_ext.checkpoint_keys TO "+q+" WITH GRANT OPTION")
		} else {
			roleExec(t, owner, "GRANT "+grant+" TO "+q)
		}
		inspect(false)
		reconcile()
		inspect(true)
	}
	roleExec(t, owner, `GRANT SELECT ON omp_audit_ext.manifest TO PUBLIC`)
	inspect(false)
	roleExec(t, owner, `REVOKE SELECT ON omp_audit_ext.manifest FROM PUBLIC`)
	inspect(true)
	// Future migrations extend the manifest without changing the inspector.
	roleExec(t, owner, `CREATE TABLE omp_audit_ext.future(x int,y int); INSERT INTO omp_audit_ext.manifest VALUES('table','omp_audit_ext.future',ARRAY['select','update(x)'])`)
	reconcile()
	inspect(true)
	roleDenied(t, runtime, `UPDATE omp_audit_ext.future SET y=1`, "42501")
	roleExec(t, runtime, `UPDATE omp_audit_ext.future SET x=1`)
}

func TestAuditExtensionInheritedPrivilege(t *testing.T) {
	_, owner, role := splitFixture(t)
	ctx := context.Background()
	_, admin := auxiliaryRole(t, owner, "ext_"+role)
	aux := pgx.Identifier{"ext_" + role}.Sanitize()
	runtime := pgx.Identifier{role}.Sanitize()
	roleExec(t, owner, "GRANT USAGE ON SCHEMA omp_audit_ext TO "+aux)
	roleExec(t, owner, "GRANT UPDATE(state) ON omp_audit_ext.checkpoint_keys TO "+aux)
	roleExec(t, admin, "GRANT "+aux+" TO "+runtime+" WITH INHERIT FALSE")
	defer roleExec(t, admin, "REVOKE "+aux+" FROM "+runtime)
	safety, err := store.InspectRoles(ctx, owner, role, true)
	if err != nil || safety.Safe() {
		t.Fatalf("NOINHERIT extension write missed: %v %s", err, safety.Detail())
	}
	c, err := owner.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Release()
	if err := store.ReconcileRuntimeGrants(ctx, c.Conn(), role); err == nil {
		t.Fatal("direct revoke hid inherited write")
	}
}
