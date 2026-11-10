package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ReconcileRuntimeGrants replaces direct privileges; inherited/PUBLIC hazards
// are detected, not silently 'fixed' with an ineffective direct REVOKE.
func ReconcileRuntimeGrants(ctx context.Context, conn *pgx.Conn, role string) error {
	if err := ValidateRoleName(role); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		layout, err := inspectApprovalLayout(ctx, tx)
		if err != nil {
			return err
		}
		quoted := pgx.Identifier{role}.Sanitize()
		tables, err := runtimeRelations(ctx, tx)
		if err != nil {
			return err
		}
		for _, t := range tables {
			if err := reconcileRelation(ctx, tx, layout, t, quoted); err != nil {
				return err
			}
		}
		if err := reconcileContainerGrants(ctx, tx, layout, quoted); err != nil {
			return err
		}
		if err := reconcileProtectedFunctions(ctx, tx, layout, quoted); err != nil {
			return err
		}
		if err := reconcileAuditGrants(ctx, tx, quoted); err != nil {
			return err
		}
		if err := reconcileAuditExtension(ctx, tx, quoted); err != nil {
			return err
		}
		safety, err := InspectRoles(ctx, tx, role, true)
		if err != nil {
			return err
		}
		if !safety.Safe() {
			return fmt.Errorf("unsafe split database roles: %s", safety.Detail())
		}
		return nil
	})
}

// runtimeRelation is a table, view or sequence the runtime role's direct
// privileges are replaced on.
type runtimeRelation struct{ schema, name, kind string }

func runtimeRelations(ctx context.Context, tx pgx.Tx) ([]runtimeRelation, error) {
	rows, err := tx.Query(ctx, `SELECT n.nspname, c.relname, c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','omp_private') AND c.relkind IN ('r','p','v','m','f','S') ORDER BY n.nspname,c.relname`)
	if err != nil {
		return nil, err
	}
	var tables []runtimeRelation
	for rows.Next() {
		var t runtimeRelation
		if err := rows.Scan(&t.schema, &t.name, &t.kind); err != nil {
			rows.Close()
			return nil, err
		}
		tables = append(tables, t)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return tables, nil
}

// runtimeRelationGrants names the object kind and the privileges the runtime
// role gets on a relation ("": none). An unknown relation in the private
// approval schema is an error.
func runtimeRelationGrants(layout approvalLayout, t runtimeRelation) (object, grants string, err error) {
	object, grants = "TABLE", "SELECT, INSERT, UPDATE, DELETE"
	if t.schema == "omp_private" && !layout.protected(t.name) && t.name != "approval_context_events_event_id_seq" {
		return "", "", fmt.Errorf("unexpected private approval relation: %s", t.name)
	}
	if t.kind == "S" {
		object, grants = "SEQUENCE", "USAGE"
		if t.name == "approval_context_events_event_id_seq" {
			grants = ""
		}
	} else if t.name == "audit_log" || t.name == "mcp_calls" {
		grants = "SELECT, INSERT"
	} else if t.name == "goose_db_version" || t.name == "approval_context" || t.name == "approval_context_events" || t.name == "approval_binding_keys" {
		grants = "SELECT"
	}
	return object, grants, nil
}

// reconcileRelation replaces the role's direct privileges on one relation:
// everything is revoked (column privileges too), then the intended set granted.
func reconcileRelation(ctx context.Context, tx pgx.Tx, layout approvalLayout, t runtimeRelation, quoted string) error {
	ident := pgx.Identifier{t.schema, t.name}.Sanitize()
	object, grants, err := runtimeRelationGrants(layout, t)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "REVOKE ALL PRIVILEGES ON "+object+" "+ident+" FROM "+quoted+" CASCADE"); err != nil {
		return err
	}
	// REVOKE table privileges does not remove column ACLs.
	if t.kind != "S" {
		if err := revokeColumnPrivileges(ctx, tx, ident, quoted); err != nil {
			return err
		}
	}
	if grants != "" {
		if _, err := tx.Exec(ctx, "GRANT "+grants+" ON "+object+" "+ident+" TO "+quoted); err != nil {
			return err
		}
	}
	return nil
}

// revokeColumnPrivileges revokes the role's privileges on each column of the
// relation that has a column ACL.
func revokeColumnPrivileges(ctx context.Context, tx pgx.Tx, ident, quoted string) error {
	cols, err := tx.Query(ctx, `SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped AND attacl IS NOT NULL`, ident)
	if err != nil {
		return err
	}
	var names []string
	for cols.Next() {
		var name string
		if err := cols.Scan(&name); err != nil {
			cols.Close()
			return err
		}
		names = append(names, pgx.Identifier{name}.Sanitize())
	}
	err = cols.Err()
	cols.Close()
	if err != nil {
		return err
	}
	for _, col := range names {
		if _, err := tx.Exec(ctx, "REVOKE SELECT ("+col+"), INSERT ("+col+"), UPDATE ("+col+"), REFERENCES ("+col+") ON "+ident+" FROM "+quoted+" CASCADE"); err != nil {
			return err
		}
	}
	return nil
}

// reconcileContainerGrants replaces the role's privileges on the approval
// binding key column, the schemas, the database and the schemas' functions.
func reconcileContainerGrants(ctx context.Context, tx pgx.Tx, layout approvalLayout, quoted string) error {
	if layout.binding {
		if _, err := tx.Exec(ctx, "GRANT UPDATE (binding_key_cipher) ON TABLE "+layout.schema+".approval_binding_keys TO "+quoted); err != nil {
			return err
		}
	}
	if layout.schema == "omp_private" {
		for _, sql := range []string{"REVOKE ALL ON SCHEMA omp_private FROM " + quoted + " CASCADE", "GRANT USAGE ON SCHEMA omp_private TO " + quoted, "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_private FROM " + quoted + " CASCADE"} {
			if _, err := tx.Exec(ctx, sql); err != nil {
				return err
			}
		}
	}
	var database string
	if err := tx.QueryRow(ctx, "SELECT current_database()").Scan(&database); err != nil {
		return err
	}
	for _, sql := range []string{
		"REVOKE ALL PRIVILEGES ON SCHEMA public FROM " + quoted + " CASCADE",
		"GRANT USAGE ON SCHEMA public TO " + quoted,
		"REVOKE ALL PRIVILEGES ON DATABASE " + pgx.Identifier{database}.Sanitize() + " FROM " + quoted + " CASCADE",
		"GRANT CONNECT ON DATABASE " + pgx.Identifier{database}.Sanitize() + " TO " + quoted,
		"REVOKE ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public FROM " + quoted + " CASCADE",
	} {
		if _, err := tx.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

// reconcileProtectedFunctions leaves the role with EXECUTE, and nothing else,
// on each protected function.
func reconcileProtectedFunctions(ctx context.Context, tx pgx.Tx, layout approvalLayout, quoted string) error {
	for _, fn := range layout.functions() {
		if _, err := tx.Exec(ctx, "REVOKE ALL PRIVILEGES ON FUNCTION "+fn+" FROM "+quoted+" CASCADE"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+fn+" TO "+quoted); err != nil {
			return err
		}
	}
	return nil
}
