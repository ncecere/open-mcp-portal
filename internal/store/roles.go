package store

import (
	"context"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

// RoleDB is satisfied by pools, connections and transactions.
type RoleDB interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

var protectedFunctions = []string{
	"public.omp_purge_audit_log(integer,integer)",
	"public.omp_purge_mcp_calls(timestamp with time zone,integer,integer)",
	"public.omp_lock_approval_context(boolean)",
	"public.omp_current_approval_context()",
	"public.omp_ensure_approval_binding_key(bytea)",
}

// ValidateRoleName rejects names PostgreSQL would truncate, and embedded NULs.
// Names are looked up with parameters and quoted as identifiers for DDL.
func ValidateRoleName(role string) error {
	if role == "" || len(role) > 63 || strings.ContainsRune(role, 0) || !utf8.ValidString(role) {
		return fmt.Errorf("DB_RUNTIME_ROLE must be an existing role name of 1 to 63 bytes without NUL")
	}
	return nil
}

// RoleSafety reports actual catalog state, never connection strings.
type RoleSafety struct {
	Session, Effective string
	Problems           []string
}

func (r RoleSafety) Safe() bool { return len(r.Problems) == 0 }
func (r RoleSafety) Detail() string {
	prefix := fmt.Sprintf("session=%s effective=%s", r.Session, r.Effective)
	if r.Safe() {
		return prefix + ": restricted runtime privileges verified"
	}
	return prefix + ": " + strings.Join(r.Problems, "; ")
}

// InspectRoles checks both login and effective identities. An explicit target is
// for migration preflight/reconciliation, where the connection is the owner.
// privileges=false permits preflight before goose has installed the schema;
// role attributes, memberships and ownership are still checked then.
func InspectRoles(ctx context.Context, db RoleDB, target string, privileges bool) (RoleSafety, error) {
	var out RoleSafety
	if err := db.QueryRow(ctx, "SELECT session_user::text, current_user::text").Scan(&out.Session, &out.Effective); err != nil {
		return out, err
	}
	roots := []string{out.Session}
	if out.Effective != out.Session {
		roots = append(roots, out.Effective)
	}
	if target != "" {
		if err := ValidateRoleName(target); err != nil {
			return out, err
		}
		roots = []string{target}
	}
	// Deliberately include NOINHERIT membership, not just currently inherited
	// rights: SET ROLE can activate it. Conservative even with set_option=false.
	rows, err := db.Query(ctx, `WITH RECURSIVE reachable AS (
 SELECT oid, rolname FROM pg_catalog.pg_roles WHERE rolname = ANY($1::text[])
 UNION SELECT r.oid, r.rolname FROM reachable x
 JOIN pg_catalog.pg_auth_members m ON m.member = x.oid
 JOIN pg_catalog.pg_roles r ON r.oid = m.roleid
 ) SELECT r.oid, r.rolname,
 r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
 OR r.rolname IN ('pg_write_server_files','pg_read_server_files','pg_execute_server_program','pg_signal_backend','pg_checkpoint'),
 EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.member = r.oid AND m.admin_option)
 FROM reachable x JOIN pg_catalog.pg_roles r ON r.oid = x.oid`, roots)
	if err != nil {
		return out, err
	}
	type roleInfo struct {
		oid          uint32
		name         string
		admin, grant bool
	}
	var roles []roleInfo
	for rows.Next() {
		var r roleInfo
		if err := rows.Scan(&r.oid, &r.name, &r.admin, &r.grant); err != nil {
			rows.Close()
			return out, err
		}
		roles = append(roles, r)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(roles) == 0 {
		return out, fmt.Errorf("DB_RUNTIME_ROLE does not exist")
	}
	for _, r := range roles {
		if r.admin || r.grant {
			out.Problems = append(out.Problems, "administrative role rights: "+r.name)
		}
		var owns bool
		err := db.QueryRow(ctx, `SELECT
 EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = current_database() AND datdba = $1)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace WHERE nspowner = $1
 AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%')
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relowner = $1)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public' AND p.proowner = $1)`, r.oid).Scan(&owns)
		if err != nil {
			return out, err
		}
		if owns {
			out.Problems = append(out.Problems, "owns application objects (or can SET ROLE to owner): "+r.name)
		}
		if !privileges {
			continue
		}
		var create bool
		err = db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace
 WHERE nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'
 AND has_schema_privilege($1::oid, oid, 'CREATE')) OR has_database_privilege($1::oid, current_database(), 'CREATE')`, r.oid).Scan(&create)
		if err != nil {
			return out, err
		}
		if create {
			out.Problems = append(out.Problems, "CREATE privilege: "+r.name)
		}
		// has_any_column_privilege includes table-level and column-level UPDATE.
		for _, table := range []string{"public.audit_log", "public.mcp_calls"} {
			var write bool
			err := db.QueryRow(ctx, `SELECT has_any_column_privilege($1::oid,$2,'UPDATE')
    OR has_table_privilege($1::oid,$2,'DELETE') OR has_table_privilege($1::oid,$2,'TRUNCATE')
    OR has_table_privilege($1::oid,$2,'TRIGGER')`, r.oid, table).Scan(&write)
			if err != nil {
				return out, err
			}
			if write {
				out.Problems = append(out.Problems, "forbidden write privilege on "+table+": "+r.name)
			}
		}
		// Base and journal are read-only; only owner-definer functions append,
		// compact or fence. Runtime must not allocate/reset event sequence values.
		for _, table := range []string{"public.approval_context", "public.approval_context_events"} {
			var contextWrite bool
			if err := db.QueryRow(ctx, `SELECT has_any_column_privilege($1::oid,$2,'UPDATE')
 OR has_any_column_privilege($1::oid,$2,'INSERT')
 OR has_table_privilege($1::oid,$2,'DELETE,TRUNCATE,TRIGGER')`, r.oid, table).Scan(&contextWrite); err != nil {
				return out, err
			}
			if contextWrite {
				out.Problems = append(out.Problems, "forbidden write privilege on "+table+": "+r.name)
			}
		}
		// Only ciphertext-column UPDATE is legitimate for root rewrapping. An
		// INSERT grant would let runtime bypass the singleton bootstrap helper.
		var bindingWrite bool
		if err := db.QueryRow(ctx, `SELECT has_any_column_privilege($1::oid,'public.approval_binding_keys','INSERT')
 OR has_table_privilege($1::oid,'public.approval_binding_keys','UPDATE,DELETE,TRUNCATE,TRIGGER')
 OR has_column_privilege($1::oid,'public.approval_binding_keys','id','UPDATE')`, r.oid).Scan(&bindingWrite); err != nil {
			return out, err
		}
		if bindingWrite {
			out.Problems = append(out.Problems, "forbidden write privilege on public.approval_binding_keys: "+r.name)
		}
		var eventSequence bool
		if err := db.QueryRow(ctx, `SELECT has_sequence_privilege($1::oid,'public.approval_context_events_event_id_seq','USAGE,SELECT,UPDATE')`, r.oid).Scan(&eventSequence); err != nil {
			return out, err
		}
		if eventSequence {
			out.Problems = append(out.Problems, "forbidden approval event sequence privilege: "+r.name)
		}
		var options bool
		err = db.QueryRow(ctx, `SELECT
 EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace,
 LATERAL aclexplode(c.relacl) a WHERE n.nspname = 'public' AND a.is_grantable AND (a.grantee = 0 OR a.grantee = $1))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute at JOIN pg_catalog.pg_class c ON c.oid = at.attrelid
 JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace, LATERAL aclexplode(at.attacl) a
 WHERE n.nspname = 'public' AND a.is_grantable AND (a.grantee = 0 OR a.grantee = $1))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n, LATERAL aclexplode(n.nspacl) a
 WHERE n.nspname = 'public' AND a.is_grantable AND (a.grantee = 0 OR a.grantee = $1))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace,
 LATERAL aclexplode(p.proacl) a WHERE n.nspname = 'public' AND a.is_grantable AND (a.grantee = 0 OR a.grantee = $1))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_database d, LATERAL aclexplode(d.datacl) a
 WHERE d.datname = current_database() AND a.is_grantable AND (a.grantee = 0 OR a.grantee = $1))`, r.oid).Scan(&options)
		if err != nil {
			return out, err
		}
		if options {
			out.Problems = append(out.Problems, "grant options: "+r.name)
		}
		var destructive, gooseWrite bool
		err = db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'
 AND c.relkind IN ('r','p') AND has_table_privilege($1::oid,c.oid,'TRUNCATE,TRIGGER')),
 has_any_column_privilege($1::oid,'public.goose_db_version','UPDATE') OR has_any_column_privilege($1::oid,'public.goose_db_version','INSERT')
 OR has_table_privilege($1::oid,'public.goose_db_version','DELETE,TRUNCATE,TRIGGER')`, r.oid).Scan(&destructive, &gooseWrite)
		if err != nil {
			return out, err
		}
		if destructive {
			out.Problems = append(out.Problems, "TRUNCATE/TRIGGER privileges: "+r.name)
		}
		if gooseWrite {
			out.Problems = append(out.Problems, "migration version table is writable: "+r.name)
		}
	}
	if !privileges {
		return out, nil
	}
	// Legitimate rights are checked for the actual serving identities only, not
	// every reachable auxiliary role (NOINHERIT may lack them until SET ROLE).
	for _, name := range roots {
		var missing bool
		err := db.QueryRow(ctx, `SELECT NOT has_schema_privilege($1, 'public', 'USAGE') OR EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public' AND c.relkind IN ('r','p','v','m','f') AND
 (NOT has_table_privilege($1,c.oid,'SELECT') OR (c.relname NOT IN ('goose_db_version','approval_context','approval_context_events','approval_binding_keys') AND NOT has_table_privilege($1,c.oid,'INSERT'))
 OR (c.relname NOT IN ('audit_log','mcp_calls','goose_db_version','approval_context','approval_context_events','approval_binding_keys') AND
 (NOT has_table_privilege($1,c.oid,'UPDATE') OR NOT has_table_privilege($1,c.oid,'DELETE')))))
 OR NOT has_column_privilege($1,'public.approval_binding_keys','binding_key_cipher','UPDATE')
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname='public' AND c.relname <> 'approval_context_events_event_id_seq'
 AND CASE WHEN c.relkind='S' THEN NOT has_sequence_privilege($1,c.oid,'USAGE') ELSE false END)`, name).Scan(&missing)
		if err != nil {
			return out, err
		}
		if missing {
			out.Problems = append(out.Problems, "missing operational table/schema/sequence privileges: "+name)
		}
		for _, fn := range protectedFunctions {
			var exec, consistent, publicExec bool
			err := db.QueryRow(ctx, `SELECT has_function_privilege($1,$2,'EXECUTE'),
    (SELECT proowner FROM pg_catalog.pg_proc WHERE oid=$2::regprocedure) = ALL(
      SELECT relowner FROM pg_catalog.pg_class WHERE oid IN ('public.audit_log'::regclass,'public.mcp_calls'::regclass)),
    EXISTS (SELECT 1 FROM pg_catalog.pg_proc p, LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
      WHERE p.oid=$2::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')`, name, fn).Scan(&exec, &consistent, &publicExec)
			if err != nil {
				return out, err
			}
			if !exec || !consistent || publicExec {
				out.Problems = append(out.Problems, "unsafe or unavailable protected function: "+fn)
			}
		}
	}
	return out, nil
}

// ReconcileRuntimeGrants replaces direct privileges; inherited/PUBLIC hazards
// are detected, not silently 'fixed' with an ineffective direct REVOKE.
func ReconcileRuntimeGrants(ctx context.Context, conn *pgx.Conn, role string) error {
	if err := ValidateRoleName(role); err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		quoted := pgx.Identifier{role}.Sanitize()
		rows, err := tx.Query(ctx, `SELECT c.relname, c.relkind::text FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','f','S') ORDER BY c.relname`)
		if err != nil {
			return err
		}
		type relation struct{ name, kind string }
		var tables []relation
		for rows.Next() {
			var t relation
			if err := rows.Scan(&t.name, &t.kind); err != nil {
				rows.Close()
				return err
			}
			tables = append(tables, t)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		for _, t := range tables {
			ident := pgx.Identifier{"public", t.name}.Sanitize()
			object, grants := "TABLE", "SELECT, INSERT, UPDATE, DELETE"
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
			if _, err := tx.Exec(ctx, "REVOKE ALL PRIVILEGES ON "+object+" "+ident+" FROM "+quoted+" CASCADE"); err != nil {
				return err
			}
			// REVOKE table privileges does not remove column ACLs.
			if t.kind != "S" {
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
			}
			if grants != "" {
				if _, err := tx.Exec(ctx, "GRANT "+grants+" ON "+object+" "+ident+" TO "+quoted); err != nil {
					return err
				}
			}
		}
		if _, err := tx.Exec(ctx, "GRANT UPDATE (binding_key_cipher) ON TABLE public.approval_binding_keys TO "+quoted); err != nil {
			return err
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
		for _, fn := range protectedFunctions {
			if _, err := tx.Exec(ctx, "REVOKE ALL PRIVILEGES ON FUNCTION "+fn+" FROM "+quoted+" CASCADE"); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, "GRANT EXECUTE ON FUNCTION "+fn+" TO "+quoted); err != nil {
				return err
			}
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
