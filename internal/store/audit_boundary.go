package store

import (
	"context"
	"github.com/jackc/pgx/v5"
)

// Historical schema fixtures have no audit schema; they keep their original
// grants. Once present, all of omp_audit is a protected owner boundary.
func inspectAuditBoundary(ctx context.Context, db RoleDB, role string, required bool, out *RoleSafety) error {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT to_regnamespace('omp_audit') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	var unsafe bool
	err := db.QueryRow(ctx, `WITH owner AS (SELECT relowner oid FROM pg_catalog.pg_class WHERE oid='public.audit_log'::regclass)
 SELECT ($2 AND NOT has_schema_privilege($1,'omp_audit','USAGE')) OR has_schema_privilege($1,'omp_audit','CREATE')
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n,owner o WHERE n.nspname='omp_audit' AND n.nspowner<>o.oid)
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,owner o WHERE n.nspname='omp_audit' AND c.relkind IN ('r','p','v','m','f','S') AND
 (c.relowner<>o.oid OR c.relkind<>'r' OR c.relname NOT IN ('state','chain') OR ($2 AND NOT has_table_privilege($1,c.oid,'SELECT')) OR has_table_privilege($1,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER,REFERENCES') OR has_any_column_privilege($1,c.oid,'INSERT,UPDATE,REFERENCES')))
 OR (SELECT count(*) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='omp_audit' AND c.relkind='r')<>2
 OR EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace,owner o WHERE n.nspname='omp_audit' AND
 (p.proowner<>o.oid OR NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp','TimeZone=UTC'],false)
 OR (p.oid=to_regprocedure('omp_audit.seal_batch(text,jsonb)') AND (NOT p.prosecdef OR ($2 AND NOT has_function_privilege($1,p.oid,'EXECUTE'))))
 OR (p.oid<>to_regprocedure('omp_audit.seal_batch(text,jsonb)') AND has_function_privilege($1,p.oid,'EXECUTE'))
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc WHERE oid=to_regprocedure('omp_audit.seal_batch(text,jsonb)'))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid='public.audit_log'::regclass AND tgname='audit_log_stream_stamp' AND tgfoid=to_regprocedure('omp_audit.stamp()') AND tgtype=7 AND tgenabled IN ('O','A'))
 OR NOT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=to_regclass('omp_audit.chain') AND tgname='chain_append_only' AND tgfoid=to_regprocedure('omp_audit.append_only()') AND tgtype=27 AND tgenabled IN ('O','A'))`, role, required).Scan(&unsafe)
	if err != nil {
		return err
	}
	if unsafe {
		out.Problems = append(out.Problems, "unsafe protected audit schema/function boundary: "+role)
	}
	return nil
}

func reconcileAuditGrants(ctx context.Context, tx pgx.Tx, quoted string) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT to_regnamespace('omp_audit') IS NOT NULL`).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return nil
	}
	for _, q := range []string{
		"REVOKE ALL ON SCHEMA omp_audit FROM " + quoted + " CASCADE",
		"GRANT USAGE ON SCHEMA omp_audit TO " + quoted,
		"REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit FROM " + quoted + " CASCADE",
		"GRANT SELECT ON ALL TABLES IN SCHEMA omp_audit TO " + quoted,
		"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit FROM " + quoted + " CASCADE",
		"GRANT EXECUTE ON FUNCTION omp_audit.seal_batch(text,jsonb) TO " + quoted,
	} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	// Column ACLs survive table-level REVOKE.
	rows, err := tx.Query(ctx, `SELECT c.relname,a.attname FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class c ON c.oid=a.attrelid JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='omp_audit' AND a.attnum>0 AND NOT a.attisdropped AND a.attacl IS NOT NULL`)
	if err != nil {
		return err
	}
	var commands []string
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			rows.Close()
			return err
		}
		c := pgx.Identifier{col}.Sanitize()
		commands = append(commands, "REVOKE SELECT ("+c+"), INSERT ("+c+"), UPDATE ("+c+"), REFERENCES ("+c+") ON "+pgx.Identifier{"omp_audit", table}.Sanitize()+" FROM "+quoted+" CASCADE")
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, q := range commands {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}
