package store

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
)

type auditExtensionObject struct {
	kind, identity string
	privileges     []string
	oid            uint32
	columns        []string
}

// Catalog identity and trust are checked independently of the migration-owned
// policy. The manifest may authorize operations, never ownership or delegation.
func auditExtensionManifest(ctx context.Context, db RoleDB) ([]auditExtensionObject, error) {
	var exists, expected bool
	if err := db.QueryRow(ctx, `SELECT to_regnamespace('omp_audit_ext') IS NOT NULL,coalesce(max(version_id),0)>=63 FROM public.goose_db_version WHERE is_applied`).Scan(&exists, &expected); err != nil {
		return nil, err
	}
	if !exists {
		if expected {
			return nil, fmt.Errorf("missing protected audit extension schema")
		}
		return nil, nil
	}
	var bad bool
	if err := db.QueryRow(ctx, `WITH owner AS (SELECT relowner oid FROM pg_class WHERE oid='public.audit_log'::regclass)
 SELECT EXISTS(SELECT 1 FROM pg_namespace n,owner o WHERE n.nspname='omp_audit_ext' AND (n.nspowner<>o.oid OR EXISTS(SELECT 1 FROM aclexplode(n.nspacl) a WHERE a.grantee=0)))
 OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace,owner o WHERE n.nspname='omp_audit_ext' AND c.relkind NOT IN ('i','I','t') AND
 (c.relkind<>'r' OR c.relowner<>o.oid OR NOT EXISTS(SELECT 1 FROM omp_audit_ext.manifest m WHERE m.kind='table' AND m.identity=c.oid::regclass::text)
 OR EXISTS(SELECT 1 FROM aclexplode(c.relacl) a WHERE a.grantee=0)
 OR EXISTS(SELECT 1 FROM pg_attribute at,LATERAL aclexplode(at.attacl) a WHERE at.attrelid=c.oid AND a.grantee=0)))
 OR EXISTS(SELECT 1 FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace,owner o WHERE n.nspname='omp_audit_ext' AND
 (p.proowner<>o.oid OR NOT p.prosecdef OR p.prokind<>'f' OR NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp','TimeZone=UTC'],false)
 OR NOT EXISTS(SELECT 1 FROM omp_audit_ext.manifest m WHERE m.kind='function' AND m.identity=p.oid::regprocedure::text)
 OR EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0)))`).Scan(&bad); err != nil {
		return nil, err
	}
	if bad {
		return nil, fmt.Errorf("unsafe audit extension catalog/owner/PUBLIC boundary")
	}
	rows, err := db.Query(ctx, `SELECT kind,identity,privileges FROM omp_audit_ext.manifest ORDER BY kind,identity`)
	if err != nil {
		return nil, err
	}
	objects, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (auditExtensionObject, error) {
		var o auditExtensionObject
		e := r.Scan(&o.kind, &o.identity, &o.privileges)
		return o, e
	})
	if err != nil {
		return nil, err
	}
	for i := range objects {
		o := &objects[i]
		if !strings.HasPrefix(o.identity, "omp_audit_ext.") || !slices.IsSorted(o.privileges) || len(slices.Compact(slices.Clone(o.privileges))) != len(o.privileges) {
			return nil, fmt.Errorf("invalid audit extension manifest: %s", o.identity)
		}
		switch o.kind {
		case "table":
			if err := db.QueryRow(ctx, `SELECT c.oid,ARRAY(SELECT attname::text FROM pg_attribute WHERE attrelid=c.oid AND attnum>0 AND NOT attisdropped ORDER BY attnum) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid=to_regclass($1) AND n.nspname='omp_audit_ext' AND c.relkind='r' AND c.oid::regclass::text=$1`, o.identity).Scan(&o.oid, &o.columns); err != nil {
				return nil, err
			}
			for _, p := range o.privileges {
				if p == "select" {
					continue
				}
				if !strings.HasPrefix(p, "update(") || !strings.HasSuffix(p, ")") || !slices.Contains(o.columns, strings.TrimSuffix(strings.TrimPrefix(p, "update("), ")")) {
					return nil, fmt.Errorf("invalid table manifest privilege: %s", p)
				}
			}
		case "function":
			if err := db.QueryRow(ctx, `SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE p.oid=to_regprocedure($1) AND n.nspname='omp_audit_ext' AND p.oid::regprocedure::text=$1`, o.identity).Scan(&o.oid); err != nil {
				return nil, err
			}
			if len(o.privileges) > 1 || (len(o.privileges) == 1 && o.privileges[0] != "execute") {
				return nil, fmt.Errorf("invalid function manifest privilege")
			}
		default:
			return nil, fmt.Errorf("invalid manifest object kind")
		}
	}
	return objects, nil
}

func inspectAuditExtension(ctx context.Context, db RoleDB, role string, required bool, out *RoleSafety) error {
	objects, err := auditExtensionManifest(ctx, db)
	if err != nil {
		out.Problems = append(out.Problems, err.Error())
		return nil
	}
	if objects == nil {
		return nil
	}
	var bad bool
	if err := db.QueryRow(ctx, `SELECT has_schema_privilege($1,'omp_audit_ext','CREATE') OR ($2 AND NOT has_schema_privilege($1,'omp_audit_ext','USAGE'))`, role, required).Scan(&bad); err != nil {
		return err
	}
	if bad {
		out.Problems = append(out.Problems, "unsafe audit extension schema privileges: "+role)
	}
	for _, o := range objects {
		if o.kind == "function" {
			if err := db.QueryRow(ctx, `SELECT has_function_privilege($1,$2::oid,'EXECUTE')`, role, o.oid).Scan(&bad); err != nil {
				return err
			}
			allowed := slices.Contains(o.privileges, "execute")
			if (bad && !allowed) || (required && allowed && !bad) {
				out.Problems = append(out.Problems, "audit extension function privilege mismatch: "+o.identity)
			}
			continue
		}
		for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER", "MAINTAIN"} {
			if err := db.QueryRow(ctx, `SELECT has_table_privilege($1,$2::oid,$3)`, role, o.oid, priv).Scan(&bad); err != nil {
				return err
			}
			allowed := priv == "SELECT" && slices.Contains(o.privileges, "select")
			if (bad && !allowed) || (required && allowed && !bad) {
				out.Problems = append(out.Problems, "audit extension table privilege mismatch: "+o.identity+" "+priv)
			}
		}
		for _, col := range o.columns {
			for _, priv := range []string{"SELECT", "INSERT", "UPDATE", "REFERENCES"} {
				if err := db.QueryRow(ctx, `SELECT has_column_privilege($1,$2::oid,$3,$4)`, role, o.oid, col, priv).Scan(&bad); err != nil {
					return err
				}
				allowed := (priv == "SELECT" && slices.Contains(o.privileges, "select")) || (priv == "UPDATE" && slices.Contains(o.privileges, "update("+col+")"))
				if (bad && !allowed) || (required && allowed && !bad) {
					out.Problems = append(out.Problems, "audit extension column privilege mismatch: "+o.identity+"."+col+" "+priv)
				}
			}
		}
	}
	return nil
}

func reconcileAuditExtension(ctx context.Context, tx pgx.Tx, quoted string) error {
	objects, err := auditExtensionManifest(ctx, tx)
	if err != nil || objects == nil {
		return err
	}
	for _, q := range []string{"REVOKE ALL ON SCHEMA omp_audit_ext FROM " + quoted + " CASCADE", "GRANT USAGE ON SCHEMA omp_audit_ext TO " + quoted, "REVOKE ALL ON ALL TABLES IN SCHEMA omp_audit_ext FROM " + quoted + " CASCADE", "REVOKE ALL ON ALL FUNCTIONS IN SCHEMA omp_audit_ext FROM " + quoted + " CASCADE"} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return err
		}
	}
	for _, o := range objects {
		if o.kind == "table" {
			for _, col := range o.columns {
				c := pgx.Identifier{col}.Sanitize()
				if _, err := tx.Exec(ctx, "REVOKE SELECT ("+c+"),INSERT ("+c+"),UPDATE ("+c+"),REFERENCES ("+c+") ON "+o.identity+" FROM "+quoted+" CASCADE"); err != nil {
					return err
				}
			}
		}
		for _, priv := range o.privileges {
			grant := strings.ToUpper(priv)
			if strings.HasPrefix(priv, "update(") {
				grant = "UPDATE (" + pgx.Identifier{strings.TrimSuffix(strings.TrimPrefix(priv, "update("), ")")}.Sanitize() + ")"
			}
			if _, err := tx.Exec(ctx, "GRANT "+grant+" ON "+o.kind+" "+o.identity+" TO "+quoted); err != nil {
				return err
			}
		}
	}
	return nil
}
