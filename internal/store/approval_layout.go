package store

import (
	"context"
	"fmt"
)

// Historical migration fixtures really run 35/36/41. Accept exactly those
// catalog layouts, never a mixed relocation or an extra protected namesake.
type approvalLayout struct {
	schema           string
	journal, binding bool
}

func inspectApprovalLayout(ctx context.Context, db RoleDB) (approvalLayout, error) {
	var l approvalLayout
	var public, private int
	if err := db.QueryRow(ctx, `SELECT
 count(*) FILTER (WHERE n.nspname='public'), count(*) FILTER (WHERE n.nspname='omp_private')
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname IN ('public','omp_private') AND c.relname IN
 ('approval_context','approval_context_events','approval_binding_keys')`).Scan(&public, &private); err != nil {
		return l, err
	}
	l.schema = "public"
	if private != 0 {
		if private != 3 || public != 0 {
			return l, fmt.Errorf("inconsistent protected approval schema")
		}
		l.schema = "omp_private"
	} else if public < 1 || public > 3 {
		return l, fmt.Errorf("missing protected approval schema")
	}
	if err := db.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL,to_regclass($2) IS NOT NULL`, l.schema+".approval_context_events", l.schema+".approval_binding_keys").Scan(&l.journal, &l.binding); err != nil {
		return l, err
	}
	if l.binding && !l.journal {
		return l, fmt.Errorf("inconsistent protected approval journal")
	}
	var bad bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname IN ('public','omp_private') AND n.nspname<>$1
 AND p.proname IN ('omp_current_approval_context','omp_lock_approval_context','omp_ensure_approval_binding_key',
 'approval_authority_changed','approval_context_monotonic','approval_binding_key_guard'))`, l.schema).Scan(&bad); err != nil {
		return l, err
	}
	if bad {
		return l, fmt.Errorf("inconsistent protected approval functions")
	}
	if err := db.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, map[string]string{"public": "omp_private", "omp_private": "public"}[l.schema]+".approval_context_events_event_id_seq").Scan(&bad); err != nil {
		return l, err
	}
	if bad {
		return l, fmt.Errorf("inconsistent protected approval sequence")
	}
	var version int64
	if err := db.QueryRow(ctx, `SELECT coalesce(max(version_id),0) FROM public.goose_db_version WHERE is_applied`).Scan(&version); err != nil {
		return l, err
	}
	if version < 35 || (version >= 42) != (l.schema == "omp_private") || l.journal != (version >= 36) || l.binding != (version >= 41) {
		return l, fmt.Errorf("protected approval layout does not match applied migration %d", version)
	}
	return l, nil
}

func (l approvalLayout) functions() []string {
	f := []string{"public.omp_purge_audit_log(integer,integer)", "public.omp_purge_mcp_calls(timestamp with time zone,integer,integer)", l.schema + ".omp_lock_approval_context(boolean)"}
	if l.journal {
		f = append(f, l.schema+".omp_current_approval_context()")
	}
	if l.binding {
		f = append(f, l.schema+".omp_ensure_approval_binding_key(bytea)")
	}
	return f
}

// Check every protected trigger/helper as well as the callable interface. A
// schema owned by an auxiliary role could replace the definer implementation.
func inspectApprovalBoundary(ctx context.Context, db RoleDB, l approvalLayout, out *RoleSafety) error {
	var unsafe bool
	err := db.QueryRow(ctx, `WITH owner AS (SELECT relowner AS oid FROM pg_catalog.pg_class WHERE oid='public.users'::regclass)
 SELECT EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace,owner o
 WHERE n.nspname=$1 AND c.relname IN ('approval_context','approval_context_events','approval_context_events_event_id_seq','approval_binding_keys') AND c.relowner<>o.oid)
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n,owner o WHERE n.nspname='omp_private' AND n.nspowner<>o.oid)
 OR EXISTS (
 SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace,owner o
 WHERE n.nspname=$1 AND p.proname IN ('omp_current_approval_context','omp_lock_approval_context','omp_ensure_approval_binding_key','approval_authority_changed','approval_context_monotonic','approval_binding_key_guard')
 AND (p.proowner<>o.oid OR NOT coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'],false)
 OR (p.proname IN ('omp_current_approval_context','omp_lock_approval_context','omp_ensure_approval_binding_key','approval_authority_changed') AND NOT p.prosecdef)
 OR EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')))
 OR EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1 AND ((c.relname IN ('approval_context','approval_context_events','approval_binding_keys') AND c.relkind<>'r')
 OR (c.relname='approval_context_events_event_id_seq' AND c.relkind<>'S')))
 OR (SELECT count(*) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=$1 AND p.proname IN ('omp_current_approval_context','omp_lock_approval_context','omp_ensure_approval_binding_key','approval_authority_changed','approval_context_monotonic','approval_binding_key_guard')) <> $2
 OR ($1='omp_private' AND EXISTS (
 SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname=$1 AND p.proname NOT IN ('omp_current_approval_context','omp_lock_approval_context','omp_ensure_approval_binding_key','approval_authority_changed','approval_context_monotonic','approval_binding_key_guard')))
 OR ($1='omp_private' AND EXISTS (
 SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE n.nspname=$1 AND c.relkind IN ('r','p','v','m','f','S') AND c.relname NOT IN ('approval_context','approval_context_events','approval_context_events_event_id_seq','approval_binding_keys')))`, l.schema, 3+boolCount(l.journal)+2*boolCount(l.binding)).Scan(&unsafe)
	if err != nil {
		return err
	}
	if unsafe {
		out.Problems = append(out.Problems, "unsafe protected approval ownership/function boundary")
	}
	return nil
}

func boolCount(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (l approvalLayout) protected(name string) bool {
	return name == "approval_context" || name == "approval_context_events" || name == "approval_binding_keys"
}
