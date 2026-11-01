package testutil

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// catalog fingerprints everything a migration defines, with this database's
// owner and runtime role names normalised, so a template copy and a database
// migrated from empty compare equal only if the schema, ownership, ACLs,
// security-definer settings, triggers and recorded migrations all match.
func catalog(t *testing.T, pool *pgxpool.Pool) []string {
	t.Helper()
	ctx := context.Background()
	owner := OwnerPool(t, pool)
	var ownerRole, runtimeRole string
	if err := owner.QueryRow(ctx, `SELECT current_user`).Scan(&ownerRole); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&runtimeRole); err != nil {
		t.Fatal(err)
	}
	norm := strings.NewReplacer(ownerRole, "<owner>", runtimeRole, "<runtime>")
	if ownerRole == runtimeRole {
		norm = strings.NewReplacer(ownerRole, "<owner>")
	}
	queries := map[string]string{
		"relation": `SELECT n.nspname||'.'||c.relname||' '||c.relkind::text||' owner='||pg_get_userbyid(c.relowner)||' acl='||coalesce(c.relacl::text,'')
			FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname IN ('public','omp_private')`,
		"function": `SELECT n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||') owner='||pg_get_userbyid(p.proowner)||
			' definer='||p.prosecdef||' config='||coalesce(p.proconfig::text,'')||' acl='||coalesce(p.proacl::text,'')||' src='||md5(p.prosrc)
			FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname IN ('public','omp_private')`,
		"schema":     `SELECT nspname||' owner='||pg_get_userbyid(nspowner)||' acl='||coalesce(nspacl::text,'') FROM pg_namespace WHERE nspname IN ('public','omp_private')`,
		"trigger":    `SELECT tgrelid::regclass::text||'.'||tgname||' '||tgfoid::regprocedure::text||' type='||tgtype||' enabled='||tgenabled::text FROM pg_trigger WHERE NOT tgisinternal`,
		"constraint": `SELECT conrelid::regclass::text||'.'||conname||' '||pg_get_constraintdef(oid) FROM pg_constraint WHERE connamespace IN ('public'::regnamespace,'omp_private'::regnamespace)`,
		"index":      `SELECT indexdef FROM pg_indexes WHERE schemaname IN ('public','omp_private')`,
		"column": `SELECT c.oid::regclass::text||'.'||a.attname||' '||format_type(a.atttypid,a.atttypmod)||' notnull='||a.attnotnull||' default='||coalesce(pg_get_expr(d.adbin,d.adrelid),'')||' acl='||coalesce(a.attacl::text,'')
			FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
			WHERE n.nspname IN ('public','omp_private') AND a.attnum>0 AND NOT a.attisdropped AND c.relkind IN ('r','p','v')`,
		"migration": `SELECT version_id::text||' '||is_applied FROM goose_db_version`,
	}
	var out []string
	for kind, q := range queries {
		rows, err := owner.Query(ctx, q)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatal(err)
			}
			out = append(out, kind+" "+norm.Replace(s))
		}
		rows.Close()
	}
	slices.Sort(out)
	return out
}

func TestTemplateMatchesFreshMigration(t *testing.T) {
	copied, _ := NewDB(t)
	fresh, _ := NewDBFromScratch(t)
	a, b := catalog(t, copied), catalog(t, fresh)
	if len(a) < 500 {
		t.Fatalf("catalog fingerprint suspiciously small: %d entries", len(a))
	}
	if !slices.Equal(a, b) {
		onlyA, onlyB := []string{}, []string{}
		for _, x := range a {
			if !slices.Contains(b, x) {
				onlyA = append(onlyA, x)
			}
		}
		for _, x := range b {
			if !slices.Contains(a, x) {
				onlyB = append(onlyB, x)
			}
		}
		t.Fatalf("template copy differs from a fresh migration:\nonly in copy (%d): %v\nonly in fresh (%d): %v", len(onlyA), first(onlyA), len(onlyB), first(onlyB))
	}
	// Negative control: the fingerprint must notice a single ACL change.
	altered, _ := NewDB(t)
	if _, err := OwnerPool(t, altered).Exec(context.Background(), `GRANT SELECT ON TABLE audit_log TO PUBLIC`); err != nil {
		t.Fatal(err)
	}
	if slices.Equal(catalog(t, altered), b) {
		t.Fatal("catalog fingerprint missed an ACL change")
	}
	// The copy also passes the real split-role safety inspection.
	var tables int
	if err := copied.QueryRow(context.Background(), `SELECT count(*) FROM users`).Scan(&tables); err != nil {
		t.Fatal("runtime pool cannot read the copy:", err)
	}
}

func first(s []string) []string {
	if len(s) > 20 {
		return s[:20]
	}
	return s
}
