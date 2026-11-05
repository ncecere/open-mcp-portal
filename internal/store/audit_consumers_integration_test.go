package store_test

import (
	"context"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"testing"
)

func TestAuditConsumerFunctionManifest(t *testing.T) {
	p, o, role := splitFixture(t)
	for _, sig := range []string{"ack(text,bigint)", "register_consumer(text,text,boolean,uuid)", "set_required(text,boolean)", "remove_consumer(text)", "record_oversized_fetch(text,bigint)"} {
		n := roleCount(t, p, `SELECT (prosecdef AND proowner=(SELECT relowner FROM pg_class WHERE oid='public.audit_log'::regclass) AND proconfig @> ARRAY['TimeZone=UTC','search_path=pg_catalog, pg_temp'] AND has_function_privilege($2,oid,'EXECUTE') AND NOT EXISTS(SELECT 1 FROM aclexplode(proacl) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'))::int FROM pg_proc WHERE oid=to_regprocedure($1)`, "omp_audit."+sig, role)
		if n != 1 {
			t.Fatalf("unsafe %s", sig)
		}
	}
	roleExec(t, o, `DROP FUNCTION omp_audit.ack(text,bigint)`)
	safety, err := store.InspectRoles(context.Background(), p, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if safety.Safe() {
		t.Fatal("inspector accepted a missing required consumer function")
	}
}
