package store_test

import (
	"context"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestUserRequestEpochTriggerPreservesApprovalPrivateBoundary(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	var privateAbsent, owned, invoker, pinned, publiclyExecutable, triggerBound bool
	if err := pool.QueryRow(ctx, `SELECT
 to_regprocedure('omp_private.advance_user_request_epoch()') IS NULL,
 p.proowner=(SELECT relowner FROM pg_class WHERE oid='public.users'::regclass),
 NOT p.prosecdef,
 coalesce(p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp'],false),
 EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE'),
 EXISTS (SELECT 1 FROM pg_trigger t WHERE t.tgrelid='public.users'::regclass AND t.tgname='user_request_epoch_advance' AND t.tgfoid=p.oid)
FROM pg_proc p WHERE p.oid='public.advance_user_request_epoch()'::regprocedure`).Scan(&privateAbsent, &owned, &invoker, &pinned, &publiclyExecutable, &triggerBound); err != nil {
		t.Fatal("inspect epoch trigger boundary:", err)
	}
	if !privateAbsent || !owned || !invoker || !pinned || publiclyExecutable || !triggerBound {
		t.Fatal("epoch trigger escaped its closed non-approval owner/ACL/dependency boundary")
	}
}
