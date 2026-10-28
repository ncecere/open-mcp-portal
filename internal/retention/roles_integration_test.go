package retention_test

import (
	"context"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/retention"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestMissingPurgeFunctionFailsClosed(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	f := &fixture{t: t, pool: pool}
	f.scalar(`INSERT INTO audit_log(occurred_at,actor_kind,action,target_type) VALUES (now()-interval '500 days','system','old.fixture','fixture') RETURNING id::text`)
	if _, err := testutil.OwnerPool(t, pool).Exec(ctx, `DROP FUNCTION public.omp_purge_audit_log(integer,integer)`); err != nil {
		t.Fatal(err)
	}
	service := retention.New(pool, retention.Config{BatchSize: 10}, testutil.Logger())
	run, ran, err := service.Pass(ctx)
	if err != nil || !ran || run.Errors[retention.AuditLog] != "database" || run.Deleted[retention.AuditLog] != 0 {
		t.Fatalf("missing function pass: %+v %v", run, err)
	}
	if n := f.scalar(`SELECT count(*)::text FROM audit_log WHERE action='old.fixture'`); n != "1" {
		t.Fatal("direct-delete fallback erased record")
	}
}
