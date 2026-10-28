package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func insertCall(t *testing.T, pool *pgxpool.Pool, age string, gatewayTeam, serverTeam any) int64 {
	t.Helper()
	return roleCount(t, pool, `INSERT INTO mcp_calls(occurred_at,method,outcome,gateway_id,gateway_slug,gateway_name,
 gateway_team_id,server_team_id,principal_kind,service_account_id)
 VALUES (now()-$1::interval,'tools/list','ok',gen_random_uuid(),'fixture','Fixture',$2,$3,'service_account',gen_random_uuid()) RETURNING id`, age, gatewayTeam, serverTeam)
}

func TestPurgeFloorsCountsAndPayloadCascade(t *testing.T) {
	runtime, _, _ := splitFixture(t)
	roleExec(t, runtime, `INSERT INTO audit_log(occurred_at,actor_kind,action,target_type) VALUES
 (now()-interval '31 days','system','old','fixture'),(now()-interval '29 days','system','recent','fixture')`)
	if n := roleCount(t, runtime, `SELECT public.omp_purge_audit_log(-100,1)`); n != 1 {
		t.Fatalf("audit deleted %d", n)
	}
	if n := roleCount(t, runtime, `SELECT public.omp_purge_audit_log(0,100)`); n != 0 {
		t.Fatalf("audit floor deleted %d", n)
	}
	old := insertCall(t, runtime, "2 days", nil, nil)
	insertCall(t, runtime, "12 hours", nil, nil)
	roleExec(t, runtime, `INSERT INTO mcp_call_payloads(call_id,occurred_at,by_gateway,by_server,arguments_cipher,arguments_bytes)
 SELECT id,occurred_at,true,false,'\x00',1 FROM mcp_calls WHERE id=$1`, old)
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now()+interval '1 year',0,100)`); n != 0 {
		t.Fatal("uninitialized rollup deleted calls")
	}
	roleExec(t, runtime, `UPDATE usage_rollup_state SET rolled_up_to=now()`)
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now()+interval '1 year',0,100)`); n != 1 {
		t.Fatalf("call 1-day floor deleted %d", n)
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM mcp_call_payloads`); n != 0 {
		t.Fatal("payload cascade failed")
	}
	if n := roleCount(t, runtime, `SELECT count(*) FROM mcp_calls`); n != 1 {
		t.Fatal("recent call deleted")
	}
	if n := roleCount(t, runtime, `SELECT (pg_typeof(public.omp_purge_audit_log(30,1))='bigint'::regtype)::int`); n != 1 {
		t.Fatal("not bigint")
	}
}

func TestPurgeEffectiveTeamPeriods(t *testing.T) {
	for _, tc := range []struct {
		name                            string
		gateway, server                 *int
		existingGateway, existingServer bool
		platform                        int
		want                            int64
	}{
		{"neither inherits platform", nil, nil, false, false, 90, 1},
		{"lone gateway longer than platform", intPtr(365), nil, true, false, 90, 0},
		{"lone server longer than platform", nil, intPtr(365), false, true, 90, 0},
		{"two explicit longest", intPtr(365), intPtr(200), true, true, 90, 0},
		{"shortest explicit", intPtr(365), intPtr(10), true, true, 90, 1},
		{"absent gateway override inherits", nil, intPtr(365), true, true, 90, 1},
		{"absent server override inherits", intPtr(365), nil, true, true, 90, 1},
		{"no overrides", nil, nil, true, true, 200, 0},
		{"clamp after shortest", intPtr(-1), intPtr(365), true, true, 365, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runtime, _, _ := splitFixture(t)
			team := func(slug string, exists bool, days *int) any {
				if !exists {
					return nil
				}
				var id string
				if err := runtime.QueryRow(context.Background(), `INSERT INTO teams(slug,name,retention_overrides)
 VALUES ($1,$1,CASE WHEN $2::int IS NULL THEN '{}'::jsonb ELSE jsonb_build_object('call_metadata',$2::int) END) RETURNING id::text`, slug, days).Scan(&id); err != nil {
					t.Fatal(err)
				}
				return id
			}
			g, s := team("gateway", tc.existingGateway, tc.gateway), team("server", tc.existingServer, tc.server)
			insertCall(t, runtime, "100 days", g, s)
			roleExec(t, runtime, `UPDATE usage_rollup_state SET rolled_up_to=now()`)
			if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now(),$1,100)`, tc.platform); n != tc.want {
				t.Fatalf("deleted %d want %d", n, tc.want)
			}
		})
	}
}
func intPtr(n int) *int { return &n }

func TestPurgeWatermarkBoundAndNullState(t *testing.T) {
	runtime, _, _ := splitFixture(t)
	// A non-hour UTC timestamp ensures UTC truncation and the overlap hour.
	persisted := time.Now().UTC().Add(-72 * time.Hour).Truncate(time.Hour).Add(37 * time.Minute)
	cutoff := persisted.Truncate(time.Hour).Add(-time.Hour)
	roleExec(t, runtime, `UPDATE usage_rollup_state SET rolled_up_to=$1`, persisted)
	for _, stamp := range []time.Time{cutoff.Add(-time.Second), cutoff, cutoff.Add(time.Second)} {
		roleExec(t, runtime, `INSERT INTO mcp_calls(occurred_at,method,outcome,gateway_id,gateway_slug,gateway_name,principal_kind,service_account_id)
 VALUES ($1,'tools/list','ok',gen_random_uuid(),'f','F','service_account',gen_random_uuid())`, stamp)
	}
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls($1,1,100)`, cutoff.Add(-time.Second)); n != 0 {
		t.Fatal("caller bound ignored")
	}
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now()+interval '100 years',1,100)`); n != 1 {
		t.Fatalf("persisted bound deleted %d", n)
	}
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(NULL,1,100)`); n != 0 {
		t.Fatal("NULL caller watermark purged")
	}
	roleExec(t, runtime, `UPDATE usage_rollup_state SET rolled_up_to=NULL`)
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now(),1,100)`); n != 0 {
		t.Fatal("NULL persisted watermark purged")
	}
	roleExec(t, runtime, `DELETE FROM usage_rollup_state`)
	if n := roleCount(t, runtime, `SELECT public.omp_purge_mcp_calls(now(),1,100)`); n != 0 {
		t.Fatal("missing persisted state purged")
	}
}

func TestPurgeInvalidInputAndFlags(t *testing.T) {
	runtime, owner, _ := splitFixture(t)
	ctx := context.Background()
	for _, args := range []string{"30,NULL", "30,0", "30,-1", "30,100001", "NULL,1"} {
		roleDenied(t, runtime, `SELECT public.omp_purge_audit_log(`+args+`)`, "22023")
		roleDenied(t, runtime, `SELECT public.omp_purge_mcp_calls(now(),`+args+`)`, "22023")
	}
	roleExec(t, owner, `CREATE FUNCTION reject_purge_fixture() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture purge error'; END $$;
 CREATE TRIGGER reject_purge_fixture BEFORE DELETE ON public.audit_log FOR EACH ROW EXECUTE FUNCTION reject_purge_fixture()`)
	roleExec(t, runtime, `INSERT INTO audit_log(occurred_at,actor_kind,action,target_type) VALUES (now()-interval '100 days','system','old','fixture')`)
	conn, err := runtime.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, before := range []string{"off", "on", "sentinel"} {
		roleExec(t, conn, `SELECT set_config('omp.audit_purge',$1,false)`, before)
		roleExec(t, conn, `DO $$ BEGIN PERFORM public.omp_purge_audit_log(30,1); EXCEPTION WHEN raise_exception THEN NULL; END $$`)
		var after string
		if err := conn.QueryRow(ctx, `SELECT current_setting('omp.audit_purge')`).Scan(&after); err != nil || after != before {
			t.Fatalf("flag after failure %q want %q: %v", after, before, err)
		}
	}
	roleExec(t, owner, `DROP TRIGGER reject_purge_fixture ON audit_log`)
	roleExec(t, conn, `SELECT public.omp_purge_audit_log(30,1)`)
	var after string
	if err := conn.QueryRow(ctx, `SELECT current_setting('omp.audit_purge')`).Scan(&after); err != nil || after != "sentinel" {
		t.Fatalf("flag after success %q: %v", after, err)
	}
	roleExec(t, conn, `SELECT set_config('omp.calls_purge','sentinel',false)`)
	roleExec(t, conn, `UPDATE usage_rollup_state SET rolled_up_to=now()`)
	roleExec(t, conn, `SELECT public.omp_purge_mcp_calls(now(),1,1)`)
	if err := conn.QueryRow(ctx, `SELECT current_setting('omp.calls_purge')`).Scan(&after); err != nil || after != "sentinel" {
		t.Fatalf("call flag after success %q: %v", after, err)
	}
	roleExec(t, owner, `CREATE TRIGGER reject_calls_fixture BEFORE DELETE ON public.mcp_calls FOR EACH ROW EXECUTE FUNCTION reject_purge_fixture()`)
	insertCall(t, runtime, "2 days", nil, nil)
	roleExec(t, conn, `DO $$ BEGIN PERFORM public.omp_purge_mcp_calls(now(),1,100); EXCEPTION WHEN raise_exception THEN NULL; END $$`)
	if err := conn.QueryRow(ctx, `SELECT current_setting('omp.calls_purge')`).Scan(&after); err != nil || after != "sentinel" {
		t.Fatalf("call flag after failure %q: %v", after, err)
	}
	roleExec(t, owner, `DROP TRIGGER reject_calls_fixture ON mcp_calls; DROP FUNCTION reject_purge_fixture()`)
}

func TestPurgeSearchPathShadowing(t *testing.T) {
	runtime, _, _ := splitFixture(t)
	ctx := context.Background()
	conn, err := runtime.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	roleExec(t, conn, `CREATE TEMP TABLE audit_log(id bigint, occurred_at timestamptz);
 INSERT INTO pg_temp.audit_log VALUES (1,now()-interval '100 days');
 CREATE TEMP TABLE mcp_calls(id bigint,occurred_at timestamptz);
 CREATE TEMP TABLE teams(id uuid,retention_overrides jsonb);
 CREATE TEMP TABLE usage_rollup_state(id int,rolled_up_to timestamptz);
 INSERT INTO pg_temp.usage_rollup_state VALUES (1,now()+interval '100 years');
 INSERT INTO public.audit_log(occurred_at,actor_kind,action,target_type) VALUES (now()-interval '100 days','system','old','fixture')`)
	if n := roleCount(t, conn, `SELECT public.omp_purge_audit_log(30,100)`); n != 1 {
		t.Fatalf("public purge deleted %d", n)
	}
	if n := roleCount(t, conn, `SELECT count(*) FROM pg_temp.audit_log`); n != 1 {
		t.Fatal("purge used shadow table")
	}
	if n := roleCount(t, conn, `SELECT public.omp_purge_mcp_calls(now(),1,100)`); n != 0 {
		t.Fatal("shadow call table used")
	}
}

func TestSingleOwnerLegacyAndDefinerRetention(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "0")
	owner, _ := testutil.NewDB(t)
	roleExec(t, owner, `INSERT INTO audit_log(occurred_at,actor_kind,action,target_type) VALUES (now()-interval '31 days','system','old','fixture')`)
	if n := roleCount(t, owner, `SELECT public.omp_purge_audit_log(30,100)`); n != 1 {
		t.Fatal("single-owner definer retention failed")
	}
	// Use one connection: flags belong to the session, not a pool.
	conn, err := owner.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	roleExec(t, conn, `INSERT INTO audit_log(actor_kind,action,target_type) VALUES ('system','legacy','fixture')`)
	roleExec(t, conn, `SELECT set_config('omg.audit_purge','on',false)`)
	roleExec(t, conn, `DELETE FROM audit_log`)
}
