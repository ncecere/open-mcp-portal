package auditstream

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestConsumerAckBoundary(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	exec(t, p, insert)
	drain(t, p)
	exec(t, p, `SELECT omp_audit.register_consumer('collector','full',true,$1)`, uuid.New())
	exec(t, p, `SELECT omp_audit.ack('collector',1)`)
	for _, seq := range []int64{0, 2, -1} {
		if _, err := p.Exec(ctx, `SELECT omp_audit.ack('collector',$1)`, seq); err == nil {
			t.Fatalf("accepted ack %d", seq)
		}
	}
	exec(t, p, `SELECT omp_audit.ack('collector',1)`)
	owner := testutil.OwnerPool(t, p)
	for _, q := range []string{`UPDATE omp_audit.consumers SET acked_seq=2`, `DELETE FROM omp_audit.retention_floor`, `INSERT INTO omp_audit.oversized_fetches VALUES('collector',1)`} {
		if p.Config().ConnConfig.User != owner.Config().ConnConfig.User {
			if _, err := p.Exec(ctx, q); err == nil {
				t.Fatalf("runtime accepted %s", q)
			}
		}
	}
}
func TestRetentionStrictParity(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	owner := testutil.OwnerPool(t, p)
	for _, raw := range []string{`null`, `[]`, `{"call_metadata":null}`, `{"call_metadata":"90"}`, `{"call_metadata":1.0}`, `{"call_metadata":0}`, `{"call_metadata":3651}`, `{"call_metadata":true}`} {
		t.Run(raw, func(t *testing.T) {
			if _, err := owner.Exec(ctx, `SELECT omp_audit.call_days($1::jsonb,90)`, raw); err == nil {
				t.Fatal("accepted malformed value")
			}
		})
	}
	for raw, want := range map[string]int64{`{}`: 90, `{"call_metadata":1}`: 1, `{"call_metadata":3650}`: 3650} {
		if got := count(t, owner, `SELECT omp_audit.call_days($1::jsonb,90)`, raw); got != want {
			t.Fatalf("%s: %d", raw, got)
		}
	}
}
func TestRetentionMissingAndMalformedFailClosed(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	o := testutil.OwnerPool(t, p)
	for _, table := range []string{"public.retention_settings", "omp_audit.state", "omp_audit.retention_floor"} {
		t.Run(table, func(t *testing.T) {
			tx, err := o.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `DELETE FROM `+table); err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(ctx, `SELECT public.omp_purge_audit_log(30,100)`); err == nil {
				t.Fatal("purge accepted missing singleton")
			}
		})
	}
	for _, raw := range []string{`{"call_metadata":null}`, `{"call_metadata":1.1}`, `{"call_metadata":0}`, `{"call_metadata":3651}`, `{"call_metadata":"90"}`} {
		exec(t, o, `UPDATE public.retention_settings SET periods=$1`, raw)
		if _, err := p.Exec(ctx, `SELECT public.omp_purge_audit_log(30,100)`); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
func TestRetentionSealedAcknowledgedPrefix(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	for _, age := range []int{200, 10, 200} {
		exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','test','test',now()-make_interval(days=>$1))`, age)
	}
	drain(t, p)
	exec(t, p, `SELECT omp_audit.register_consumer('required','summary',true,$1)`, uuid.New())
	if n := count(t, p, `SELECT public.omp_purge_audit_log(30,100)`); n != 0 {
		t.Fatal(n)
	}
	exec(t, p, `SELECT omp_audit.ack('required',3)`)
	if n := count(t, p, `SELECT public.omp_purge_audit_log(30,100)`); n != 1 {
		t.Fatal(n)
	}
	if n := count(t, p, `SELECT count(*) FROM public.audit_log`); n != 2 {
		t.Fatal(n)
	}
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	earliest, err := CheckRange(ctx, tx, 0, 100)
	if err == nil || earliest != 2 {
		t.Fatalf("%d %v", earliest, err)
	}
	if _, err := CheckRange(ctx, tx, 1, 100); err != nil {
		t.Fatal(err)
	}
}
func TestRetentionCatalogContract(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	n := count(t, p, `SELECT count(*) FROM pg_proc WHERE oid='public.omp_purge_audit_log(integer,integer)'::regprocedure AND prosecdef AND proowner=(SELECT relowner FROM pg_class WHERE oid='public.audit_log'::regclass) AND proconfig @> ARRAY['TimeZone=UTC','search_path=pg_catalog, pg_temp'] AND NOT EXISTS(SELECT 1 FROM aclexplode(proacl) a WHERE grantee=0 AND privilege_type='EXECUTE')`)
	if n != 1 {
		t.Fatal("purge contract lost")
	}
}
func TestRetentionTenThousandTeams(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	o := testutil.OwnerPool(t, p)
	exec(t, o, `INSERT INTO public.teams(name,slug,retention_overrides) SELECT 'perf-'||n,'perf-'||n,'{"call_metadata":3650}'::jsonb FROM generate_series(1,10000) n`)
	start := time.Now()
	if n := count(t, p, `SELECT public.omp_purge_audit_log(30,100)`); n != 0 {
		t.Fatal(n)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("10k teams: %s", elapsed)
	} else {
		t.Logf("10k teams: %s", elapsed)
	}
}
func TestOversizedAckInterlock(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','test','test',jsonb_build_object('large',repeat('x',17*1024*1024)))`)
	drain(t, p)
	if count(t, p, `SELECT flags::bigint FROM omp_audit.chain WHERE seq=1`)&2 == 0 {
		t.Fatal("missing oversized flag")
	}
	exec(t, p, `SELECT omp_audit.register_consumer('full','full',true,$1)`, uuid.New())
	if _, err := p.Exec(ctx, `SELECT omp_audit.ack('full',1)`); err == nil || !strings.Contains(err.Error(), "oversized_pending") {
		t.Fatal(fmt.Sprint(err))
	}
	exec(t, p, `SELECT omp_audit.record_oversized_fetch('full',1)`)
	exec(t, p, `SELECT omp_audit.ack('full',1)`)
}

func cleanAuditFixture(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	o := testutil.OwnerPool(t, p)
	tx, err := o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT set_config('omp.audit_purge','on',true)`); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM public.audit_log`); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDeliveryInteriorMissingIsIntegrityFailure(t *testing.T) {
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	for range 3 {
		exec(t, p, insert)
	}
	drain(t, p)
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e, err := Read(ctx, tx, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := VerifyEntry(e, Genesis(e.Stream)); err != nil || !ok {
		t.Fatalf("verify: %v %v", ok, err)
	}
	tx.Rollback(ctx)
	o := testutil.OwnerPool(t, p)
	tx, err = o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	execErr := func(q string) {
		if _, err := tx.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	execErr(`SELECT set_config('omp.audit_purge','on',true)`)
	execErr(`DELETE FROM public.audit_log WHERE row_uid=(SELECT row_uid FROM omp_audit.chain WHERE seq=2)`)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	tx, err = p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = CheckRange(ctx, tx, 0, 3); err == nil || err.Error() != "audit_row_missing" {
		t.Fatalf("interior expiry: %v", err)
	}
}

func TestRetentionFloorCallsAndTimezone(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		floor, calls, team, age int
		want                    int64
	}{
		{"floor", 300, 90, 0, 200, 0}, {"platform", 30, 300, 0, 200, 0}, {"team", 30, 90, 300, 200, 0}, {"old", 30, 90, 300, 400, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			cleanAuditFixture(t, p)
			o := testutil.OwnerPool(t, p)
			exec(t, o, `UPDATE omp_audit.retention_floor SET min_days=$1`, tc.floor)
			exec(t, o, `UPDATE public.retention_settings SET periods=jsonb_build_object('call_metadata',$1::int)`, tc.calls)
			if tc.team > 0 {
				exec(t, o, `INSERT INTO public.teams(name,slug,retention_overrides) VALUES('team','team',jsonb_build_object('call_metadata',$1::int))`, tc.team)
			}
			exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','test','test',now()-make_interval(days=>$1))`, tc.age)
			drain(t, p)
			tx, err := p.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			if _, err = tx.Exec(ctx, `SET LOCAL TimeZone='America/New_York'`); err != nil {
				t.Fatal(err)
			}
			var got int64
			if err = tx.QueryRow(ctx, `SELECT public.omp_purge_audit_log(30,100)`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
func TestRetentionErrorRestoresFlag(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	exec(t, o, `UPDATE public.retention_settings SET periods='{"call_metadata":null}'`)
	// Catch the error in a PL/pgSQL subtransaction, then observe caller state.
	exec(t, o, `DO $$ BEGIN PERFORM set_config('omp.audit_purge','off',true); BEGIN PERFORM public.omp_purge_audit_log(30,100); EXCEPTION WHEN OTHERS THEN NULL; END; IF current_setting('omp.audit_purge')<>'off' THEN RAISE EXCEPTION 'purge flag leaked'; END IF; END $$`)
}
