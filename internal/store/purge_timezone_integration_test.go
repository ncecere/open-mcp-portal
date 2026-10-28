package store_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// hostilePurgeZone finds a POSIX zone whose 24-hour DST jump makes calendar
// subtraction violate BOTH elapsed-time floors at at. J rules ignore leap day;
// derive them from nearby UTC dates in a non-leap year, wrapping the end rule.
// Probe a bounded set rather than assuming a local date/offset (including near
// leap day and year boundaries). Failure to find an actual attack is fatal,
// never a skip or a test that silently stops exercising the vulnerability.
func hostilePurgeZone(t *testing.T, conn *pgxpool.Conn, at time.Time) string {
	t.Helper()
	ctx := context.Background()
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) // also restores the probe's transaction-local TimeZone
	for offset := -2; offset <= 2; offset++ {
		date := at.UTC().AddDate(0, 0, offset)
		start := time.Date(2001, date.Month(), date.Day(), 0, 0, 0, 0, time.UTC).YearDay()
		end := (start-1+10)%365 + 1
		for _, hour := range []int{0, 6, 12, 18} {
			zone := fmt.Sprintf("AAA12BBB-12,J%d/%d,J%d/%d", start, hour, end, hour)
			roleExec(t, tx, `SELECT set_config('TimeZone',$1,true)`, zone)
			var callSeconds, auditSeconds float64
			if err := tx.QueryRow(ctx, `SELECT
 extract(epoch FROM ($1::timestamptz - ($1::timestamptz - make_interval(days=>1)))),
 extract(epoch FROM ($1::timestamptz - ($1::timestamptz - make_interval(days=>30))))`, at).Scan(&callSeconds, &auditSeconds); err != nil {
				t.Fatal(err)
			}
			if callSeconds == 0 && auditSeconds == 29*24*60*60 {
				return zone
			}
		}
	}
	t.Fatalf("no hostile POSIX zone found for %s", at.UTC())
	return ""
}

func hostilePurgeConn(t *testing.T, runtime *pgxpool.Pool) (*pgxpool.Conn, string) {
	t.Helper()
	ctx := context.Background()
	conn, err := runtime.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Release)
	var now time.Time
	if err := conn.QueryRow(ctx, `SELECT now()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	zone := hostilePurgeZone(t, conn, now)
	roleExec(t, conn, `SELECT set_config('TimeZone',$1,false),
 set_config('omp.audit_purge','audit-sentinel',false),
 set_config('omp.calls_purge','calls-sentinel',false)`, zone)
	// Prove this connection is authenticated as the restricted runtime, not
	// SET ROLE or an owner fixture. Only DDL instrumentation uses OwnerPool.
	if n := roleCount(t, conn, `SELECT (session_user=current_user AND current_user=$1
 AND NOT (SELECT rolsuper FROM pg_roles WHERE rolname=current_user))::int`, runtime.Config().ConnConfig.User); n != 1 {
		t.Fatal("not authenticated as restricted runtime")
	}
	return conn, zone
}

func assertPurgeCallerSettings(t *testing.T, conn *pgxpool.Conn, zone string) {
	t.Helper()
	var afterZone, auditFlag, callsFlag string
	err := conn.QueryRow(context.Background(), `SELECT current_setting('TimeZone'),
 current_setting('omp.audit_purge'),current_setting('omp.calls_purge')`).Scan(&afterZone, &auditFlag, &callsFlag)
	if err != nil || afterZone != zone || auditFlag != "audit-sentinel" || callsFlag != "calls-sentinel" {
		t.Fatalf("caller settings: zone=%q audit=%q calls=%q: %v", afterZone, auditFlag, callsFlag, err)
	}
}

func TestPurgeHostileTimeZoneFloors(t *testing.T) {
	for _, kind := range []string{"audit", "calls"} {
		t.Run(kind, func(t *testing.T) {
			runtime, _, _ := splitFixture(t)
			conn, zone := hostilePurgeConn(t, runtime)
			var query, table string
			if kind == "audit" {
				// Hours are elapsed durations even in the hostile zone.
				roleExec(t, conn, `INSERT INTO audit_log(occurred_at,actor_kind,action,target_type) VALUES
 (now()-interval '744 hours','system','old','fixture'),
 (now()-interval '708 hours','system','29.5 days old','fixture')`)
				query, table = `SELECT public.omp_purge_audit_log(0,100)`, "audit_log"
			} else {
				insertCall(t, runtime, "48 hours", nil, nil)
				insertCall(t, runtime, "2 hours", nil, nil)
				roleExec(t, conn, `UPDATE usage_rollup_state SET rolled_up_to=now()`)
				// The recent call is already below the persisted overlap cutoff:
				// only the one-day floor, not the watermark, can protect it.
				if n := roleCount(t, conn, `SELECT count(*) FROM mcp_calls WHERE occurred_at <
 (SELECT date_trunc('hour',rolled_up_to,'UTC')-interval '1 hour' FROM usage_rollup_state WHERE id=1)`); n != 2 {
					t.Fatal("call fixtures are not both below the persisted watermark")
				}
				query, table = `SELECT public.omp_purge_mcp_calls(now(),0,100)`, "mcp_calls"
			}
			if n := roleCount(t, conn, query); n != 1 {
				t.Fatalf("hostile TimeZone bypassed %s elapsed-time floor: deleted %d rows, want only 1 truly old row", kind, n)
			}
			assertPurgeCallerSettings(t, conn, zone)
			// The migration's system retirement audit entry is also recent and
			// protected. Count only this test's audit fixtures, not that history.
			filter := ""
			if kind == "audit" {
				filter = " WHERE target_type='fixture'"
			}
			if n := roleCount(t, conn, `SELECT count(*) FROM public.`+table+filter); n != 1 {
				t.Fatal("protected recent row did not survive")
			}
			if n := roleCount(t, conn, query); n != 0 {
				t.Fatal("repeated purge deleted the protected row")
			}
			assertPurgeCallerSettings(t, conn, zone)
		})
	}
}

func TestPurgeTimeZoneAndFlagsRestoredAfterError(t *testing.T) {
	runtime, owner, _ := splitFixture(t)
	roleExec(t, owner, `CREATE FUNCTION reject_timezone_purge() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN RAISE EXCEPTION 'fixture purge error'; END $$;
 CREATE TRIGGER reject_timezone_purge BEFORE DELETE ON public.audit_log
 FOR EACH ROW EXECUTE FUNCTION reject_timezone_purge();
 CREATE TRIGGER reject_timezone_purge BEFORE DELETE ON public.mcp_calls
 FOR EACH ROW EXECUTE FUNCTION reject_timezone_purge()`)
	conn, zone := hostilePurgeConn(t, runtime)
	roleExec(t, conn, `INSERT INTO audit_log(occurred_at,actor_kind,action,target_type)
 VALUES (now()-interval '744 hours','system','old','fixture');
 UPDATE usage_rollup_state SET rolled_up_to=now()`)
	insertCall(t, runtime, "48 hours", nil, nil)
	for _, tc := range []struct{ call, code string }{
		{`public.omp_purge_audit_log(30,100)`, "raise_exception"},
		{`public.omp_purge_mcp_calls(now(),1,100)`, "raise_exception"},
		{`public.omp_purge_audit_log(30,0)`, "invalid_parameter_value"},
		{`public.omp_purge_mcp_calls(now(),1,0)`, "invalid_parameter_value"},
	} {
		// Catch inside the statement, not by rolling back an outer transaction,
		// so subsequent reads observe the caller's restored function settings.
		roleExec(t, conn, `DO $$ BEGIN PERFORM `+tc.call+`; RAISE EXCEPTION 'expected purge error' USING ERRCODE='XX000';
 EXCEPTION WHEN `+tc.code+` THEN NULL; END $$`)
		assertPurgeCallerSettings(t, conn, zone)
	}
}

func TestPurgeFunctionsPinUTCAndSearchPath(t *testing.T) {
	runtime, _, _ := splitFixture(t)
	for _, signature := range []string{
		"public.omp_purge_audit_log(integer,integer)",
		"public.omp_purge_mcp_calls(timestamptz,integer,integer)",
	} {
		if n := roleCount(t, runtime, `SELECT (prosecdef
 AND proconfig @> ARRAY['TimeZone=UTC','search_path=pg_catalog, pg_temp']
 AND proowner=(SELECT relowner FROM pg_class WHERE oid='public.audit_log'::regclass)
 AND proowner=(SELECT relowner FROM pg_class WHERE oid='public.mcp_calls'::regclass)
 AND NOT EXISTS (SELECT 1 FROM aclexplode(proacl) WHERE grantee=0 AND privilege_type='EXECUTE'))::int
 FROM pg_proc WHERE oid=$1::regprocedure`, signature); n != 1 {
			t.Fatalf("%s must pin UTC/search_path and retain its owner and PUBLIC execution denial", signature)
		}
	}
}

func TestPurgeHostileTimeZoneProbeCalendarEdges(t *testing.T) {
	runtime, _, _ := splitFixture(t)
	conn, err := runtime.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	for _, stamp := range []string{
		"2027-01-01T00:01:00Z", "2027-12-31T23:59:00Z",
		"2028-01-01T00:01:00Z", "2028-02-29T00:01:00Z",
		"2028-02-29T23:59:00Z", "2028-03-01T00:01:00Z",
		"2028-12-31T23:59:00Z", "2029-01-01T00:01:00Z",
	} {
		t.Run(stamp, func(t *testing.T) {
			at, err := time.Parse(time.RFC3339, stamp)
			if err != nil {
				t.Fatal(err)
			}
			hostilePurgeZone(t, conn, at)
		})
	}
}
