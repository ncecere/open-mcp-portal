package auditstream

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

const createSinkSQL = `SELECT omp_audit_ext.create_sink($1,'sink','full',$2,true,100,'\x01','receiver.example','\x02',NULL,NULL,'hint')`
const updateSinkSQL = `SELECT omp_audit_ext.update_sink($1,$2,'sink','full',$3,true,100,'\x01','receiver.example','\x02',NULL,NULL,'hint')`

func sinkFixture(t *testing.T, required bool) (*pgxpool.Pool, *pgxpool.Pool, uuid.UUID) {
	t.Helper()
	p, _ := testutil.NewDB(t)
	cleanAuditFixture(t, p)
	o := testutil.OwnerPool(t, p)
	id := uuid.New()
	exec(t, p, createSinkSQL, id, required)
	return p, o, id
}
func sinkReject(t *testing.T, p *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := p.Exec(ctx, sql, args...); err == nil {
		t.Fatalf("accepted %s", sql)
	}
}
func sinkBegin(t *testing.T, p *pgxpool.Pool, id uuid.UUID, revision, cursor int64, kind string, first, last int64) uuid.UUID {
	t.Helper()
	var token uuid.UUID
	if err := p.QueryRow(ctx, `SELECT omp_audit_ext.begin_attempt($1,$2,$3,$4,$5,$6)`, id, revision, cursor, kind, first, last).Scan(&token); err != nil {
		t.Fatal(err)
	}
	return token
}
func TestSinkAttemptFences(t *testing.T) {
	p, o, id := sinkFixture(t, false)
	exec(t, p, insert)
	drain(t, p)
	sinkReject(t, p, `SELECT omp_audit_ext.begin_attempt($1,1,0,'data',1,1)`, id)
	if count(t, p, `SELECT count(*) FROM public.notification_events WHERE event='audit.sink_failing'`) != 0 {
		t.Fatal("disabled sinks produced an event")
	}
	exec(t, o, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	for _, q := range []string{
		`SELECT omp_audit_ext.begin_attempt($1,2,0,'data',1,1)`,
		`SELECT omp_audit_ext.begin_attempt($1,1,1,'data',1,1)`,
		`SELECT omp_audit_ext.begin_attempt($1,1,0,'wrong',1,1)`,
		`SELECT omp_audit_ext.begin_attempt($1,1,0,'gap',1,1)`,
		`SELECT omp_audit_ext.begin_attempt($1,1,0,'data',2,2)`,
		`SELECT omp_audit_ext.begin_attempt($1,1,0,'data',1,100)`,
	} {
		sinkReject(t, p, q, id)
	}
	a := sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	b := sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, a)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'failed','timeout',false)`, id, b)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'failed','timeout',false)`, id, b)
	for i := 0; i < 2; i++ {
		b = sinkBegin(t, p, id, 1, 0, "data", 1, 1)
		exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'failed','timeout',$3)`, id, b, i == 1)
	}
	if count(t, p, `SELECT consecutive_failures FROM omp_audit_ext.sinks WHERE id=$1`, id) != 3 {
		t.Fatal("failure counted incorrectly")
	}
	b = sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,true)`, id, b)
	if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("cursor did not use endpoint")
	}
	exec(t, p, insert)
	drain(t, p)
	b = sinkBegin(t, p, id, 1, 1, "data", 2, 2)
	exec(t, p, updateSinkSQL, id, 1, false)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, b)
	b = sinkBegin(t, p, id, 2, 1, "data", 2, 2)
	exec(t, p, `SELECT omp_audit_ext.resume_sink($1,2,1)`, id)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, b)
}
func TestSinkPurgePromotionAndGap(t *testing.T) {
	p, o, id := sinkFixture(t, false)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old.sink','fixture',now()-interval '4000 days')`)
	drain(t, p)
	exec(t, p, `SELECT public.omp_purge_audit_log(30,100)`)
	if count(t, p, `SELECT purged_seq FROM omp_audit.retention_floor`) != 1 {
		t.Fatal("optional sink held purge")
	}
	// Purge wins immediately before promotion, without any expiry pass.
	sinkReject(t, p, updateSinkSQL, id, 1, true)
	exec(t, p, `SELECT omp_audit_ext.expire_sink($1,1,0)`, id)
	exec(t, p, `SELECT omp_audit_ext.resume_sink($1,1,0)`, id)
	sinkReject(t, p, `SELECT omp_audit_ext.resume_sink($1,1,0)`, id)
	sinkReject(t, p, updateSinkSQL, id, 1, true)
	exec(t, o, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	token := sinkBegin(t, p, id, 1, 0, "gap", 1, 1)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, token)
	exec(t, p, updateSinkSQL, id, 1, true)
	// New enrollment is exactly the purged boundary, never the current tip.
	exec(t, p, `SELECT omp_audit_ext.delete_sink($1,2)`, id)
	exec(t, p, createSinkSQL, id, false)
	if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("wrong enrollment boundary")
	}
}
func TestSinkFloorSnapshotFence(t *testing.T) {
	p, _, id := sinkFixture(t, false)
	tx, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var revision int64
	if err = tx.QueryRow(ctx, `SELECT consumer_revision FROM omp_audit.retention_floor`).Scan(&revision); err != nil {
		t.Fatal(err)
	}
	exec(t, p, updateSinkSQL, id, 1, true)
	_, err = tx.Exec(ctx, `SELECT public.omp_purge_audit_log(30,100)`)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "40001" {
		t.Fatalf("expected snapshot serialization failure: %v", err)
	}
}
func TestSinkRequiredCapAndAgeOnly(t *testing.T) {
	p, o, id := sinkFixture(t, true)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old.sink','fixture',now()-interval '4000 days')`)
	exec(t, p, `SELECT public.omp_purge_audit_log(30,100)`)
	if count(t, p, `SELECT count(*) FROM public.audit_log WHERE action='old.sink'`) != 1 {
		t.Fatal("age-only path bypassed sink")
	}
	drain(t, p)
	for _, state := range []string{"active", "paused"} {
		// Owner fixture models a disabled or paused required sink; the cap has no filters.
		exec(t, o, `UPDATE omp_audit_ext.sinks SET enabled=false,state=$2 WHERE id=$1`, id, state)
		exec(t, p, `SELECT public.omp_purge_audit_log(30,100)`)
		if count(t, p, `SELECT count(*) FROM public.audit_log WHERE action='old.sink'`) != 1 {
			t.Fatal("required cap bypassed")
		}
	}
	sinkReject(t, p, `SELECT omp_audit_ext.expire_sink($1,1,0)`, id)
}
func TestSinkOversizedHold(t *testing.T) {
	p, o, id := sinkFixture(t, true)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,metadata) VALUES('system','test','test',jsonb_build_object('large',repeat('x',17*1024*1024)))`)
	drain(t, p)
	exec(t, o, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	b := sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, b)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'held',NULL,false)`, id, b)
	if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 0 {
		t.Fatal("held passed oversized row")
	}
	b = sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	sinkReject(t, p, `SELECT omp_audit_ext.acknowledge_oversized($1,2,1)`, id)
	sinkReject(t, p, `SELECT omp_audit_ext.acknowledge_oversized($1,1,2)`, id)
	exec(t, p, `SELECT omp_audit_ext.acknowledge_oversized($1,1,1)`, id)
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'held',NULL,false)`, id, b)
	if count(t, p, `SELECT cursor_seq FROM omp_audit_ext.sinks WHERE id=$1`, id) != 1 {
		t.Fatal("ack did not advance exactly one")
	}
}

func TestSinkRetryKindAndStateLockOrder(t *testing.T) {
	p, o, id := sinkFixture(t, false)
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','old.sink','fixture',now()-interval '4000 days')`)
	drain(t, p)
	exec(t, o, `SELECT omp_audit_ext.set_sinks_enabled(true,'0.15.0')`)
	a := sinkBegin(t, p, id, 1, 0, "data", 1, 1)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'failed','timeout',false)`, id, a)
	exec(t, p, `SELECT public.omp_purge_audit_log(30,100)`)
	exec(t, p, `SELECT omp_audit_ext.resume_sink($1,1,0)`, id)
	b := sinkBegin(t, p, id, 1, 0, "gap", 1, 1)
	var kind string
	if err := p.QueryRow(ctx, `SELECT inflight_kind FROM omp_audit_ext.sinks WHERE id=$1`, id).Scan(&kind); err != nil || kind != "gap" {
		t.Fatalf("retry kind: %s %v", kind, err)
	}
	sinkReject(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, a)
	exec(t, p, `SELECT omp_audit_ext.finish_attempt($1,$2,'ok',NULL,false)`, id, b)
	// Hold state in another transaction. Sink configuration must never wait for it.
	tx, err := o.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT 1 FROM omp_audit.state WHERE singleton FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	cfg, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer cfg.Rollback(ctx)
	if _, err = cfg.Exec(ctx, `SET LOCAL lock_timeout='500ms'`); err != nil {
		t.Fatal(err)
	}
	if _, err = cfg.Exec(ctx, updateSinkSQL, id, 1, true); err != nil {
		t.Fatalf("sink transition locked state: %v", err)
	}
	if err = cfg.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	// Pin the floor-before-sink ordering and definer settings in every transition.
	if count(t, o, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='omp_audit_ext' AND p.proname IN ('update_sink','delete_sink','begin_attempt','finish_attempt','expire_sink','resume_sink','acknowledge_oversized') AND (position('FROM omp_audit.retention_floor' IN prosrc)>position('FROM omp_audit_ext.sinks' IN prosrc) OR NOT prosecdef OR NOT proconfig @> ARRAY['search_path=pg_catalog, pg_temp','TimeZone=UTC'])`) != 0 {
		t.Fatal("unsafe sink lock order or settings")
	}
}
