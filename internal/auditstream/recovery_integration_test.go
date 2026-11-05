package auditstream

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/migrations"
	"github.com/pressly/goose/v3"
	"os"
	osexec "os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestIncarnationRecovery(t *testing.T) {
	for _, rebase := range []bool{false, true} {
		t.Run(fmt.Sprint(rebase), func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			owner := testutil.OwnerPool(t, p)
			s := Sealer{p}
			drain(t, p)
			exec(t, owner, `UPDATE omp_audit.state SET system_identifier='1'`)
			exec(t, p, insert)
			if n, err := s.Batch(ctx); err != nil || n != 0 {
				t.Fatalf("halt: %d %v", n, err)
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE status='halted_incarnation'`) != 1 {
				t.Fatal("not halted")
			}
			if p.Config().ConnConfig.User != owner.Config().ConnConfig.User {
				if err := (Sealer{p}).Rebind(ctx); err == nil {
					t.Fatal("runtime rebind succeeded")
				}
				if err := (Sealer{p}).Rebase(ctx, nil); err == nil {
					t.Fatal("runtime rebase succeeded")
				}
			}
			if rebase {
				if err := (Sealer{owner}).Rebase(ctx, nil); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := (Sealer{owner}).Rebind(ctx); err != nil {
					t.Fatal(err)
				}
			}
			drain(t, p)
			if rebase {
				checkEpoch(t, p)
			}
		})
	}
}

func TestTimelineEpoch(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	drain(t, p)
	exec(t, owner, `UPDATE omp_audit.state SET timeline=timeline+1`)
	if _, err := (Sealer{p}).Batch(ctx); err != nil {
		t.Fatal(err)
	}
	checkEpoch(t, p)
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start' AND epoch_summary->>'reason'='timeline'`) != 1 {
		t.Fatal("missing timeline declaration")
	}
}

func checkEpoch(t *testing.T, pool interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}) {
	t.Helper()
	var raw []byte
	var hash string
	var stream uuid.UUID
	var epoch uint32
	var seq int64
	var at time.Time
	var chain string
	if err := pool.QueryRow(ctx, `SELECT epoch_summary,encode(summary_hash,'hex'),(SELECT stream_id FROM omp_audit.state WHERE singleton),epoch,seq,occurred_at,encode(chain_hash,'hex') FROM omp_audit.chain WHERE kind='epoch_start' ORDER BY seq DESC LIMIT 1`).Scan(&raw, &hash, &stream, &epoch, &seq, &at, &chain); err != nil {
		t.Fatal(err)
	}
	var e EpochSummary
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", EpochSummaryHash(e)) != hash {
		t.Fatal("SQL/Go epoch summary mismatch")
	}
	prev, _ := hex.DecodeString(e.PredecessorHash)
	record := EpochRecordBytes(stream, epoch, seq, at, EpochSummaryHash(e))
	ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), prev...), record...))
	if fmt.Sprintf("%x", ch) != chain {
		t.Fatal("SQL/Go epoch chain mismatch")
	}
}

func TestRebaseForeignAndResume(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	exec(t, p, insert)
	// A logical-replication apply worker can preserve a foreign transaction id.
	exec(t, o, `ALTER TABLE public.audit_log DISABLE TRIGGER audit_log_stream_stamp`)
	exec(t, o, `INSERT INTO public.audit_log(actor_kind,action,target_type,txid,row_uid) VALUES('system','foreign','test','900000000000',gen_random_uuid())`)
	exec(t, o, `ALTER TABLE public.audit_log ENABLE TRIGGER audit_log_stream_stamp`)
	if err := (Sealer{o}).Rebase(ctx, nil); err != nil {
		t.Fatal(err)
	}
	exec(t, p, insert)
	drain(t, p)
	if count(t, p, `SELECT count(*) FROM omp_audit.chain c JOIN public.audit_log a ON c.row_uid=a.row_uid WHERE a.action='foreign'`) != 1 {
		t.Fatal("foreign row lost or duplicated")
	}
	// Simulate death after A commits, before the first marker is sealed.
	exec(t, o, `SELECT omp_audit.prepare_epoch('rebase',NULL)`)
	exec(t, o, `UPDATE omp_audit.state SET status='rebasing',rebase_f=pg_current_xact_id(),cursor_txid=pg_current_xact_id(),cursor_id=0`)
	exec(t, p, insert)
	if _, err := p.Exec(ctx, `SELECT omp_audit.seal_batch('epoch','[{"kind":"epoch_start","summary_hash":"0000000000000000000000000000000000000000000000000000000000000000"}]')`); err == nil {
		t.Fatal("bad epoch accepted")
	}
	if err := (Sealer{o}).Rebase(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 2 {
		t.Fatal("resume repeated marker")
	}
	// Simulate death after epoch_start, while B is streaming candidates.
	exec(t, o, `UPDATE omp_audit.state SET status='rebasing'`)
	exec(t, p, insert)
	if err := (Sealer{o}).Rebase(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 2 {
		t.Fatal("resume repeated marker")
	}
	drain(t, p)
	n := count(t, p, `SELECT last_seq+10 FROM omp_audit.state`)
	if err := (Sealer{o}).Rebase(ctx, &n); err != nil {
		t.Fatal(err)
	}
	checkEpoch(t, p)
	if count(t, p, `SELECT last_seq FROM omp_audit.state`) != n+1 {
		t.Fatal("resume sequence")
	}
}

func TestSweepGapAndOwnership(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	var id int64
	if err := p.QueryRow(ctx, insert).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if err := (Sealer{p}).sealIDs(ctx, "sweep", []int64{id}); err == nil {
		t.Fatal("sweep stole fast row")
	}
	if err := (Sealer{p}).sealIDs(ctx, "rebase", []int64{id}); err == nil {
		t.Fatal("rebase while running")
	}
	drain(t, p)
	exec(t, o, `ALTER TABLE public.audit_log DISABLE TRIGGER audit_log_stream_stamp`)
	exec(t, o, `INSERT INTO public.audit_log(actor_kind,action,target_type,txid,row_uid) SELECT 'system','gap','test',cursor_txid,gen_random_uuid() FROM omp_audit.state`)
	exec(t, o, `ALTER TABLE public.audit_log ENABLE TRIGGER audit_log_stream_stamp`)
	// The planted row must be behind the cursor in both coordinates.
	exec(t, o, `UPDATE omp_audit.state SET cursor_id=9223372036854775807,sweep_pending=true`)
	waitWatermark(t, p)
	if n, err := (Sealer{p}).Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("sweep %d %v", n, err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE flags=1`) != 1 {
		t.Fatal("missing late flag")
	}
	if n, err := (Sealer{p}).Sweep(ctx); err != nil || n != 0 {
		t.Fatalf("empty sweep %d %v", n, err)
	}
}

func TestRebaseLockBlockedOldXID(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	writer, err := p.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Rollback(ctx)
	if _, err = writer.Exec(ctx, `SELECT pg_current_xact_id(),pg_current_snapshot()`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	var pid uint32 = writer.Conn().PgConn().PID()
	blocked := false
	err = (Sealer{o}).rebase(ctx, nil, func(stage string) {
		if stage != "locked" {
			return
		}
		go func() {
			_, e := writer.Exec(ctx, insert)
			if e == nil {
				e = writer.Commit(ctx)
			}
			done <- e
		}()
		deadline := time.Now().Add(10 * time.Second)
		for count(t, o, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND NOT granted AND relation='public.audit_log'::regclass`, pid) == 0 {
			if time.Now().After(deadline) {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		blocked = true
	})
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if !blocked {
		t.Fatal("writer never blocked on SHARE lock")
	}
	waitWatermark(t, p)
	if n, err := (Sealer{p}).Batch(ctx); err != nil || n != 0 {
		t.Fatalf("fast stole blocked row: %d %v", n, err)
	}
	if n, err := (Sealer{p}).Sweep(ctx); err != nil || n != 1 {
		t.Fatalf("blocked row sweep: %d %v", n, err)
	}
}

func TestSweepExplain300k(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	exec(t, o, `INSERT INTO public.audit_log(actor_kind,action,target_type) SELECT 'system','explain','test' FROM generate_series(1,300000)`)
	exec(t, o, `UPDATE omp_audit.state SET cursor_txid=pg_current_xact_id(),cursor_id=9223372036854775807`)
	exec(t, o, `INSERT INTO omp_audit.chain(seq,kind,row_uid,legacy_id,audit_id,epoch,flags,occurred_at,summary_hash,entry_hash,chain_hash) SELECT row_number() OVER (ORDER BY id),'entry',row_uid,CASE WHEN txid IS NULL THEN id END,id,1,0,occurred_at,decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex') FROM public.audit_log`)
	exec(t, o, `ANALYZE public.audit_log; ANALYZE omp_audit.chain`)
	rows, err := p.Query(ctx, `EXPLAIN (ANALYZE,BUFFERS) `+sweepWindowQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var line string
		if err = rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		t.Log(line)
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestEpochGoldenSQLAndGo(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	raw, err := os.ReadFile("testdata/epoch_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Summary EpochSummary `json:"summary"`
		Hash    string       `json:"hash"`
		Record  string       `json:"record"`
		Chain   string       `json:"chain"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		if fmt.Sprintf("%x", EpochSummaryHash(v.Summary)) != v.Hash {
			t.Fatal("Go golden mismatch")
		}
		record, err := hex.DecodeString(v.Record)
		if err != nil {
			t.Fatal(err)
		}
		if len(record) != 119 {
			t.Fatal("golden record length")
		}
		sh := EpochSummaryHash(v.Summary)
		got := EpochRecordBytes(uuid.MustParse("00112233-4455-4677-8899-aabbccddeeff"), 2, int64(binary.BigEndian.Uint64(record[23:31])), time.UnixMicro(1700000000123456), sh)
		if hex.EncodeToString(got) != v.Record {
			t.Fatal("Go epoch record mismatch")
		}
		prev, _ := hex.DecodeString(v.Summary.PredecessorHash)
		ch := sha256.Sum256(append(append([]byte("OMP-AUDIT-EVIDENCE\x00CHAIN\x00V2\x00"), prev...), got...))
		if fmt.Sprintf("%x", ch) != v.Chain {
			t.Fatal("Go epoch chain mismatch")
		}
		e, _ := json.Marshal(v.Summary)
		var h string
		if err = o.QueryRow(ctx, `SELECT encode(omp_audit.epoch_summary($1::jsonb),'hex')`, e).Scan(&h); err != nil {
			t.Fatal(err)
		}
		if h != v.Hash {
			t.Fatal("SQL golden mismatch")
		}
	}
}

func TestRebaseCrashProcess(t *testing.T) {
	if url := os.Getenv("OMP_REBASE_CRASH_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Close()
		err = (Sealer{p}).rebase(ctx, nil, func(stage string) {
			if stage == os.Getenv("OMP_REBASE_CRASH_STAGE") {
				process, _ := os.FindProcess(os.Getpid())
				_ = process.Kill()
			}
		})
		t.Fatalf("crash hook did not kill process: %v", err)
	}
	for _, stage := range []string{"fenced", "marked"} {
		t.Run(stage, func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			o := testutil.OwnerPool(t, p)
			drain(t, p)
			execSQL := insert
			exec(t, p, execSQL)
			binary, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			child := osexec.Command(binary, "-test.run=^TestRebaseCrashProcess$")
			child.Env = append(os.Environ(), "OMP_REBASE_CRASH_URL="+o.Config().ConnString(), "OMP_REBASE_CRASH_STAGE="+stage)
			if err = child.Run(); err == nil {
				t.Fatal("child survived")
			}
			if exit, ok := err.(*osexec.ExitError); !ok || exit.ExitCode() != -1 {
				t.Fatalf("child did not die by signal: %v", err)
			}
			markers := int64(0)
			if stage == "marked" {
				markers = 1
			}
			if got := count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`); got != markers {
				t.Fatalf("wrong kill boundary: markers=%d want=%d", got, markers)
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE status='rebasing'`) != 1 {
				t.Fatal("missing persisted fence")
			}
			if err = (Sealer{o}).Rebase(ctx, nil); err != nil {
				t.Fatal(err)
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 1 {
				t.Fatal("duplicate epoch after process kill")
			}
			drain(t, p)
		})
	}
}

func TestRebindRefusesRegressedXmin(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	exec(t, o, `UPDATE omp_audit.state SET status='halted_incarnation',cursor_txid='900000000000'`)
	if err := (Sealer{o}).Rebind(ctx); err == nil {
		t.Fatal("regressed xmin accepted")
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE status='halted_incarnation'`) != 1 {
		t.Fatal("refusal changed status")
	}
}

func TestSweepSignedIdentityRange(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	exec(t, o, `ALTER TABLE public.audit_log DISABLE TRIGGER audit_log_stream_stamp`)
	exec(t, o, `INSERT INTO public.audit_log(id,actor_kind,action,target_type,txid,row_uid) OVERRIDING SYSTEM VALUE SELECT i,'system','signed-gap','test',cursor_txid,gen_random_uuid() FROM omp_audit.state CROSS JOIN unnest(ARRAY['-9223372036854775808'::bigint,-1::bigint]) i`)
	exec(t, o, `ALTER TABLE public.audit_log ENABLE TRIGGER audit_log_stream_stamp`)
	exec(t, o, `UPDATE omp_audit.state SET sweep_pending=true,sweep_scan_id=NULL,sweep_started_xmin=NULL`)
	waitWatermark(t, p)
	if n, err := (Sealer{p}).Sweep(ctx); err != nil || n != 2 {
		t.Fatalf("signed identity sweep %d %v", n, err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE flags=1 AND audit_id<0`) != 2 {
		t.Fatal("signed identity lost")
	}
}

func TestRecoveryBatchPersistsIncarnationHalt(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	var id int64
	if err := p.QueryRow(ctx, insert).Scan(&id); err != nil {
		t.Fatal(err)
	}
	exec(t, o, `UPDATE omp_audit.state SET system_identifier='1'`)
	if err := (Sealer{p}).sealIDs(ctx, "rebase", []int64{id}); err == nil {
		t.Fatal("incarnation mismatch reported success")
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE status='halted_incarnation'`) != 1 {
		t.Fatal("error rolled back incarnation halt")
	}
}

func TestRebaseLegacyHistoryAndLag(t *testing.T) {
	p, _ := testutil.NewDBWithMigration(t, func(c context.Context, o *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(o)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err = provider.UpTo(c, 57); err != nil {
			return err
		}
		if _, err = o.Exec(c, `INSERT INTO public.audit_log(actor_kind,action,target_type,occurred_at) VALUES('system','legacy','test',now()-interval '1 year')`); err != nil {
			return err
		}
		return store.Migrate(c, o, testutil.Logger(), role)
	})
	o := testutil.OwnerPool(t, p)
	if err := (Sealer{o}).Rebase(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM public.audit_log a,omp_audit.state s WHERE a.txid IS NULL AND a.id>s.history_id`) != 0 {
		t.Fatal("legacy cursor did not advance")
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE cursor_txid=rebase_f AND cursor_id=0`) != 1 {
		t.Fatal("rebase moved xid cursor")
	}
	if n, err := (Sealer{p}).Batch(ctx); err != nil || n != 0 {
		t.Fatalf("history reselected: %d %v", n, err)
	}
	var lag float64
	if err := p.QueryRow(ctx, lagQuery).Scan(&lag); err != nil {
		t.Fatal(err)
	}
	if lag != 0 {
		t.Fatalf("rebased legacy row still contributes lag: %f", lag)
	}
}

func TestSweepBoundaryRejectsDistantGap(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	exec(t, o, `INSERT INTO public.audit_log(actor_kind,action,target_type) SELECT 'system','window','test' FROM generate_series(1,5001)`)
	drain(t, p)
	exec(t, o, `ALTER TABLE public.audit_log DISABLE TRIGGER audit_log_stream_stamp`)
	var id int64
	if err := o.QueryRow(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type,txid,row_uid) SELECT 'system','distant-gap','test',cursor_txid,gen_random_uuid() FROM omp_audit.state RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	exec(t, o, `ALTER TABLE public.audit_log ENABLE TRIGGER audit_log_stream_stamp`)
	exec(t, o, `UPDATE omp_audit.state SET cursor_id=9223372036854775807,sweep_scan_id=NULL,sweep_started_xmin=NULL,sweep_pending=true`)
	waitWatermark(t, p)
	if err := (Sealer{p}).sealIDs(ctx, "sweep", []int64{id}); err == nil || !strings.Contains(err.Error(), "outside sweep window") {
		t.Fatalf("distant gap boundary: %v", err)
	}
	var total int64
	for i := 0; i < 3; i++ {
		n, err := (Sealer{p}).Sweep(ctx)
		if err != nil {
			t.Fatal(err)
		}
		total += n
	}
	if total != 1 {
		t.Fatalf("windowed sweep lost distant gap: %d", total)
	}
}

func TestRebaseResumeNumberIsStable(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	n := count(t, p, `SELECT last_seq+10 FROM omp_audit.state`)
	exec(t, o, `SELECT omp_audit.prepare_epoch('rebase',$1)`, n)
	exec(t, o, `UPDATE omp_audit.state SET status='rebasing',rebase_resume_after=$1,rebase_f=pg_current_xact_id(),cursor_txid=pg_current_xact_id(),cursor_id=0`, n)
	changed := n + 1
	if err := (Sealer{o}).Rebase(ctx, &changed); err == nil {
		t.Fatal("changed resume number accepted")
	}
	if err := (Sealer{o}).Rebase(ctx, &n); err != nil {
		t.Fatal(err)
	}
	exec(t, o, `UPDATE omp_audit.state SET status='rebasing'`)
	if err := (Sealer{o}).Rebase(ctx, &n); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 1 {
		t.Fatal("same-number retry duplicated marker")
	}
}

func TestRebindRefreshesTimelineWithoutEpoch(t *testing.T) {
	p, _ := testutil.NewDB(t)
	o := testutil.OwnerPool(t, p)
	drain(t, p)
	var epoch, cursorID int64
	var cursor string
	if err := p.QueryRow(ctx, `SELECT epoch,cursor_txid::text,cursor_id FROM omp_audit.state`).Scan(&epoch, &cursor, &cursorID); err != nil {
		t.Fatal(err)
	}
	exec(t, o, `UPDATE omp_audit.state SET system_identifier='1',timeline=timeline+1`)
	if _, err := (Sealer{p}).Batch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := (Sealer{o}).Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := (Sealer{p}).Batch(ctx); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.state WHERE epoch=$1 AND cursor_txid=$2::xid8 AND cursor_id=$3 AND timeline=('x'||substr(pg_walfile_name(pg_current_wal_lsn()),1,8))::bit(32)::bigint`, epoch, cursor, cursorID) != 1 {
		t.Fatal("rebind did not preserve epoch/cursor and refresh timeline")
	}
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 0 {
		t.Fatal("rebind caused an unintended epoch")
	}
}

func TestTimelineChangeDuringRebase(t *testing.T) {
	for _, marked := range []bool{false, true} {
		t.Run(fmt.Sprint(marked), func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			o := testutil.OwnerPool(t, p)
			drain(t, p)
			exec(t, o, `SELECT omp_audit.prepare_epoch('rebase',NULL)`)
			exec(t, o, `UPDATE omp_audit.state SET status='rebasing',rebase_f=pg_current_xact_id(),cursor_txid=pg_current_xact_id(),cursor_id=0`)
			// Model the old incarnation in state and its already prepared declaration;
			// the live insertion timeline now differs, exactly as after promotion.
			exec(t, o, `UPDATE omp_audit.state SET timeline=timeline+1,epoch_pending=jsonb_set(jsonb_set(epoch_pending,'{summary,old_timeline}',to_jsonb(timeline+1)),'{summary,new_timeline}',to_jsonb(timeline+1))`)
			if marked {
				exec(t, o, `SELECT omp_audit.append_epoch(NULL)`)
			}
			var id int64
			if err := p.QueryRow(ctx, insert).Scan(&id); err != nil {
				t.Fatal(err)
			}
			if err := (Sealer{o}).Rebase(ctx, nil); err != nil {
				t.Fatal(err)
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='epoch_start'`) != 2 {
				t.Fatal("missing or duplicated transition")
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE kind='entry' AND epoch=3 AND audit_id=$1`, id) != 1 {
				t.Fatal("data used the pre-promotion epoch")
			}
			checkEpoch(t, p)
		})
	}
}
