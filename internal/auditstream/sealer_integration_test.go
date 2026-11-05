package auditstream

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
	"github.com/pressly/goose/v3"
)

var ctx = context.Background()

func exec(t *testing.T, p *pgxpool.Pool, q string, args ...any) {
	t.Helper()
	if _, err := p.Exec(ctx, q, args...); err != nil {
		t.Fatal(err)
	}
}
func count(t *testing.T, p *pgxpool.Pool, q string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := p.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
func drain(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if _, err := (Sealer{p}).Batch(ctx); err != nil {
			t.Fatal(err)
		}
		if count(t, p, `SELECT count(*) FROM public.audit_log a WHERE NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid OR c.legacy_id=a.id AND a.txid IS NULL)`) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("watermark did not clear within two minutes (cluster-wide writing transaction)")
}
func waitWatermark(t *testing.T, p *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		if count(t, p, `SELECT count(*) FROM public.audit_log WHERE txid>=pg_snapshot_xmin(pg_current_snapshot())`) == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("cluster watermark blocked")
}

const insert = `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','test','test') RETURNING id`

func TestWatermarkNegativeControl(t *testing.T) {
	p, _ := testutil.NewDB(t)
	drain(t, p)
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var early, late int64
	if err := tx.QueryRow(ctx, insert).Scan(&early); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(ctx, insert).Scan(&late); err != nil {
		t.Fatal(err)
	}
	max := count(t, p, `SELECT max(id) FROM public.audit_log`)
	if max != late {
		t.Fatal("negative control setup")
	}
	if n, err := (Sealer{p}).Batch(ctx); err != nil || n != 0 {
		t.Fatalf("watermark must hold: %d %v", n, err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM public.audit_log WHERE id>$1`, max) != 0 || count(t, p, `SELECT count(*) FROM public.audit_log WHERE id=$1 AND id<=$2`, early, max) != 1 {
		t.Fatal("id tailing did not lose early row")
	}
	drain(t, p)
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE audit_id IN ($1,$2)`, early, late) != 2 {
		t.Fatal("watermark lost rows")
	}
}
func TestWatermarkConcurrentWriters(t *testing.T) {
	p, _ := testutil.NewDB(t)
	var wg sync.WaitGroup
	for w := 0; w < 24; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			random := rand.New(rand.NewPCG(uint64(w), 38))
			for i := 0; i < 400; i++ {
				tx, err := p.Begin(ctx)
				if err != nil {
					t.Error(err)
					return
				}
				_, err = tx.Exec(ctx, `SELECT 1; SAVEPOINT s`)
				if err == nil {
					_, err = tx.Exec(ctx, insert)
				}
				if err == nil && i%3 == 0 {
					_, err = tx.Exec(ctx, `ROLLBACK TO SAVEPOINT s`)
				}
				if err == nil {
					_, err = tx.Exec(ctx, insert)
				}
				if err != nil {
					t.Error(err)
					_ = tx.Rollback(ctx)
					return
				}
				time.Sleep(time.Duration(random.IntN(4)) * time.Millisecond)
				if i%10 == 0 {
					_ = tx.Rollback(ctx)
				} else if err := tx.Commit(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	for {
		select {
		case <-done:
			drain(t, p)
			if count(t, p, `SELECT count(*) FROM public.audit_log a WHERE NOT EXISTS(SELECT 1 FROM omp_audit.chain c WHERE c.row_uid=a.row_uid OR c.legacy_id=a.id AND a.txid IS NULL)`) != 0 {
				t.Fatal("missing")
			}
			if count(t, p, `SELECT count(*) FROM omp_audit.chain`) != count(t, p, `SELECT count(*) FROM public.audit_log`) {
				t.Fatal("phantom or duplicate")
			}
			return
		default:
			if _, err := (Sealer{p}).Batch(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
}
func TestStampInsertCopyAndReuse(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	drain(t, p)
	var id int64
	var uid uuid.UUID
	var xid string
	if err := p.QueryRow(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type,txid,row_uid) VALUES('system','forged','test','1','00000000-0000-4000-8000-000000000000') RETURNING id,row_uid,txid::text`).Scan(&id, &uid, &xid); err != nil {
		t.Fatal(err)
	}
	if xid == "1" || uid == uuid.MustParse("00000000-0000-4000-8000-000000000000") {
		t.Fatal("forgery survived")
	}
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type,txid,row_uid) VALUES('system','null','test',NULL,NULL)`)
	conn, err := p.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = conn.Conn().PgConn().CopyFrom(ctx, strings.NewReader("system\tcopy\ttest\t\\N\t\\N\nsystem\tcopy\ttest\t1\t00000000-0000-4000-8000-000000000000\n"), `COPY public.audit_log(actor_kind,action,target_type,txid,row_uid) FROM STDIN`)
	conn.Release()
	if err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT count(*) FROM public.audit_log WHERE action IN ('null','copy') AND (txid IS NULL OR row_uid IS NULL OR txid='1'::xid8 OR row_uid='00000000-0000-4000-8000-000000000000')`) != 0 {
		t.Fatal("copy missing uid")
	}
	drain(t, p)
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SET LOCAL omp.audit_purge='on'`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM public.audit_log WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	exec(t, p, `INSERT INTO public.audit_log(id,actor_kind,action,target_type) OVERRIDING SYSTEM VALUE VALUES($1,'system','reused','test')`, id)
	drain(t, p)
	if count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE audit_id=$1`, id) != 2 {
		t.Fatal("reused ID lost")
	}
}
func TestSQLGolden(t *testing.T) {
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		r := vectorRow(v.JSON)
		var hash string
		if err := owner.QueryRow(ctx, `SELECT encode(omp_audit.summary(a),'hex') FROM (SELECT $1::timestamptz occurred_at,'team.create'::text action,'system'::text actor_kind,NULL::uuid actor_user_id,NULL::uuid team_id,'team'::text target_type,''::text target_id,$2::text request_id,NULL::uuid actor_token_id) x CROSS JOIN LATERAL (SELECT jsonb_populate_record(NULL::public.audit_log,to_jsonb(x)) a) y`, r.OccurredAt, r.RequestID).Scan(&hash); err != nil {
			t.Fatal(err)
		}
		if hash != v.Summary {
			t.Fatal("SQL summary differs")
		}
		// Actual seal recomputes chain hash in SQL with the same Go record layout.
		exec(t, p, `INSERT INTO public.audit_log(occurred_at,actor_kind,action,target_type,request_id,after_state,metadata) VALUES($1,'system','team.create','team',$2,'null'::jsonb,$3::jsonb)`, r.OccurredAt, r.RequestID, v.JSON)
	}
	drain(t, p)
}
func candidate(t *testing.T, p *pgxpool.Pool) Record {
	t.Helper()
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','candidate','test')`)
	var stream uuid.UUID
	var epoch uint32
	var seq int64
	var prev []byte
	if err := p.QueryRow(ctx, `SELECT stream_id,epoch,last_seq,last_chain_hash FROM omp_audit.state`).Scan(&stream, &epoch, &seq, &prev); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := p.QueryRow(ctx, `SELECT to_jsonb(a) FROM public.audit_log a WHERE action='candidate' ORDER BY id DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var r Row
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	r.BeforeState = nil
	r.AfterState = nil
	var previous [32]byte
	copy(previous[:], prev)
	rec, _, err := NewRecord(stream, epoch, seq+1, previous, r)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}
func TestSealBatchRejects(t *testing.T) {
	for _, name := range []string{"summary", "chain", "seq", "digest", "oversize", "rebasing", "cursor", "reused", "kind", "flags", "empty", "gap"} {
		t.Run(name, func(t *testing.T) {
			p, _ := testutil.NewDB(t)
			owner := testutil.OwnerPool(t, p)
			drain(t, p)
			if name == "gap" {
				// An unsealed committed row below the candidate: sealing the candidate alone would skip it.
				exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','skipped','test')`)
			}
			rec := candidate(t, p)
			waitWatermark(t, p)
			mode := "fast"
			records := []Record{rec}
			switch name {
			case "kind":
				records[0].Kind = "checkpoint"
			case "flags":
				records[0].Flags = 4
			case "empty":
				records = []Record{}
			case "summary":
				records[0].Summary = strings.Repeat("00", 32)
			case "chain":
				records[0].Chain = strings.Repeat("00", 32)
			case "seq":
				records[0].Seq++
			case "digest":
				records[0].Entry = "00"
			case "oversize":
				records = make([]Record, 1001)
			case "rebasing":
				exec(t, owner, `UPDATE omp_audit.state SET status='rebasing'`)
			case "cursor":
				exec(t, owner, `UPDATE omp_audit.state SET cursor_txid='18446744073709551615'`)
			case "reused":
				raw, _ := json.Marshal(records)
				exec(t, p, `SELECT omp_audit.seal_batch($1,$2::jsonb)`, mode, raw)
				records[0].Seq++
			}
			raw, err := json.Marshal(records)
			if err != nil {
				t.Fatal(err)
			}
			before := count(t, p, `SELECT last_seq FROM omp_audit.state`)
			_, err = p.Exec(ctx, `SELECT omp_audit.seal_batch($1,$2::jsonb)`, mode, raw)
			expected := map[string]string{"summary": "summary mismatch", "chain": "chain mismatch", "seq": "invalid record", "digest": "invalid digest", "oversize": "invalid batch length", "rebasing": "stale stream status", "cursor": "cursor regression", "reused": "stale identity", "kind": "invalid record", "flags": "invalid record", "empty": "invalid batch length", "gap": "watermark gap"}[name]
			if err == nil || !strings.Contains(err.Error(), expected) {
				t.Fatalf("expected %s, got %v", expected, err)
			}
			if count(t, p, `SELECT last_seq FROM omp_audit.state`) != before {
				t.Fatal("rejected batch changed state")
			}

		})
	}
}
func TestAuditRuntimeBoundary(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	p, _ := testutil.NewDB(t)
	for _, q := range []string{`UPDATE omp_audit.state SET status='rebasing'`, `DELETE FROM omp_audit.chain`, `INSERT INTO omp_audit.chain(seq) VALUES(99)`, `SELECT omp_audit.scalar('x'::bytea)`, `SELECT omp_audit.summary(NULL::public.audit_log)`, `SET session_replication_role='replica'`, `CREATE TABLE omp_audit.evil(id int)`} {
		if _, err := p.Exec(ctx, q); err == nil {
			t.Fatalf("runtime accepted %s", q)
		}
	}
	drain(t, p)
}

// Pin digest representation too: accidental base64 encodings must not cross the
// SQL boundary (the JSON records carry lowercase hex, never bytea JSON).
func TestDigestHexLength(t *testing.T) {
	r := vectorRow(`{}`)
	sh := SummaryHash(r)
	if len(hex.EncodeToString(sh[:])) != 64 {
		t.Fatal("digest")
	}
}

func TestHistorySeamAndSQLChainGolden(t *testing.T) {
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(v.JSON, func(t *testing.T) {
			p, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
				db := stdlib.OpenDBFromPool(owner)
				defer db.Close()
				provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
				if err != nil {
					return err
				}
				if _, err := provider.UpTo(ctx, 56); err != nil {
					return err
				}
				// Retired-platform migration may have written history; remove it only
				// through the trusted owner's existing purge flag for this fixture.
				exec(t, owner, `BEGIN; SET LOCAL omp.audit_purge='on'; DELETE FROM public.audit_log; COMMIT`)
				r := vectorRow(v.JSON)
				exec(t, owner, `INSERT INTO public.audit_log(id,occurred_at,actor_kind,action,target_type,target_id,request_id,after_state,metadata) OVERRIDING SYSTEM VALUE VALUES(42,$1,'system','team.create','team','',$2,'null'::jsonb,$3::jsonb)`, r.OccurredAt, r.RequestID, v.JSON)
				return store.Migrate(ctx, owner, testutil.Logger(), role)
			})
			owner := testutil.OwnerPool(t, p)
			exec(t, owner, `UPDATE omp_audit.state SET stream_id='00112233-4455-4677-8899-aabbccddeeff',last_chain_hash=decode($1,'hex')`, v.Genesis)
			exec(t, p, `INSERT INTO public.audit_log(id,actor_kind,action,target_type) OVERRIDING SYSTEM VALUE VALUES(2,'system','fast-low-id','test')`)
			n, err := (Sealer{p}).Batch(ctx)
			if err != nil || n != 1 {
				t.Fatalf("history: %d %v", n, err)
			}
			var sh, eh, ch string
			if err := p.QueryRow(ctx, `SELECT encode(summary_hash,'hex'),encode(entry_hash,'hex'),encode(chain_hash,'hex') FROM omp_audit.chain WHERE seq=1 AND legacy_id=42`).Scan(&sh, &eh, &ch); err != nil {
				t.Fatal(err)
			}
			if sh != v.Summary || eh != v.Entry || ch != v.Chain {
				t.Fatalf("SQL golden mismatch %s %s %s", sh, eh, ch)
			}
			drain(t, p)
			if count(t, p, `SELECT count(*) FROM omp_audit.chain`) != 2 || count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE audit_id=2 AND row_uid IS NOT NULL`) != 1 {
				t.Fatal("history-fast seam gap")
			}
		})
	}
}

func TestInterruptedIndexBuild(t *testing.T) {
	p, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err := provider.UpTo(ctx, 58); err != nil {
			return err
		}
		exec(t, owner, `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','index','test'),('system','index','test')`)
		// A failed concurrent unique build leaves the same invalid catalog state
		// as an interrupted ordinary build, without timing-dependent cancellation.
		if _, err := owner.Exec(ctx, `CREATE UNIQUE INDEX CONCURRENTLY audit_log_stream_idx ON public.audit_log((1))`); err == nil {
			t.Fatal("negative control must fail")
		}
		if count(t, owner, `SELECT count(*) FROM pg_index WHERE indexrelid='public.audit_log_stream_idx'::regclass AND NOT indisvalid`) != 1 {
			t.Fatal("no invalid index left")
		}
		return store.Migrate(ctx, owner, testutil.Logger(), role)
	})
	if count(t, p, `SELECT count(*) FROM pg_index WHERE indexrelid='public.audit_log_stream_idx'::regclass AND indisvalid AND NOT indisunique`) != 1 {
		t.Fatal("invalid build not repaired")
	}
}

func TestAuditInspectorRejectsExcessGrants(t *testing.T) {
	t.Setenv("OMP_TEST_SPLIT_ROLES", "1")
	p, _ := testutil.NewDB(t)
	owner := testutil.OwnerPool(t, p)
	role := p.Config().ConnConfig.User
	quoted := pgx.Identifier{role}.Sanitize()
	for _, grant := range []string{`GRANT UPDATE(status) ON omp_audit.state TO `, `GRANT CREATE ON SCHEMA omp_audit TO `, `GRANT EXECUTE ON FUNCTION omp_audit.scalar(bytea) TO `, `GRANT SELECT ON omp_audit.state TO `} {
		q := grant + quoted
		if strings.HasPrefix(grant, "GRANT SELECT") {
			q += " WITH GRANT OPTION"
		}
		exec(t, owner, q)
		safety, err := store.InspectRoles(ctx, p, "", true)
		if err != nil {
			t.Fatal(err)
		}
		if safety.Safe() {
			t.Fatal("inspector accepted " + q)
		}
		conn, err := owner.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		err = store.ReconcileRuntimeGrants(ctx, conn.Conn(), role)
		conn.Release()
		if err != nil {
			t.Fatal(err)
		}
	}
	admin, err := pgx.Connect(ctx, testutil.DatabaseURL())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, `GRANT SET ON PARAMETER session_replication_role TO `+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, `REVOKE SET ON PARAMETER session_replication_role FROM `+quoted)
	safety, err := store.InspectRoles(ctx, p, "", true)
	if err != nil {
		t.Fatal(err)
	}
	if safety.Safe() || !strings.Contains(safety.Detail(), "SET session_replication_role") {
		t.Fatal("parameter privilege not detected")
	}
}

func TestClusterWatermarkWriterAndReadOnly(t *testing.T) {
	p, _ := testutil.NewDB(t)
	other, _ := testutil.NewDB(t)
	drain(t, p)
	tx, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_current_xact_id()`); err != nil {
		t.Fatal(err)
	}
	exec(t, p, `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','other-db-blocked','test')`)
	if n, err := (Sealer{p}).Batch(ctx); err != nil || n != 0 {
		t.Fatalf("other writer must block: %d %v", n, err)
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	ro, err := other.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Rollback(ctx)
	if _, err := ro.Exec(ctx, `SELECT 1`); err != nil {
		t.Fatal(err)
	}
	drain(t, p)
}

func TestStampUsesTopLevelXid(t *testing.T) {
	p, _ := testutil.NewDB(t)
	tx, err := p.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	var top, stamped string
	if err := tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&top); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SAVEPOINT nested`); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, `INSERT INTO public.audit_log(actor_kind,action,target_type) VALUES('system','nested','test') RETURNING txid::text`).Scan(&stamped); err != nil {
		t.Fatal(err)
	}
	if top != stamped {
		t.Fatal("stamped subtransaction xid")
	}
}

func TestBatchRollbackAndStaleReread(t *testing.T) {
	p, _ := testutil.NewDB(t)
	drain(t, p)
	first := candidate(t, p)
	second := candidate(t, p)
	waitWatermark(t, p)
	before := count(t, p, `SELECT last_seq FROM omp_audit.state`)
	second.Seq = first.Seq + 1 // deliberately retain the wrong predecessor-derived hash
	raw, err := json.Marshal([]Record{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `SELECT omp_audit.seal_batch('fast',$1::jsonb)`, raw); err == nil || !strings.Contains(err.Error(), "chain mismatch") {
		t.Fatalf("expected second-record chain rejection: %v", err)
	}
	if count(t, p, `SELECT last_seq FROM omp_audit.state`) != before || count(t, p, `SELECT count(*) FROM omp_audit.chain WHERE seq>$1`, before) != 0 {
		t.Fatal("partial rejected batch persisted")
	}
	raw, err = json.Marshal([]Record{first})
	if err != nil {
		t.Fatal(err)
	}
	exec(t, p, `SELECT omp_audit.seal_batch('fast',$1::jsonb)`, raw)
	// An already selected batch is stale. The next real sealer pass must select
	// the remaining row afresh, not loop retrying the rejected identity.
	if _, err := p.Exec(ctx, `SELECT omp_audit.seal_batch('fast',$1::jsonb)`, raw); err == nil {
		t.Fatal("accepted stale batch")
	}
	drain(t, p)
	if count(t, p, `SELECT last_seq FROM omp_audit.state`) != before+2 {
		t.Fatal("rollback created gap or stale candidate stranded row")
	}
}

// History is sealed strictly in id order: a caller cannot seal a later legacy
// row past an unsealed earlier one, nor go back below the history cursor.
func TestHistoryCannotSkip(t *testing.T) {
	p, _ := testutil.NewDBWithMigration(t, func(ctx context.Context, owner *pgxpool.Pool, role string) error {
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			return err
		}
		if _, err := provider.UpTo(ctx, 56); err != nil {
			return err
		}
		exec(t, owner, `BEGIN; SET LOCAL omp.audit_purge='on'; DELETE FROM public.audit_log; COMMIT`)
		exec(t, owner, `INSERT INTO public.audit_log(id,actor_kind,action,target_type) OVERRIDING SYSTEM VALUE VALUES(10,'system','legacy-a','test'),(20,'system','legacy-b','test')`)
		return store.Migrate(ctx, owner, testutil.Logger(), role)
	})
	record := func(id int64) Record {
		t.Helper()
		var stream uuid.UUID
		var epoch uint32
		var seq int64
		var prev []byte
		if err := p.QueryRow(ctx, `SELECT stream_id,epoch,last_seq,last_chain_hash FROM omp_audit.state`).Scan(&stream, &epoch, &seq, &prev); err != nil {
			t.Fatal(err)
		}
		var raw []byte
		if err := p.QueryRow(ctx, `SELECT to_jsonb(a) FROM public.audit_log a WHERE id=$1`, id).Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var r Row
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		r.BeforeState, r.AfterState = nil, nil
		var previous [32]byte
		copy(previous[:], prev)
		rec, _, err := NewRecord(stream, epoch, seq+1, previous, r)
		if err != nil {
			t.Fatal(err)
		}
		return rec
	}
	seal := func(id int64) error {
		raw, err := json.Marshal([]Record{record(id)})
		if err != nil {
			t.Fatal(err)
		}
		_, err = p.Exec(ctx, `SELECT omp_audit.seal_batch('history',$1::jsonb)`, raw)
		return err
	}
	if err := seal(20); err == nil || !strings.Contains(err.Error(), "history gap") {
		t.Fatalf("skipping legacy row 10: %v", err)
	}
	if err := seal(10); err != nil {
		t.Fatal(err)
	}
	if err := seal(10); err == nil {
		t.Fatal("history regression accepted")
	}
	if err := seal(20); err != nil {
		t.Fatal(err)
	}
	if count(t, p, `SELECT history_id FROM omp_audit.state`) != 20 {
		t.Fatal("history cursor")
	}
}
