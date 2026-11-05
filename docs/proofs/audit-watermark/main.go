//go:build ignore

// Scratch proof for the #38 design (decision 93): does an xid8 snapshot-xmin
// watermark seal every committed audit row exactly once, when id tailing does
// not? Runs against a disposable PostgreSQL only; it drops and creates the
// databases wmproof and wmproof_other on that server. See docs/audit-streaming.md.
//
//	OMP_PROOF_URL=postgres://u:p@127.0.0.1:PORT/postgres \
//	OMP_PROOF_DB=postgres://u:p@127.0.0.1:PORT/wmproof \
//	OMP_PROOF_OTHER=postgres://u:p@127.0.0.1:PORT/wmproof_other \
//	go run ./docs/proofs/audit-watermark/main.go
package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var errAbort = errors.New("deliberate abort")

func must(err error) {
	if err != nil {
		panic(err)
	}
}

type cursor struct{ txid, id int64 }

// sealBatch is the proposed sealer read: one statement, so the watermark and
// the rows come from the same snapshot. Rows strictly below the watermark
// belong to finished transactions; (txid, id) order is total and stable.
const sealSQL = `
WITH wm AS (SELECT pg_snapshot_xmin(pg_current_snapshot()) AS x)
SELECT a.txid::text::bigint, a.id, (SELECT x FROM wm)::text::bigint
FROM audit_log a
WHERE a.txid IS NOT NULL
  AND a.txid < (SELECT x FROM wm)
  AND (a.txid, a.id) > ($1::bigint::text::xid8, $2::bigint)
ORDER BY a.txid, a.id
LIMIT $3`

func seal(ctx context.Context, pool *pgxpool.Pool, c cursor, limit int) (cursor, []int64, int64) {
	rows, err := pool.Query(ctx, sealSQL, c.txid, c.id, limit)
	must(err)
	defer rows.Close()
	var ids []int64
	var wm int64
	for rows.Next() {
		var tx, id int64
		must(rows.Scan(&tx, &id, &wm))
		if tx < c.txid || (tx == c.txid && id <= c.id) {
			panic("non-monotonic cursor")
		}
		c = cursor{tx, id}
		ids = append(ids, id)
	}
	must(rows.Err())
	return c, ids, wm
}

func main() {
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, os.Getenv("OMP_PROOF_URL"))
	must(err)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS wmproof WITH (FORCE)")
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS wmproof_other WITH (FORCE)")
	_, err = admin.Exec(ctx, "CREATE DATABASE wmproof")
	must(err)
	_, err = admin.Exec(ctx, "CREATE DATABASE wmproof_other")
	must(err)
	cfg, err := pgxpool.ParseConfig(os.Getenv("OMP_PROOF_DB"))
	must(err)
	cfg.MaxConns = 40
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	must(err)
	defer pool.Close()

	// --- 1. Expand-only DDL on a pre-populated table: no rewrite, old rows NULL.
	_, err = pool.Exec(ctx, `CREATE TABLE audit_log (
		id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		occurred_at timestamptz NOT NULL DEFAULT now(),
		action text NOT NULL, writer int NOT NULL DEFAULT 0)`)
	must(err)
	_, err = pool.Exec(ctx, `INSERT INTO audit_log (action) SELECT 'legacy' FROM generate_series(1, 200000)`)
	must(err)
	var fnBefore, fnAfter uint32
	must(pool.QueryRow(ctx, `SELECT relfilenode FROM pg_class WHERE relname='audit_log'`).Scan(&fnBefore))
	t0 := time.Now()
	_, err = pool.Exec(ctx, `ALTER TABLE audit_log ADD COLUMN txid xid8;
		ALTER TABLE audit_log ALTER COLUMN txid SET DEFAULT pg_current_xact_id()`)
	must(err)
	ddl := time.Since(t0)
	t0 = time.Now()
	_, err = pool.Exec(ctx, `CREATE INDEX CONCURRENTLY audit_log_txid_idx ON audit_log (txid, id) WHERE txid IS NOT NULL`)
	must(err)
	idx := time.Since(t0)
	must(pool.QueryRow(ctx, `SELECT relfilenode FROM pg_class WHERE relname='audit_log'`).Scan(&fnAfter))
	var legacyNull int64
	must(pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE txid IS NULL`).Scan(&legacyNull))
	fmt.Printf("1. DDL: add column + default %v, no rewrite=%v, legacy rows NULL=%d/200000; concurrent partial index %v\n",
		ddl.Round(time.Millisecond), fnBefore == fnAfter, legacyNull, idx.Round(time.Millisecond))
	// An insert that does not name txid (a previous release) still gets one.
	var gotTx bool
	must(pool.QueryRow(ctx, `INSERT INTO audit_log (action) VALUES ('old-binary') RETURNING txid IS NOT NULL`).Scan(&gotTx))
	fmt.Printf("   previous-release insert gets txid from the default: %v\n", gotTx)
	// Inside a savepoint, the default is still the top-level xid.
	tx, err := pool.Begin(ctx)
	must(err)
	var top, inSP string
	must(tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&top))
	_, err = tx.Exec(ctx, `SAVEPOINT s1`)
	must(err)
	must(tx.QueryRow(ctx, `INSERT INTO audit_log (action) VALUES ('sp') RETURNING txid::text`).Scan(&inSP))
	must(tx.Rollback(ctx))
	fmt.Printf("   savepoint insert txid equals top-level xid: %v\n", top == inSP)
	_, err = pool.Exec(ctx, `DELETE FROM audit_log`)
	must(err)

	// --- 2. Negative control and the same scenario under the watermark.
	t1, err := pool.Begin(ctx)
	must(err)
	var early int64
	must(t1.QueryRow(ctx, `INSERT INTO audit_log (action) VALUES ('early-id-late-commit') RETURNING id`).Scan(&early))
	var late int64
	must(pool.QueryRow(ctx, `INSERT INTO audit_log (action) VALUES ('late-id-early-commit') RETURNING id`).Scan(&late))
	// id tailing: read what is visible, advance to max id.
	var maxSeen int64
	must(pool.QueryRow(ctx, `SELECT coalesce(max(id),0) FROM audit_log`).Scan(&maxSeen))
	c, idsBefore, _ := seal(ctx, pool, cursor{}, 1000)
	must(t1.Commit(ctx))
	var missed int64
	must(pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE id <= $1 AND id <> $2`, maxSeen, late).Scan(&missed))
	var idTailNext int64
	must(pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE id > $1`, maxSeen).Scan(&idTailNext))
	_, idsAfter, _ := seal(ctx, pool, c, 1000)
	fmt.Printf("2. negative control: id tail advanced to %d while id %d was uncommitted; next id>cursor read returns %d rows -> id %d LOST (%v)\n",
		maxSeen, early, idTailNext, early, missed == 1 && idTailNext == 0)
	fmt.Printf("   watermark: first pass sealed %v (holds back), after commit sealed %v\n", idsBefore, idsAfter)
	_, err = pool.Exec(ctx, `DELETE FROM audit_log`)
	must(err)

	// --- 3. Randomized stress: concurrent writers with out-of-order commits,
	// savepoint rollbacks, whole-transaction aborts, read-before-write
	// (late xid assignment), while a sealer runs continuously.
	const writers = 24
	const txPerWriter = 400
	var committedIDs sync.Map
	var stop atomic.Bool
	var sealed []int64
	sealedSet := map[int64]bool{}
	dups := 0
	sealerDone := make(chan struct{})
	var passes int
	go func() {
		defer close(sealerDone)
		c := cursor{}
		for {
			last := stop.Load()
			nc, ids, _ := seal(ctx, pool, c, 500)
			c = nc
			passes++
			for _, id := range ids {
				if sealedSet[id] {
					dups++
				}
				sealedSet[id] = true
				sealed = append(sealed, id)
			}
			if last && len(ids) == 0 {
				return
			}
			if len(ids) == 0 {
				time.Sleep(time.Duration(rand.IntN(3)) * time.Millisecond)
			}
		}
	}()
	var wg sync.WaitGroup
	var aborted, spRolled atomic.Int64
	t0 = time.Now()
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(w), 38))
			for i := 0; i < txPerWriter; i++ {
				var mine, rolledBack []int64
				err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
					if r.IntN(3) == 0 { // read first: xid assigned late
						if _, err := tx.Exec(ctx, `SELECT pg_sleep($1)`, float64(r.IntN(4))/1000); err != nil {
							return err
						}
					}
					n := 1 + r.IntN(4)
					for k := 0; k < n; k++ {
						sp := r.IntN(6) == 0
						if sp {
							if _, err := tx.Exec(ctx, `SAVEPOINT s`); err != nil {
								return err
							}
						}
						var id int64
						if err := tx.QueryRow(ctx, `INSERT INTO audit_log (action, writer) VALUES ('x', $1) RETURNING id`, w).Scan(&id); err != nil {
							return err
						}
						if sp && r.IntN(2) == 0 {
							if _, err := tx.Exec(ctx, `ROLLBACK TO SAVEPOINT s`); err != nil {
								return err
							}
							rolledBack = append(rolledBack, id)
							spRolled.Add(1)
						} else {
							mine = append(mine, id)
						}
					}
					if _, err := tx.Exec(ctx, `SELECT pg_sleep($1)`, float64(r.IntN(8))/1000); err != nil { // commit delay
						return err
					}
					if r.IntN(10) == 0 {
						return errAbort
					}
					return nil
				})
				if errors.Is(err, errAbort) {
					aborted.Add(1)
					continue
				}
				must(err)
				for _, id := range mine {
					committedIDs.Store(id, true)
				}
			}
		}(w)
	}
	wg.Wait()
	writeDur := time.Since(t0)
	stop.Store(true)
	<-sealerDone
	var tableIDs []int64
	rows, err := pool.Query(ctx, `SELECT id FROM audit_log ORDER BY id`)
	must(err)
	for rows.Next() {
		var id int64
		must(rows.Scan(&id))
		tableIDs = append(tableIDs, id)
	}
	must(rows.Err())
	committed := 0
	committedIDs.Range(func(_, _ any) bool { committed++; return true })
	missing, extra := 0, 0
	for _, id := range tableIDs {
		if !sealedSet[id] {
			missing++
		}
	}
	tbl := map[int64]bool{}
	for _, id := range tableIDs {
		tbl[id] = true
	}
	for id := range sealedSet {
		if !tbl[id] {
			extra++
		}
	}
	idOrderInversions := 0
	for i := 1; i < len(sealed); i++ {
		if sealed[i] < sealed[i-1] {
			idOrderInversions++
		}
	}
	fmt.Printf("3. stress: %d writers x %d tx in %v; %d committed rows (client view) = %d rows in table; %d whole-tx aborts, %d savepoint rollbacks\n",
		writers, txPerWriter, writeDur.Round(time.Millisecond), committed, len(tableIDs), aborted.Load(), spRolled.Load())
	fmt.Printf("   sealer: %d passes, sealed %d, missing %d, phantom %d, duplicates %d; seal order differs from id order %d times (so id tailing would have been unsafe)\n",
		passes, len(sealed), missing, extra, dups, idOrderInversions)
	if missing != 0 || extra != 0 || dups != 0 || committed != len(tableIDs) {
		fmt.Println("   FAIL")
		os.Exit(1)
	}
	sort.Slice(tableIDs, func(i, j int) bool { return tableIDs[i] < tableIDs[j] })

	// --- 4. Lag: an open writing transaction in ANOTHER database on the same
	// cluster holds the watermark (xids are cluster-wide).
	other, err := pgx.Connect(ctx, os.Getenv("OMP_PROOF_OTHER"))
	must(err)
	otx, err := other.Begin(ctx)
	must(err)
	_, err = otx.Exec(ctx, `SELECT pg_current_xact_id()`)
	must(err)
	cur, _, _ := seal(ctx, pool, cursor{}, 1_000_000)
	_, err = pool.Exec(ctx, `INSERT INTO audit_log (action) VALUES ('behind-other-db')`)
	must(err)
	_, held, _ := seal(ctx, pool, cur, 1000)
	// A read-only transaction without an xid does NOT hold it.
	must(otx.Rollback(ctx))
	ro, err := other.Begin(ctx)
	must(err)
	_, err = ro.Exec(ctx, `SELECT 1`)
	must(err)
	_, freed, _ := seal(ctx, pool, cur, 1000)
	must(ro.Rollback(ctx))
	fmt.Printf("4. lag: writer txn open in another database -> sealed %d new rows (held); after it ends, with only a read-only txn open -> sealed %d\n", len(held), len(freed))
	fmt.Println("RESULT: PASS")
}
