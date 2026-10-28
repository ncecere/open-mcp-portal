package approvals

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type attentionPause struct {
	once    sync.Once
	pause   chan uint32
	release chan struct{}
}

func (p *attentionPause) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "-- name: ApprovalAttention") {
		p.once.Do(func() {
			p.pause <- c.PgConn().PID()
			select {
			case <-p.release:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (*attentionPause) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestAttentionSnapshotHasNoFenceOrActorLock(t *testing.T) {
	for _, split := range []bool{false, true} {
		t.Run(fmt.Sprintf("split=%v", split), func(t *testing.T) {
			f := newAttentionFixture(t, split)
			p := beginFixture(t, f)
			pause := &attentionPause{pause: make(chan uint32, 1), release: make(chan struct{})}
			cfg := f.db.Config()
			cfg.ConnConfig.Tracer = pause
			pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(pool.Close)
			f.s.pool = pool
			type result struct {
				items []AttentionItem
				total int64
				err   error
			}
			done := make(chan result, 1)
			go func() {
				items, total, err := f.s.Attention(context.Background(), f.reviewer, nil, 20)
				done <- result{items, total, err}
			}()
			var pid uint32
			select {
			case pid = <-pause.pause:
			case <-time.After(5 * time.Second):
				t.Fatal("attention did not establish snapshot")
			}
			var locks int
			if err = f.owner.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks WHERE pid=$1 AND
     ((locktype='relation' AND mode<>'AccessShareLock') OR locktype IN ('tuple','advisory'))`, pid).Scan(&locks); err != nil {
				t.Fatal(err)
			}
			if locks != 0 {
				t.Fatalf("attention holds %d row/authority locks", locks)
			}
			writeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			_, err = f.db.Exec(writeCtx, `UPDATE users SET status='suspended' WHERE id=$1`, f.reviewer.UserID)
			cancel()
			close(pause.release)
			if err != nil {
				t.Fatalf("actor writer blocked by attention: %v", err)
			}
			got := <-done
			if got.err != nil || got.total != 1 || len(got.items) != 1 || got.items[0].ID != p.Receipt.ID {
				t.Fatalf("inconsistent snapshot: %+v", got)
			}
			_, _, err = f.s.Attention(context.Background(), f.reviewer, nil, 20)
			requireCode(t, err, "forbidden")
			// The old attention hint cannot authorize a decision.
			_, err = f.s.Decide(context.Background(), f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
			requireCode(t, err, "forbidden")
		})
	}
}

func TestAttentionDeadlineCancelsBlockedRead(t *testing.T) {
	f := newAttentionFixture(t, true)
	tx, err := f.owner.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err = tx.Exec(context.Background(), `LOCK TABLE approval_requests IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err = f.s.Attention(ctx, f.reviewer, nil, 20)
	if err == nil || time.Since(start) > time.Second {
		t.Fatalf("attention escaped deadline: %v", err)
	}
}
