package approvals

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/authz"
)

type queueTrace struct {
	mu            sync.Mutex
	sql           []string
	candidateRows int64
	pause         chan uint32
	release       chan struct{}
	once          sync.Once
}

func (tr *queueTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	tr.mu.Lock()
	tr.sql = append(tr.sql, d.SQL)
	tr.mu.Unlock()
	if tr.pause != nil && strings.Contains(d.SQL, "-- name: ApprovalQueueCandidates") {
		tr.once.Do(func() {
			tr.pause <- c.PgConn().PID()
			select {
			case <-tr.release:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (tr *queueTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if len(tr.sql) > 0 && strings.Contains(tr.sql[len(tr.sql)-1], "-- name: ApprovalQueueCandidates") {
		tr.candidateRows += d.CommandTag.RowsAffected()
	}
}
func (tr *queueTrace) reset() { tr.mu.Lock(); defer tr.mu.Unlock(); tr.sql = nil; tr.candidateRows = 0 }
func traceQueue(t *testing.T, f *serviceFixture, owner bool, tr *queueTrace) {
	t.Helper()
	source := f.db
	if owner {
		source = f.owner
	}
	cfg := source.Config()
	cfg.ConnConfig.Tracer = tr
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f.s.pool = pool
}

// Direct metadata seeding avoids quota/state transitions. The cipher is
// intentionally invalid: queue projections must never fetch or decrypt it.
func seedQueue(t *testing.T, f *serviceFixture, base uuid.UUID, n int, requester uuid.UUID, kind, status string) {
	t.Helper()
	salt := uuid.NewString()
	execFixture(t, f.db, `INSERT INTO approval_requests
 (id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
 gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,
 capability_fingerprint,server_origin,preview_cipher,status,created_at,expires_at,terminal_at)
 SELECT gen_random_uuid(),rule_id,rule_revision,context_epoch,$3,$4,
 CASE WHEN $3='service_account' THEN $5::uuid ELSE NULL::uuid END,
 gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,
 md5($6)||md5(g::text||$6),capability_fingerprint,server_origin,'invalid-preview'::bytea,'pending',
 created_at - g*interval '1 microsecond',created_at + interval '1 hour',NULL
 FROM approval_requests CROSS JOIN generate_series(1,$2::integer) g WHERE id=$1`, base, n, kind, requester, f.saTeam, salt)
	if status == "cancelled" {
		execFixture(t, f.db, `UPDATE approval_requests SET status='cancelled',review_revision=review_revision+1,terminal_at=created_at WHERE left(binding_digest,32)=md5($1)`, salt)
	}
}

func TestQueueEmptyHistoryHasNoFenceOrWriterWait(t *testing.T) {
	for _, owner := range []bool{false, true} {
		t.Run(fmt.Sprintf("owner=%v", owner), func(t *testing.T) {
			f := newServiceFixture(t)
			p := beginFixture(t, f)
			tr := &queueTrace{pause: make(chan uint32, 1), release: make(chan struct{})}
			traceQueue(t, f, owner, tr)
			type result struct {
				rows []Receipt
				next string
				err  error
			}
			done := make(chan result, 1)
			go func() {
				r, n, e := f.s.ListRequestsPage(context.Background(), f.outsider, "requested", "", 200)
				done <- result{r, n, e}
			}()
			var pid uint32
			select {
			case pid = <-tr.pause:
			case <-time.After(5 * time.Second):
				t.Fatal("list did not reach candidate query")
			}
			// All relation locks held by this queue transaction must be plain reads.
			var locks int
			if err := f.owner.QueryRow(context.Background(), `SELECT count(*) FROM pg_locks WHERE pid=$1 AND
   ((locktype='relation' AND mode<>'AccessShareLock') OR locktype IN ('tuple','advisory'))`, pid).Scan(&locks); err != nil {
				t.Fatal(err)
			}
			if locks != 0 {
				t.Fatalf("queue holds %d authority/row locks", locks)
			}
			writeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
			// Update the very same actor, not merely an unrelated authority row.
			_, err := f.db.Exec(writeCtx, `UPDATE users SET platform_role='platform_auditor' WHERE id=$1`, f.outsider.UserID)
			cancel()
			close(tr.release)
			if err != nil {
				t.Fatalf("authority writer waited on list: %v", err)
			}
			got := <-done
			if got.err != nil || len(got.rows) != 0 || got.next != "" {
				t.Fatalf("empty queue: %+v", got)
			}
			tr.reset()
			if _, _, err = f.s.ListRequestsPage(context.Background(), f.outsider, "requested", "", 200); err != nil {
				t.Fatal(err)
			}
			before := len(tr.sql)
			seedQueue(t, f, p.Receipt.ID, 10000, f.requester.UserID, "user", "cancelled")
			tr.reset()
			for _, view := range []string{"requested", "actionable"} {
				tr.reset()
				r, n, e := f.s.ListRequestsPage(context.Background(), f.outsider, view, "", 200)
				if e != nil || len(r) != 0 || n != "" {
					t.Fatalf("history leaked to %s: %d %q %v", view, len(r), n, e)
				}
				if len(tr.sql) != before || tr.candidateRows != 0 {
					t.Fatalf("history-dependent queries/candidates: %d vs %d; rows=%d", len(tr.sql), before, tr.candidateRows)
				}
				if !strings.Contains(strings.ToLower(tr.sql[0]), "repeatable read read only") {
					t.Fatalf("not a read-only snapshot: %q", tr.sql[0])
				}
			}
		})
	}
}

func TestQueueSnapshotKeepsHintsConsistentButNextCallRevalidates(t *testing.T) {
	f := newServiceFixture(t)
	p := beginFixture(t, f)
	tr := &queueTrace{pause: make(chan uint32, 1), release: make(chan struct{})}
	traceQueue(t, f, false, tr)
	type result struct {
		rows []Receipt
		err  error
	}
	done := make(chan result, 1)
	go func() {
		rows, _, err := f.s.ListRequestsPage(context.Background(), f.reviewer, "actionable", "", 1)
		done <- result{rows, err}
	}()
	select {
	case <-tr.pause:
	case <-time.After(5 * time.Second):
		t.Fatal("list did not establish snapshot")
	}
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.reviewer.UserID)
	close(tr.release)
	got := <-done
	if got.err != nil || len(got.rows) != 1 || got.rows[0].ID != p.Receipt.ID || !got.rows[0].CanDecide {
		t.Fatalf("inconsistent snapshot hints: %+v", got)
	}
	_, _, err := f.s.ListRequestsPage(context.Background(), f.reviewer, "actionable", "", 1)
	requireCode(t, err, "forbidden")
	// A true hint from the old snapshot never authorizes the actual decision.
	_, err = f.s.Decide(context.Background(), f.reviewer, p.Receipt.ID, Decision{Decision: "approve", ExpectedReviewRevision: p.Receipt.ReviewRevision, ExpectedArgsDigest: p.Receipt.ArgsDigest})
	requireCode(t, err, "forbidden")
}

func TestQueueKeysetMetadataAndCandidateBudget(t *testing.T) {
	f := newServiceFixture(t)
	p := beginFixture(t, f)
	seedQueue(t, f, p.Receipt.ID, 410, f.requester.UserID, "user", "pending")
	seedQueue(t, f, p.Receipt.ID, 1500, f.outsider.UserID, "user", "cancelled")
	tr := &queueTrace{}
	traceQueue(t, f, false, tr)
	seen := map[uuid.UUID]bool{}
	cursor := ""
	for page := 0; ; page++ {
		tr.reset()
		rows, next, err := f.s.ListRequestsPage(context.Background(), f.requester, "requested", cursor, 200)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 200 || tr.candidateRows > 201 {
			t.Fatalf("unbounded page: items=%d candidates=%d", len(rows), tr.candidateRows)
		}
		for _, r := range rows {
			if r.RequesterID != f.requester.UserID || seen[r.ID] || r.Preview != nil {
				t.Fatalf("private, repeated or preview-bearing row: %+v", r)
			}
			seen[r.ID] = true
		}
		for _, sql := range tr.sql {
			if strings.Contains(sql, "-- name: FindApprovalRequestBinding") || strings.Contains(sql, "FOR KEY SHARE") || strings.Contains(sql, "omp_lock_approval_context") {
				t.Fatalf("detail projection or authority lock in list: %s", sql)
			}
		}
		if next == "" {
			break
		}
		if next == cursor || page > 5 {
			t.Fatal("cursor did not advance")
		}
		cursor = next
	}
	if len(seen) != 411 {
		t.Fatalf("history silently truncated: %d", len(seen))
	}
	// Terminal renewable rows must also use only a metadata binding lookup.
	execFixture(t, f.db, `UPDATE approval_requests SET status='cancelled',review_revision=review_revision+1,terminal_at=now() WHERE id=$1`, p.Receipt.ID)
	tr.reset()
	rows, _, err := f.s.ListRequestsPage(context.Background(), f.requester, "requested", "", 1)
	if err != nil || len(rows) != 1 || !rows[0].CanRenew || rows[0].Preview != nil {
		t.Fatalf("renewal metadata: %+v %v", rows, err)
	}
	for _, sql := range tr.sql {
		if strings.Contains(sql, "-- name: FindApprovalRequestBinding") {
			t.Fatal("renewal fetched preview cipher")
		}
	}
}

func TestQueueEmptyPageAdvancesPastFalsePositiveReviewers(t *testing.T) {
	f := newServiceFixture(t)
	// With a real primary reviewer, platform admins are SQL fallback candidates
	// only. Exact permissions must exclude them, without scanning the whole queue.
	p := beginFixture(t, f)
	seedQueue(t, f, p.Receipt.ID, 405, f.requester.UserID, "user", "pending")
	tr := &queueTrace{}
	traceQueue(t, f, false, tr)
	cursor := ""
	total := int64(0)
	for page := 0; page < 3; page++ {
		tr.reset()
		rows, next, err := f.s.ListRequestsPage(context.Background(), f.admin, "actionable", cursor, 200)
		if err != nil || len(rows) != 0 {
			t.Fatalf("fallback weakened: rows=%d err=%v", len(rows), err)
		}
		if tr.candidateRows > 201 {
			t.Fatal("candidate budget exceeded")
		}
		total += min(tr.candidateRows, 200)
		if page < 2 && (next == "" || next == cursor) {
			t.Fatal("empty page lost continuation")
		}
		if page == 2 && next != "" {
			t.Fatal("unexpected continuation after end")
		}
		cursor = next
	}
	if total != 406 {
		t.Fatalf("scanned %d candidates", total)
	}
}

func TestQueueLiveActorEpochDeadlineAndServiceAccountAgent(t *testing.T) {
	f := newServiceFixture(t)
	ctx := context.Background()
	p := beginFixture(t, f)
	// A forged cached platform role must not make an ordinary active user a
	// fallback candidate. Conversely a live promotion must be observed.
	fake := f.outsider
	fake.PlatformRole = authz.PlatformAdmin
	rows, _, err := f.s.ListRequestsPage(ctx, fake, "actionable", "", 200)
	if err != nil || len(rows) != 0 {
		t.Fatalf("cached role trusted: %v %v", rows, err)
	}
	execFixture(t, f.db, `UPDATE users SET status='suspended' WHERE id=$1`, f.requester.UserID)
	_, _, err = f.s.ListRequestsPage(ctx, f.requester, "requested", "", 200)
	requireCode(t, err, "forbidden")
	execFixture(t, f.db, `UPDATE users SET status='active' WHERE id=$1`, f.requester.UserID)
	// Earlier epoch is excluded even though the record is still pending.
	rows, next, err := f.s.ListRequestsPage(ctx, f.reviewer, "actionable", "", 200)
	if err != nil || len(rows) != 0 || next != "" {
		t.Fatalf("stale epoch: %v %q %v", rows, next, err)
	}
	// Create a fresh current-epoch request, then move the service clock past
	// expiry. No list is allowed to transition the record to terminal status.
	f.input.Binding.Epoch = mustEpoch(t, f.s)
	p = beginFixture(t, f)
	f.s.SetClock(func() time.Time { return p.Receipt.ExpiresAt.Add(time.Second) })
	rows, _, err = f.s.ListRequestsPage(ctx, f.reviewer, "actionable", "", 200)
	if err != nil || len(rows) != 0 || requestStatus(t, f, p.Receipt.ID) != Pending {
		t.Fatal("expired queue or list mutated receipt", err)
	}
	f.s.SetClock(nil)
	seedQueue(t, f, p.Receipt.ID, 3, f.sa, "service_account", "cancelled")
	for _, a := range []authz.Actor{f.saOwner, f.requester} {
		rows, _, err = f.s.ListRequestsPage(ctx, a, "requested", "", 200)
		want := 0
		if a.UserID == f.saOwner.UserID {
			want = 3
		} else {
			want = 2
		}
		if err != nil || len(rows) != want {
			t.Fatalf("SA requester membership: got %d want %d err=%v", len(rows), want, err)
		}
	}
	execFixture(t, f.db, `UPDATE teams SET status='archived' WHERE id=$1`, f.saTeam)
	rows, _, err = f.s.ListRequestsPage(ctx, f.saOwner, "requested", "", 200)
	if err != nil || len(rows) != 0 {
		t.Fatal("archived SA team visible", err)
	}
}
