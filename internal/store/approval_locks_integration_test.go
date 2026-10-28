package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func approvalWaitBlocked(t *testing.T, db *pgxpool.Pool, pid uint32) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := db.QueryRow(context.Background(), `SELECT cardinality(pg_blocking_pids($1::integer))>0`, pid).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			return
		}
		select {
		case <-deadline.C:
			t.Fatal("writer never reached the fence")
		case <-tick.C:
		}
	}
}

// Administrative writers wait at the authority table fence, before taking
// rows. The consumer's live reads remain NONLOCKING while it spends and audits.
func TestApprovalFenceAdministrativeWriters(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		for _, sql := range []string{
			`UPDATE users SET status='suspended'`,
			`UPDATE api_keys SET revoked_at=now()`,
			`DELETE FROM oauth_tokens WHERE kind='access'`,
			`UPDATE mcp_servers SET enabled=false`,
			`UPDATE service_connections SET status='needs_reconsent',access_token_cipher=NULL,revision=revision+1`,
		} {
			t.Run(sql, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				// System consumption: no human audit FK/row lock under the fence.
				approved := approvalApproved(t, db)
				consumer, err := db.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer consumer.Rollback(ctx)
				cq := dbgen.New(consumer)
				epoch, err := cq.LockApprovalContext(ctx)
				if err != nil {
					t.Fatal(err)
				}
				writer, err := db.Acquire(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Release()
				done := make(chan error, 1)
				go func() { _, err := writer.Exec(ctx, sql); done <- err }()
				approvalWaitBlocked(t, testutil.OwnerPool(t, db), writer.Conn().PgConn().PID())
				// A locking read here would invert writer -> epoch and deadlock. These
				// current-authority validation reads deliberately see the last commit.
				var status string
				if err := consumer.QueryRow(ctx, `SELECT status FROM users LIMIT 1`).Scan(&status); err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				if _, err := cq.UseApprovalRequest(ctx, approvalUseParams(approved, &now)); err != nil {
					t.Fatal(err)
				}
				roleExec(t, consumer, `INSERT INTO audit_log(actor_kind,action,target_type,target_id,metadata) VALUES ('system','approval.used','approval_request',$1,jsonb_build_object('requesterId',$2::text,'decidedBy',$3::text))`, approved.ID.String(), approved.RequesterID.String(), approved.DecidedBy.UUID.String())
				if err := consumer.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := <-done; err != nil {
					t.Fatal(err)
				}
				if approvalEpoch(t, db) <= epoch {
					t.Fatal("writer did not invalidate epoch after fence release")
				}
			})
		}
	})
}

// Lock helper is transaction-scoped. Both modes conservatively take the same
// exclusive table fence; contending approvals fail fast and must retry.
func TestApprovalFenceRuleAndActorOrder(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		reader, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Rollback(ctx)
		rq := dbgen.New(reader)
		actor := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		if _, err := rq.LockApprovalActor(ctx, actor); err != nil {
			t.Fatal(err)
		}
		epoch, err := rq.LockApprovalContext(ctx)
		if err != nil {
			t.Fatal(err)
		}
		other, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Rollback(ctx)
		if _, err := dbgen.New(other).LockApprovalContext(ctx); !approvalIsSQLState(err, "55P03") {
			t.Fatal("contending fence did not fail fast:", err)
		}
		_ = other.Rollback(ctx)
		writer, err := db.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Release()
		attempt := func() error {
			return pgx.BeginFunc(ctx, writer, func(tx pgx.Tx) error {
				q := dbgen.New(tx)
				// Direct helper contention fails fast, without waiting on actor rows.
				if _, err := q.LockApprovalContextExclusive(ctx); err != nil {
					return err
				}
				_, err := tx.Exec(ctx, `UPDATE approval_rules SET revision=revision+1,enabled=false`)
				return err
			})
		}
		if err := attempt(); !approvalIsSQLState(err, "55P03") {
			t.Fatal("rule administration did not fail fast:", err)
		}
		// This FK is protected by the actor lock acquired BEFORE the fence.
		roleExec(t, reader, `INSERT INTO audit_log(actor_kind,actor_user_id,action,target_type) VALUES ('user',$1,'approval.test','approval_request')`, actor)
		if err := reader.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := attempt(); err != nil {
			t.Fatal(err)
		}
		if approvalEpoch(t, db) <= epoch {
			t.Fatal("rule write did not advance epoch")
		}
	})
}

func TestApprovalAdvisoryQuotaAndLiveDedup(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pending := approvalPending(t, db, time.Now().UTC())
		first, err := db.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback(ctx)
		q := dbgen.New(first)
		if _, err = q.LockApprovalContext(ctx); err != nil {
			t.Fatal(err)
		}
		key := dbgen.LockApprovalRequesterParams{RequesterKind: pending.RequesterKind, RequesterID: pending.RequesterID}
		if err = q.LockApprovalRequester(ctx, key); err != nil {
			t.Fatal(err)
		}
		conn, err := db.Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Release()
		attempt := func() error {
			return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
				q := dbgen.New(tx)
				if _, err := q.LockApprovalContext(ctx); err != nil {
					return err
				}
				if err := q.LockApprovalRequester(ctx, key); err != nil {
					return err
				}
				n, err := q.CountPendingApprovalRequests(ctx, dbgen.CountPendingApprovalRequestsParams{RequesterKind: pending.RequesterKind, RequesterID: pending.RequesterID, AtTime: time.Now()})
				if n != 1 && err == nil {
					return errors.New("quota count mismatch")
				}
				return err
			})
		}
		if err := attempt(); !approvalIsSQLState(err, "55P03") {
			t.Fatal("contending quota transaction did not fail fast:", err)
		}
		if err := first.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := attempt(); err != nil {
			t.Fatal(err)
		}
		// The partial unique index is a second dedup boundary even if a caller
		// neglects the advisory protocol. Terminal history is retained separately.
		roleDenied(t, db, `INSERT INTO approval_requests SELECT gen_random_uuid(),rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,capability_fingerprint,server_origin,preview_cipher,preview_truncated,preview_redacted,status,review_revision,decided_by,created_at,expires_at,valid_until,decided_at,used_at,terminal_at FROM approval_requests`, "23505")
	})
}
