package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestApprovalJournalMigrationInvalidatesEveryOldSnapshot(t *testing.T) {
	approvalModes(t, func(t *testing.T, runtime *pgxpool.Pool) {
		ctx := context.Background()
		owner := testutil.OwnerPool(t, runtime)
		// This database was freshly created by NewDB; rebuild ONLY its schema
		// to exercise the real, unmodified 35 -> 36 upgrade with existing data.
		roleExec(t, owner, `DROP SCHEMA public CASCADE`)
		roleExec(t, owner, `CREATE SCHEMA public`)
		db := stdlib.OpenDBFromPool(owner)
		defer db.Close()
		provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := provider.UpTo(ctx, 35); err != nil {
			t.Fatal(err)
		}
		roleExec(t, owner, `INSERT INTO teams(slug,name) VALUES ('pre-journal','Before journal')`)
		// Defensively exceed even the protected base: snapshots have no FK to
		// it, and the migration must invalidate every historical snapshot.
		roleExec(t, owner, `INSERT INTO approval_requests(rule_id,rule_revision,context_epoch,requester_kind,requester_id,gateway_id,server_id,capability_id,exposed_name,args_digest,binding_digest,capability_fingerprint,server_origin,created_at,expires_at,preview_cipher)
			VALUES (gen_random_uuid(),1,1000000,'user',gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),gen_random_uuid(),'test',repeat('a',64),repeat('b',64),repeat('c',64),'https://test.invalid',now(),now()+interval '1 hour','sealed'::bytea)`)
		if _, err := provider.UpTo(ctx, 36); err != nil {
			t.Fatal(err)
		}
		// Assert migration 36 itself before later migrations can deliberately
		// invalidate context again (41 installs the stable binding root).
		if got := approvalEpoch(t, owner); got != 1000001 {
			t.Fatalf("journal upgrade epoch=%d want 1000001", got)
		}
		if n := roleCount(t, owner, `SELECT count(*) FROM approval_context_events`); n != 0 {
			t.Fatal("journal upgrade fabricated an authority mutation")
		}
		role := ""
		if runtime != owner {
			role = runtime.Config().ConnConfig.User
		}
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
			t.Fatal(err)
		}
		upgraded := approvalEpoch(t, runtime)
		if upgraded < 1000001 {
			t.Fatalf("later upgrade regressed epoch=%d", upgraded)
		}
		var staleID uuid.UUID
		if err := runtime.QueryRow(ctx, `SELECT id FROM approval_requests`).Scan(&staleID); err != nil {
			t.Fatal(err)
		}
		if r, err := dbgen.New(runtime).GetApprovalRequest(ctx, staleID); err != nil || r.PreviewCipher != nil {
			t.Fatal("upgrade-stale preview disclosed", err)
		}
		// The same predicate used by generated decision/use queries must reject
		// the deliberately higher old snapshot after the one-time invalidation.
		if n := roleCount(t, runtime, `SELECT count(*) FROM approval_requests WHERE context_epoch=public.omp_current_approval_context()`); n != 0 {
			t.Fatal("pre-journal request survived upgrade")
		}
		roleExec(t, runtime, `UPDATE teams SET status='archived'`)
		if got := approvalEpoch(t, runtime); got <= upgraded {
			t.Fatalf("first writer did not advance journal epoch: before=%d after=%d", upgraded, got)
		}
	})
}

func TestApprovalJournalFenceCoversExactlyAuthorityTables(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		tx := approvalBegin(t, ctx, db)
		if _, err := dbgen.New(tx).LockApprovalContext(ctx); err != nil {
			t.Fatal(err)
		}
		var missing, unexpected int
		if err := tx.QueryRow(ctx, `WITH required AS (
			SELECT DISTINCT tgrelid AS oid FROM pg_trigger WHERE tgfoid='public.approval_authority_changed()'::regprocedure
			UNION SELECT 'public.approval_context_events'::regclass::oid
		), fenced AS (
			SELECT relation AS oid FROM pg_locks WHERE pid=pg_backend_pid() AND locktype='relation' AND mode='ExclusiveLock' AND granted
		) SELECT (SELECT count(*) FROM required WHERE oid NOT IN (SELECT oid FROM fenced)),
		         (SELECT count(*) FROM fenced WHERE oid NOT IN (SELECT oid FROM required))`).Scan(&missing, &unexpected); err != nil {
			t.Fatal(err)
		}
		if missing != 0 || unexpected != 0 {
			t.Fatalf("authority fence drift: missing=%d unexpected=%d", missing, unexpected)
		}
	})
}

// A request-detail query can wait behind DDL or an explicit table lock. Its
// preview expiry must use actual wall time after that wait, not transaction now().
func TestApprovalPreviewExpiryAfterTableWait(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		created := time.Now().UTC().Add(-24*time.Hour + time.Second)
		pending := approvalPending(t, db, created)
		reader := approvalBegin(t, ctx, db)
		var started time.Time
		if err := reader.QueryRow(ctx, `SELECT now()`).Scan(&started); err != nil {
			t.Fatal(err)
		}
		if !started.Before(pending.ExpiresAt) {
			t.Fatal("fixture expired before transaction began")
		}
		blocker := approvalBegin(t, ctx, testutil.OwnerPool(t, db))
		roleExec(t, blocker, `LOCK TABLE approval_requests IN ACCESS EXCLUSIVE MODE`)
		type result struct {
			preview []byte
			err     error
		}
		done := make(chan result, 1)
		go func() {
			r, err := dbgen.New(reader).GetApprovalRequest(ctx, pending.ID)
			done <- result{preview: r.PreviewCipher, err: err}
		}()
		approvalWaitBlocked(t, testutil.OwnerPool(t, db), reader.Conn().PgConn().PID())
		// Observe the server's clock boundary, not a scheduling sleep.
		tick := time.NewTicker(5 * time.Millisecond)
		defer tick.Stop()
		for {
			var elapsed bool
			if err := db.QueryRow(ctx, `SELECT clock_timestamp() >= $1::timestamptz`, pending.ExpiresAt).Scan(&elapsed); err != nil {
				t.Fatal(err)
			}
			if elapsed {
				break
			}
			select {
			case <-tick.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		if err := blocker.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		r := <-done
		if r.err != nil || r.preview != nil {
			t.Fatal("preview exposed after expiry during table wait", r.err)
		}
	})
}
