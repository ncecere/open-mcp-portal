package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func approvalIsSQLState(err error, code string) bool {
	var pgerr *pgconn.PgError
	return errors.As(err, &pgerr) && pgerr.Code == code
}

func approvalBegin(t *testing.T, ctx context.Context, db *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := db.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

// Allocation order is NOT commit order. Even the older event committed last
// must invalidate snapshots captured after the newer event committed.
func TestApprovalJournalMVCCOutOfOrderCommit(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		before := approvalEpoch(t, db)
		older := approvalBegin(t, ctx, db)
		roleExec(t, older, `UPDATE teams SET status='archived'`)
		var olderID int64
		if err := older.QueryRow(ctx, `SELECT max(event_id) FROM approval_context_events`).Scan(&olderID); err != nil {
			t.Fatal(err)
		}
		newer := approvalBegin(t, ctx, db)
		roleExec(t, newer, `UPDATE users SET status='suspended'`)
		var newerID int64
		if err := newer.QueryRow(ctx, `SELECT max(event_id) FROM approval_context_events`).Scan(&newerID); err != nil {
			t.Fatal(err)
		}
		if olderID >= newerID {
			t.Fatalf("event order: older=%d newer=%d", olderID, newerID)
		}
		// Initial authentication snapshot must not bless either uncommitted change.
		if got := approvalEpoch(t, db); got != before {
			t.Fatalf("uncommitted authority blessed: got %d want %d", got, before)
		}
		if err := newer.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if got := approvalEpoch(t, db); got != before+newerID {
			t.Fatalf("first commit epoch=%d want %d", got, before+newerID)
		}
		pending := approvalPending(t, db, time.Now().UTC())
		if err := older.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if got := approvalEpoch(t, db); got != before+olderID+newerID {
			t.Fatalf("older allocation committed last epoch=%d", got)
		}
		if r, err := dbgen.New(db).GetApprovalRequest(ctx, pending.ID); err != nil || r.PreviewCipher != nil {
			t.Fatal("older allocation failed to invalidate snapshot", err)
		}
		before = approvalEpoch(t, db)
		rolledBack := approvalBegin(t, ctx, db)
		roleExec(t, rolledBack, `UPDATE teams SET status='active'`)
		if err := rolledBack.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if got := approvalEpoch(t, db); got != before {
			t.Fatal("rolled-back event changed committed epoch")
		}
		// Change-and-revert in one transaction still appends two positive events.
		revert := approvalBegin(t, ctx, db)
		roleExec(t, revert, `UPDATE teams SET status='active'`)
		roleExec(t, revert, `UPDATE teams SET status='archived'`)
		if err := revert.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if approvalEpoch(t, db) <= before {
			t.Fatal("change-and-revert recovered an old epoch")
		}
	})
}

func TestApprovalJournalCompactionIsAtomicAndEpochNeutral(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		roleExec(t, db, `INSERT INTO teams(slug,name) SELECT 'journal-'||n,'Journal' FROM generate_series(1,1001) n`)
		before := approvalEpoch(t, db)
		count := roleCount(t, db, `SELECT count(*) FROM approval_context_events`)
		if count <= 1000 {
			t.Fatal("fixture did not exceed compaction threshold")
		}
		pending := approvalPending(t, db, time.Now().UTC())
		for _, commit := range []bool{false, true} {
			tx := approvalBegin(t, ctx, db)
			got, err := dbgen.New(tx).LockApprovalContext(ctx)
			if err != nil || got != before {
				t.Fatalf("compacted epoch=%d want %d: %v", got, before, err)
			}
			var remaining int64
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM approval_context_events`).Scan(&remaining); err != nil || remaining != 0 {
				t.Fatalf("events not compacted: %d %v", remaining, err)
			}
			// A normal reader neither waits for the table fence nor sees half the
			// base/journal swap. It sees the old committed journal and old base.
			if approvalEpoch(t, db) != before || roleCount(t, db, `SELECT count(*) FROM approval_context_events`) != count {
				t.Fatal("uncommitted compaction leaked to reader")
			}
			if commit {
				if err := tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				count = 0
			} else if err := tx.Rollback(ctx); err != nil {
				t.Fatal(err)
			}
			if approvalEpoch(t, db) != before || roleCount(t, db, `SELECT count(*) FROM approval_context_events`) != count {
				t.Fatal("compaction changed epoch or rollback lost events")
			}
		}
		if r, err := dbgen.New(db).GetApprovalRequest(ctx, pending.ID); err != nil || len(r.PreviewCipher) == 0 {
			t.Fatal("compaction invalidated a valid preview", err)
		}
		roleExec(t, db, `UPDATE teams SET status='archived' WHERE slug='journal-1'`)
		if approvalEpoch(t, db) <= before {
			t.Fatal("post-compaction event did not invalidate")
		}
	})
}

// This is the old provider->epoch->connection / connection->epoch inversion.
// Use the actual connection queries and observe the real row wait before the
// disconnect appends its event. No sleeps or artificial epoch-row locks.
func TestApprovalJournalProviderDisconnectWriterSchedule(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		providerID := uuid.MustParse("00000000-0000-0000-0000-000000000009")
		connectionID := uuid.MustParse("00000000-0000-0000-0000-000000000010")
		disconnect := approvalBegin(t, ctx, db)
		if _, err := dbgen.New(disconnect).LockProviderConnectionByID(ctx, connectionID); err != nil {
			t.Fatal(err)
		}
		clientEdit := approvalBegin(t, ctx, db)
		roleExec(t, clientEdit, `UPDATE auth_providers SET client_id='new-client',revision=revision+1 WHERE id=$1`, providerID)
		done := make(chan error, 1)
		go func() {
			_, err := dbgen.New(clientEdit).MarkProviderConnectionsReconsent(ctx, providerID)
			done <- err
		}()
		approvalWaitBlocked(t, testutil.OwnerPool(t, db), clientEdit.Conn().PgConn().PID())
		if err := dbgen.New(disconnect).DeleteProviderConnection(ctx, connectionID); err != nil {
			t.Fatal("disconnect deadlocked with provider edit:", err)
		}
		if err := disconnect.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal("provider edit failed after disconnect:", err)
		}
		if err := clientEdit.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

// This is team archive -> audit actor FK / admin UpdateUser -> epoch.
// Once the audit is observed waiting on the admin's user row, the user update
// must still complete without waiting for any archive-owned global mutex.
func TestApprovalJournalTeamArchiveUserFKWriterSchedule(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		actor := uuid.MustParse("00000000-0000-0000-0000-000000000001")
		admin := approvalBegin(t, ctx, db)
		if _, err := dbgen.New(admin).GetUserForUpdate(ctx, actor); err != nil {
			t.Fatal(err)
		}
		archive := approvalBegin(t, ctx, db)
		roleExec(t, archive, `UPDATE teams SET status='archived'`)
		done := make(chan error, 1)
		go func() {
			_, err := archive.Exec(ctx, `INSERT INTO audit_log(actor_kind,actor_user_id,action,target_type) VALUES ('user',$1,'team.archived','team')`, actor)
			done <- err
		}()
		approvalWaitBlocked(t, testutil.OwnerPool(t, db), archive.Conn().PgConn().PID())
		if _, err := dbgen.New(admin).UpdateUserAccess(ctx, dbgen.UpdateUserAccessParams{ID: actor, PlatformRole: "platform_admin", Status: "suspended"}); err != nil {
			t.Fatal("admin update deadlocked with archive audit:", err)
		}
		if err := admin.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal("archive audit failed after admin commit:", err)
		}
		if err := archive.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestApprovalJournalFenceBusyDoesNotSpend(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		for _, sql := range []string{
			`SELECT id FROM users FOR UPDATE`, // ROW SHARE, not just DML
			`UPDATE teams SET status='archived'`,
			`UPDATE provider_connections SET scopes='{read}'`,
		} {
			r := approvalApproved(t, db)
			writer := approvalBegin(t, ctx, db)
			roleExec(t, writer, sql)
			for _, exclusive := range []bool{false, true} {
				consumer := approvalBegin(t, ctx, db)
				var epoch int64
				err := consumer.QueryRow(ctx, `SELECT public.omp_lock_approval_context($1)`, exclusive).Scan(&epoch)
				if !approvalIsSQLState(err, "55P03") {
					t.Fatalf("busy fence did not fail fast (%s): %v", sql, err)
				}
				// PostgreSQL has aborted the transaction; no caller can accidentally
				// continue to spend after ignoring the busy error.
				now := time.Now().UTC()
				if _, err := dbgen.New(consumer).UseApprovalRequest(ctx, approvalUseParams(r, &now)); !approvalIsSQLState(err, "25P02") {
					t.Fatal("busy transaction could continue:", err)
				}
				_ = consumer.Rollback(ctx)
			}
			var waits int
			if err := testutil.OwnerPool(t, db).QueryRow(ctx, `SELECT count(*) FROM pg_locks WHERE pid=$1 AND NOT granted`, writer.Conn().PgConn().PID()).Scan(&waits); err != nil || waits != 0 {
				t.Fatal("authority writer acquired a global fence wait", err)
			}
			_ = writer.Rollback(ctx)
			got, err := dbgen.New(db).GetApprovalRequest(ctx, r.ID)
			if err != nil || got.Status != "approved" || got.UsedAt != nil {
				t.Fatal("busy fence spent approval", err)
			}
		}
		if n := roleCount(t, db, `SELECT count(*) FROM audit_log WHERE action='approval.used'`); n != 0 {
			t.Fatal("busy fence recorded spend")
		}
	})
}

func TestApprovalJournalRuntimePrivileges(t *testing.T) {
	runtime, owner, role := splitFixture(t)
	ctx := context.Background()
	for _, sql := range []string{
		`INSERT INTO approval_context_events DEFAULT VALUES`,
		`UPDATE approval_context_events SET event_id=1`,
		`DELETE FROM approval_context_events`, `TRUNCATE approval_context_events`,
		`SELECT nextval('approval_context_events_event_id_seq')`,
		`SELECT setval('approval_context_events_event_id_seq',1)`,
		`SELECT last_value FROM approval_context_events_event_id_seq`,
		`UPDATE approval_context SET epoch=epoch+1`,
		`SELECT public.approval_authority_changed()`,
	} {
		roleDenied(t, runtime, sql, "42501")
	}
	outsider, _ := auxiliaryRole(t, owner, "journal_outsider_"+role)
	roleDenied(t, outsider, `SELECT public.omp_current_approval_context()`, "42501")
	if _, err := dbgen.New(runtime).GetApprovalContext(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := dbgen.New(runtime).LockApprovalContext(ctx); err != nil {
		t.Fatal(err)
	}
	for _, sql := range []string{
		"GRANT INSERT ON approval_context_events TO " + pgx.Identifier{role}.Sanitize(),
		"GRANT USAGE,UPDATE ON SEQUENCE approval_context_events_event_id_seq TO " + pgx.Identifier{role}.Sanitize(),
	} {
		roleExec(t, owner, sql)
		safety, err := store.InspectRoles(ctx, runtime, "", true)
		if err != nil || safety.Safe() {
			t.Fatalf("unsafe journal privileges missed: %+v %v", safety, err)
		}
		if err := store.Migrate(ctx, owner, testutil.Logger(), role); err != nil {
			t.Fatal(err)
		}
		safety, err = store.InspectRoles(ctx, runtime, "", true)
		if err != nil || !safety.Safe() {
			t.Fatalf("journal grants not reconciled: %+v %v", safety, err)
		}
	}
}

func TestApprovalJournalReconnectNotRefresh(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		seedApprovalAuthority(t, db)
		ctx := context.Background()
		q := dbgen.New(db)
		id := uuid.MustParse("00000000-0000-0000-0000-000000000010")
		before := approvalEpoch(t, db)
		connection, err := q.GetProviderConnectionByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := q.SetProviderConnectionRefreshed(ctx, dbgen.SetProviderConnectionRefreshedParams{
			ID: id, Scopes: connection.Scopes, AccessTokenCipher: []byte("refresh"),
		}); err != nil {
			t.Fatal(err)
		}
		if approvalEpoch(t, db) != before {
			t.Fatal("same-scope refresh invalidated context")
		}
		if _, err := q.ReconnectProviderConnection(ctx, dbgen.ReconnectProviderConnectionParams{
			ID: id, Scopes: connection.Scopes, AccessTokenCipher: []byte("reconnect"),
		}); err != nil {
			t.Fatal(err)
		}
		if approvalEpoch(t, db) <= before {
			t.Fatal("same-scope active reconnect failed to invalidate context")
		}
	})
}

func TestApprovalJournalOverflowFailsClosed(t *testing.T) {
	approvalModes(t, func(t *testing.T, db *pgxpool.Pool) {
		ctx := context.Background()
		owner := testutil.OwnerPool(t, db)
		roleExec(t, owner, `UPDATE approval_context SET epoch=9223372036854775807-(SELECT coalesce(sum(event_id),0)::bigint FROM approval_context_events)`)
		roleExec(t, db, `INSERT INTO teams(slug,name) VALUES ('overflow','Overflow')`)
		if _, err := dbgen.New(db).GetApprovalContext(ctx); !approvalIsSQLState(err, "22003") {
			t.Fatal("overflow reused an epoch:", err)
		}
		if _, err := dbgen.New(db).LockApprovalContext(ctx); !approvalIsSQLState(err, "22003") {
			t.Fatal("overflow fence did not fail closed:", err)
		}
	})
}
