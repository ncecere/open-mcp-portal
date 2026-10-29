package store_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

// These exercise SQL constraints/parameter ordering/fences, not task authority,
// input validation or encryption. Placeholder bytes are deliberately not a
// production envelope; the service must seal/verify before using these queries.
func taskReservationParams() dbgen.InsertMCPTaskReservationParams {
	id := uuid.New()
	return dbgen.InsertMCPTaskReservationParams{
		ID: id, HandleDigest: fmt.Sprintf("%x", sha256.Sum256([]byte(id.String()))),
		PrincipalKind: "user", CredentialKind: "api_key",
		Column4:      uuid.MustParse("00000000-0000-0000-0000-000000000001"),
		Column7:      uuid.MustParse("00000000-0000-0000-0000-000000000006"),
		GatewayID:    uuid.MustParse("00000000-0000-0000-0000-000000000005"),
		ServerID:     uuid.MustParse("00000000-0000-0000-0000-000000000003"),
		CapabilityID: uuid.MustParse("00000000-0000-0000-0000-000000000004"),
		Column13:     int64(time.Hour / time.Millisecond), Column14: 30_000,
	}
}

func taskSQLCount(t *testing.T, pool *pgxpool.Pool, query string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func requireTaskNoRows(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("wanted fenced/absent row, got %v", err)
	}
}

func TestTaskSQLReservationAndOperationFences(t *testing.T) {
	approvalModes(t, func(t *testing.T, pool *pgxpool.Pool) {
		ctx := context.Background()
		seedApprovalAuthority(t, pool)
		q := dbgen.New(pool)
		p := taskReservationParams()
		epoch := approvalEpoch(t, pool)
		r, err := q.InsertMCPTaskReservation(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if r.Status != "reserved" || r.Revision != 1 || r.UserID.UUID != p.Column4 || !r.UserID.Valid ||
			r.ApiKeyID.UUID != p.Column7 || !r.ApiKeyID.Valid || r.ServiceAccountID.Valid || r.OauthGrantID.Valid || r.ServiceAccountKeyID.Valid ||
			r.CeilingAt.Sub(r.CreatedAt) != time.Hour || !r.ExpiresAt.Equal(r.CeilingAt) ||
			r.ReservationDeadline == nil || r.ReservationDeadline.Sub(r.CreatedAt) != 30*time.Second {
			t.Fatalf("reservation parameter/clock association: %+v", r)
		}
		_, err = q.GetMCPTaskByDigest(ctx, p.HandleDigest)
		requireTaskNoRows(t, err) // A reservation must never be externally findable.
		if n, err := q.CountUserOpenMCPTasks(ctx, r.UserID); err != nil || n != 1 {
			t.Fatalf("reserved capacity: %d %v", n, err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte("binding fixture")))
		prepared := dbgen.PrepareMCPTaskReservationParams{ID: r.ID, Column2: r.Revision,
			Binding: json.RawMessage(`{"fixture":true}`), BindingDigest: &digest, StateCipher: []byte("prepared fixture")}
		r, err = q.PrepareMCPTaskReservation(ctx, prepared)
		if err != nil {
			t.Fatal(err)
		}
		_, err = q.PrepareMCPTaskReservation(ctx, prepared)
		requireTaskNoRows(t, err)
		created := r.CreatedAt
		r, err = q.ActivateMCPTaskReservation(ctx, dbgen.ActivateMCPTaskReservationParams{
			ID: r.ID, Column2: r.Revision, Status: "working", StateCipher: []byte("active fixture"),
			UpstreamCreatedAt: &created, UpstreamUpdatedAt: &created, Column7: r.ExpiresAt.Add(time.Hour), PollIntervalMs: 60_000,
		})
		if err != nil || !r.ExpiresAt.Equal(r.CeilingAt) || r.ReservationDeadline != nil {
			t.Fatalf("activation/clamped lifetime: %+v %v", r, err)
		}
		if _, err := q.GetMCPTaskByDigest(ctx, p.HandleDigest); err != nil {
			t.Fatal(err)
		}
		op := uuid.NullUUID{UUID: uuid.New(), Valid: true}
		r, err = q.AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{
			ID: r.ID, Column2: r.Revision, OperationID: op, Column4: 30_000, Column5: true,
		})
		if err != nil || r.OperationDeadline == nil || !r.OperationID.Valid || r.OperationID != op || !r.NextPollAt.After(r.UpdatedAt) {
			t.Fatalf("operation claim/poll bound: %+v %v", r, err)
		}
		stale := r.Revision
		_, err = q.AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{
			ID: r.ID, Column2: r.Revision, OperationID: uuid.NullUUID{UUID: uuid.New(), Valid: true}, Column4: 30_000,
		})
		requireTaskNoRows(t, err) // Even a non-poll cannot overlap the live operation.
		r, err = q.CommitMCPTaskInputState(ctx, dbgen.CommitMCPTaskInputStateParams{
			ID: r.ID, Column2: r.Revision, OperationID: op, StateCipher: []byte("attempted fixture"),
		})
		if err != nil {
			t.Fatal(err)
		}
		finish := dbgen.FinishMCPTaskOperationParams{ID: r.ID, Column2: stale, OperationID: op,
			Status: "working", StateCipher: []byte("stale fixture"), UpstreamUpdatedAt: &created,
			Column7: r.ExpiresAt, PollIntervalMs: 60_000}
		_, err = q.FinishMCPTaskOperation(ctx, finish)
		requireTaskNoRows(t, err)
		finish.Column2 = r.Revision
		finish.StateCipher = []byte("accepted fixture")
		finish.Column7 = r.ExpiresAt.Add(-time.Minute)
		r, err = q.FinishMCPTaskOperation(ctx, finish)
		if err != nil || r.OperationID.Valid || r.OperationDeadline != nil || string(r.StateCipher) != "accepted fixture" || !r.ExpiresAt.Equal(finish.Column7) {
			t.Fatalf("fenced finish/decreasing deadline: %+v %v", r, err)
		}
		_, err = q.AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{
			ID: r.ID, Column2: r.Revision, OperationID: op, Column4: 30_000, Column5: true,
		})
		requireTaskNoRows(t, err) // Releasing an operation must not remove poll pacing.
		r, err = q.AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{
			ID: r.ID, Column2: r.Revision, OperationID: op, Column4: 30_000,
		})
		if err != nil {
			t.Fatal(err)
		}
		if n, err := q.ReleaseMCPTaskOperation(ctx, dbgen.ReleaseMCPTaskOperationParams{ID: r.ID, Column2: r.Revision + 1, OperationID: op}); err != nil || n != 0 {
			t.Fatalf("stale operation release: %d %v", n, err)
		}
		if n, err := q.ReleaseMCPTaskOperation(ctx, dbgen.ReleaseMCPTaskOperationParams{ID: r.ID, Column2: r.Revision, OperationID: op}); err != nil || n != 1 {
			t.Fatalf("operation release: %d %v", n, err)
		}
		finish.Column2 = r.Revision
		_, err = q.FinishMCPTaskOperation(ctx, finish)
		requireTaskNoRows(t, err)
		r, err = q.GetMCPTaskByDigest(ctx, p.HandleDigest)
		if err != nil || string(r.StateCipher) != "accepted fixture" {
			t.Fatalf("release restored old state: %+v %v", r, err)
		}
		op = uuid.NullUUID{UUID: uuid.New(), Valid: true}
		r, err = q.AcquireMCPTaskOperation(ctx, dbgen.AcquireMCPTaskOperationParams{ID: r.ID, Column2: r.Revision, OperationID: op, Column4: 30_000})
		if err != nil {
			t.Fatal(err)
		}
		finish.OperationID = op
		finish.Column2, finish.Status, finish.Column7 = r.Revision, "completed", r.ExpiresAt.Add(time.Hour)
		r, err = q.FinishMCPTaskOperation(ctx, finish)
		if err != nil || r.Status != "completed" || !r.ExpiresAt.Equal(finish.Column7.Add(-time.Hour)) {
			t.Fatalf("terminal finish cannot extend deadline: %+v %v", r, err)
		}
		if n, err := q.CountUserOpenMCPTasks(ctx, r.UserID); err != nil || n != 0 {
			t.Fatalf("terminal capacity not released: %d %v", n, err)
		}
		if approvalEpoch(t, pool) != epoch {
			t.Fatal("operational task transitions churned approval authority")
		}
		roleExec(t, pool, `UPDATE mcp_tasks SET expires_at=created_at+interval '1 microsecond' WHERE id=$1`, r.ID)
		_, err = q.GetMCPTaskByDigest(ctx, p.HandleDigest)
		requireTaskNoRows(t, err)
		if n, err := q.PruneExpiredMCPTasks(ctx, 1); err != nil || n != 1 {
			t.Fatalf("expired active mapping prune: %d %v", n, err)
		}
	})
}

func TestTaskSQLExpiryConstraintsAndDiscovery(t *testing.T) {
	approvalModes(t, func(t *testing.T, pool *pgxpool.Pool) {
		ctx := context.Background()
		seedApprovalAuthority(t, pool)
		q := dbgen.New(pool)
		p := taskReservationParams()
		for _, mutate := range []func(*dbgen.InsertMCPTaskReservationParams){
			func(p *dbgen.InsertMCPTaskReservationParams) { p.Column13 = 86_400_001 },
			func(p *dbgen.InsertMCPTaskReservationParams) { p.Column13 = 0 },
			func(p *dbgen.InsertMCPTaskReservationParams) { p.Column4 = uuid.Nil },
			func(p *dbgen.InsertMCPTaskReservationParams) {
				p.Column9 = uuid.MustParse("00000000-0000-0000-0000-000000000008")
			},
		} {
			bad := taskReservationParams()
			mutate(&bad)
			_, err := q.InsertMCPTaskReservation(ctx, bad)
			var pg *pgconn.PgError
			if !errors.As(err, &pg) || pg.Code != "23514" {
				t.Fatalf("wanted task CHECK violation, got %v", err)
			}
		}
		r, err := q.InsertMCPTaskReservation(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		locked, err := dbgen.New(tx).GetMCPTaskForUpdate(ctx, r.ID)
		if err != nil || locked.ID != r.ID {
			t.Fatalf("locked row: %+v %v", locked, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		// Forced expiry, not a natural-expiry soak: effective reads/counts deny
		// before the independently scheduled pruning query is ever called.
		roleExec(t, pool, `UPDATE mcp_tasks SET reservation_deadline=created_at+interval '1 microsecond' WHERE id=$1`, r.ID)
		if n, err := q.CountUserOpenMCPTasks(ctx, r.UserID); err != nil || n != 0 {
			t.Fatalf("expired reservation counted: %d %v", n, err)
		}
		if n, err := q.PruneExpiredMCPTasks(ctx, 1); err != nil || n != 1 {
			t.Fatalf("reservation prune: %d %v", n, err)
		}
		if n, err := q.PruneExpiredMCPTasks(ctx, 1); err != nil || n != 0 {
			t.Fatalf("repeated prune: %d %v", n, err)
		}
		p = taskReservationParams()
		r, err = q.InsertMCPTaskReservation(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := q.DeleteMCPTaskReservation(ctx, dbgen.DeleteMCPTaskReservationParams{ID: r.ID, Column2: r.Revision + 1}); err != nil || n != 0 {
			t.Fatalf("stale reservation deletion: %d %v", n, err)
		}
		if n, err := q.DeleteMCPTaskReservation(ctx, dbgen.DeleteMCPTaskReservationParams{ID: r.ID, Column2: r.Revision}); err != nil || n != 1 {
			t.Fatalf("reservation deletion: %d %v", n, err)
		}
		if n := taskSQLCount(t, pool, `SELECT count(*) FROM mcp_servers WHERE id=$1 AND supports_tasks=false`, p.ServerID); n != 1 {
			t.Fatal("discovery default is not false")
		}
		if err := q.SetMCPServerTaskSupport(ctx, dbgen.SetMCPServerTaskSupportParams{ID: p.ServerID, SupportsTasks: true}); err != nil {
			t.Fatal(err)
		}
		roleExec(t, pool, `UPDATE mcp_servers SET name='Metadata write' WHERE id=$1`, p.ServerID)
		if n := taskSQLCount(t, pool, `SELECT count(*) FROM mcp_servers WHERE id=$1 AND supports_tasks`, p.ServerID); n != 1 {
			t.Fatal("metadata write cleared discovery fact")
		}
		if err := q.ClearMCPServerRefreshed(ctx, p.ServerID); err != nil {
			t.Fatal(err)
		}
		if n := taskSQLCount(t, pool, `SELECT count(*) FROM mcp_servers WHERE id=$1 AND NOT supports_tasks`, p.ServerID); n != 1 {
			t.Fatal("URL refresh invalidation retained stale task discovery")
		}
		for _, method := range []string{"tasks/get", "tasks/update", "tasks/cancel"} {
			roleExec(t, pool, `INSERT INTO mcp_calls(method,gateway_id,gateway_slug,gateway_name,user_id,exposed_name,outcome) VALUES($1,$2,'approval','Approval',$3,'approval__test','ok')`, method, p.GatewayID, p.Column4)
		}
	})
}

func TestTaskSQLCapacitySerialization(t *testing.T) {
	approvalModes(t, func(t *testing.T, pool *pgxpool.Pool) {
		seedApprovalAuthority(t, pool)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		second := uuid.New()
		roleExec(t, pool, `INSERT INTO api_keys(id,user_id,name,prefix,digest,expires_at) VALUES($1,$2,'second','omp_87654321',repeat('f',64),now()+interval '1 day')`, second, taskReservationParams().Column4)
		var accepted atomic.Int32
		var wg sync.WaitGroup
		errs := make(chan error, 24)
		for i := range 24 {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				tx, err := pool.Begin(ctx)
				if err != nil {
					errs <- err
					return
				}
				defer tx.Rollback(context.Background())
				q := dbgen.New(tx)
				if err := q.LockMCPTaskPrincipal(ctx, 0x4f4d505441534b); err != nil {
					errs <- err
					return
				}
				p := taskReservationParams()
				if i%2 == 0 {
					p.Column7 = second
				}
				n, err := q.CountUserOpenMCPTasks(ctx, uuid.NullUUID{UUID: p.Column4, Valid: true})
				if err != nil {
					errs <- err
					return
				}
				if n >= 3 {
					return
				}
				if _, err := q.InsertMCPTaskReservation(ctx, p); err != nil {
					errs <- err
					return
				}
				if err := tx.Commit(ctx); err != nil {
					errs <- err
					return
				}
				accepted.Add(1)
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		if accepted.Load() != 3 {
			t.Fatalf("shared capacity admitted %d, want 3", accepted.Load())
		}
		q := dbgen.New(pool)
		p := taskReservationParams()
		p.PrincipalKind, p.CredentialKind = "service_account", "service_account"
		p.Column4, p.Column7 = uuid.Nil, uuid.Nil
		p.Column5 = uuid.MustParse("00000000-0000-0000-0000-000000000007")
		p.Column9 = uuid.MustParse("00000000-0000-0000-0000-000000000008")
		r, err := q.InsertMCPTaskReservation(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := q.CountServiceAccountOpenMCPTasks(ctx, r.ServiceAccountID); err != nil || n != 1 {
			t.Fatalf("service capacity: %d %v", n, err)
		}
		if n, err := q.CountUserOpenMCPTasks(ctx, uuid.NullUUID{UUID: taskReservationParams().Column4, Valid: true}); err != nil || n != 3 {
			t.Fatalf("user capacity: %d %v", n, err)
		}
	})
}
