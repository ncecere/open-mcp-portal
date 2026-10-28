package httpapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/approvals"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// ANALYZE takes SHARE UPDATE EXCLUSIVE without changing semantic authority.
// Hold exactly that lock until the test explicitly releases it; no timing race
// with the real autovacuum launcher is needed to reproduce the matrix failure.
func holdMatrixMaintenance(t *testing.T, ctx context.Context, owner *pgxpool.Pool) (pgx.Tx, int) {
	t.Helper()
	tx, err := owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	if _, err = tx.Exec(ctx, `LOCK TABLE public.gateways IN SHARE UPDATE EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	var pid int
	if err = tx.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid); err != nil {
		t.Fatal(err)
	}
	return tx, pid
}

func TestApprovalMatrixBeginFailsClosedDuringMaintenance(t *testing.T) {
	e := newMatrixEnv(t)
	svc, in, _ := approvalMatrixBeginFixture(&mctx{e: e, tf: &e.b}, "get")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tx, pid := holdMatrixMaintenance(t, ctx, testutil.OwnerPool(t, e.app.Pool))
	var mode string
	if err := e.app.Pool.QueryRow(ctx, `SELECT mode FROM pg_locks WHERE pid=$1 AND relation='public.gateways'::regclass AND granted`, pid).Scan(&mode); err != nil || mode != "ShareUpdateExclusiveLock" {
		t.Fatalf("maintenance lock: mode=%q err=%v", mode, err)
	}
	// Observe the hidden SQL cause without changing Service.safeError or any
	// production fence. Application operations still use the runtime-role pool.
	_, err := dbgen.New(e.app.Pool).LockApprovalContext(ctx)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "55P03" || !strings.Contains(pe.Message, "gateways") {
		t.Fatalf("fence cause: want 55P03 on gateways, got %v", err)
	}
	if _, err = svc.Begin(ctx, in); !errors.Is(err, approvals.ErrUnavailable) {
		t.Fatalf("governed Begin during maintenance: %v", err)
	}
	var count int
	if err = e.app.Pool.QueryRow(ctx, `SELECT count(*) FROM approval_requests WHERE server_id=$1`, in.Binding.ServerID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed Begin created a request: count=%d err=%v", count, err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	assertMatrixBegin(t, ctx, svc, in)
}

func TestApprovalMatrixQuiescesMaintenanceBeforeLoadingFixtures(t *testing.T) {
	e := newMatrixEnv(t)
	// Startup must exclude future autonomous workers too, not merely wait for
	// one worker and reopen a race before the next Begin/Decide.
	var maintenanceDisabled bool
	if err := testutil.OwnerPool(t, e.app.Pool).QueryRow(context.Background(), `
		SELECT bool_and(COALESCE(reloptions @> ARRAY['autovacuum_enabled=false'], false))
		FROM pg_class WHERE relnamespace IN ('public'::regnamespace, 'omp_private'::regnamespace)
		AND relkind='r'`).Scan(&maintenanceDisabled); err != nil || !maintenanceDisabled {
		t.Fatalf("matrix fixture still allows autonomous table maintenance: disabled=%v err=%v", maintenanceDisabled, err)
	}
	svc, in, _ := approvalMatrixBeginFixture(&mctx{e: e, tf: &e.b}, "get")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	owner := testutil.OwnerPool(t, e.app.Pool)
	tx, pid := holdMatrixMaintenance(t, ctx, owner)
	done := make(chan error, 1)
	go func() { done <- quiesceApprovalMatrix(ctx, owner) }()
	// Release maintenance only after PostgreSQL proves the setup barrier is
	// waiting behind it. Poll lock state, not Begin, and never retry an admission.
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		err := owner.QueryRow(ctx, `SELECT EXISTS (SELECT FROM pg_locks WHERE relation='public.gateways'::regclass AND NOT granted AND $1=ANY(pg_blocking_pids(pid)))`, pid).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("fixture setup did not wait for maintenance: %v", err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Disabling maintenance and waiting for an existing worker must not mutate
	// authority: the exact captured epoch and original input remain valid.
	assertMatrixBegin(t, ctx, svc, in)
}

func assertMatrixBegin(t *testing.T, ctx context.Context, svc *approvals.Service, in approvals.BeginInput) {
	t.Helper()
	epoch, err := svc.Epoch(ctx)
	if err != nil || epoch != in.Binding.Epoch {
		t.Fatalf("fixture authority changed: epoch=%d want=%d err=%v", epoch, in.Binding.Epoch, err)
	}
	plan, err := svc.Begin(ctx, in)
	if err != nil || !plan.Required || plan.Receipt.ID == uuid.Nil || plan.Receipt.Status != approvals.Pending {
		t.Fatalf("valid governed fixture: required=%v receipt=%+v err=%v", plan.Required, plan.Receipt, err)
	}
}

func TestMatrixSubtestHelpersUseCurrentTest(t *testing.T) {
	e := newMatrixEnv(t)
	before := e.next()
	t.Run("scoped helpers", func(t *testing.T) {
		scoped := e.withTest(t)
		if scoped.t != t || scoped.app.t != t {
			t.Fatal("fixture SQL/app failures belong to the parent test")
		}
		for _, s := range scoped.callers {
			if s.t != t || s.app.t != t {
				t.Fatal("session failures belong to the parent test")
			}
		}
		if got := scoped.next(); got != before+1 {
			t.Fatalf("scoped fixture counter=%d", got)
		}
	})
	if got := e.next(); got != before+2 {
		t.Fatalf("subtest reused fixture identifiers: %d", got)
	}
	if e.t != t || e.app.t != t {
		t.Fatal("subtest changed parent helper ownership")
	}
}
