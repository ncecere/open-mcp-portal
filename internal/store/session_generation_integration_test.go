package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestBrowserSessionGenerationMonotonicAndImmutableSnapshots(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	id, sessionID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'session-gen-store@example.test','Session generation store','test','session-gen-store')`, id); err != nil {
		t.Fatal(err)
	}
	var schema int64
	if err := pool.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&schema); err != nil || schema < 53 {
		t.Fatal("session-generation proof requires expanded schema53")
	}
	t.Log("SESSION_GENERATION_SCHEMA53_APPLIED_OWNED_DB")
	var generation int64
	if err := pool.QueryRow(ctx, `INSERT INTO sessions(id,user_id,token_digest,csrf_token,expires_at)
VALUES ($1,$2,'owned-generation-digest','owned-csrf',now()+interval '1 hour') RETURNING session_generation`, sessionID, id).Scan(&generation); err != nil || generation != 1 {
		t.Fatal("legacy initial session insert:", err)
	}
	contextVersion := func() int64 {
		t.Helper()
		var n int64
		if err := pool.QueryRow(ctx, `SELECT omp_private.omp_current_approval_context()`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	before := contextVersion()
	check := func(statement string, wantGen, wantEpoch int64, changed bool) {
		t.Helper()
		var epoch int64
		if err := pool.QueryRow(ctx, statement, id).Scan(&generation, &epoch); err != nil || generation != wantGen || epoch != wantEpoch {
			t.Fatalf("generation/epoch got=%d/%d want=%d/%d err=%v", generation, epoch, wantGen, wantEpoch, err)
		}
		after := contextVersion()
		if changed && after <= before || !changed && after != before {
			t.Fatal("session generation/request epoch lost approval-journal coverage")
		}
		before = after
	}
	check(`UPDATE users SET display_name='Profile touch' WHERE id=$1 RETURNING session_generation,request_epoch`, 1, 1, false)
	check(`UPDATE users SET session_generation=session_generation+1 WHERE id=$1 RETURNING session_generation,request_epoch`, 2, 2, true)
	check(`UPDATE users SET status='suspended' WHERE id=$1 RETURNING session_generation,request_epoch`, 3, 3, true)
	check(`UPDATE users SET status='active' WHERE id=$1 RETURNING session_generation,request_epoch`, 3, 4, true)
	check(`UPDATE users SET status=status,session_generation=session_generation WHERE id=$1 RETURNING session_generation,request_epoch`, 3, 4, false)
	_, err := pool.Exec(ctx, `UPDATE users SET session_generation=session_generation-1 WHERE id=$1`, id)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "users_session_generation_monotonic" {
		t.Fatal("session generation decrease did not refuse with exact constraint")
	}
	_, err = pool.Exec(ctx, `UPDATE sessions SET session_generation=3 WHERE id=$1`, sessionID)
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "sessions_generation_immutable" {
		t.Fatal("old session snapshot was rewritten to revive its cookie")
	}
	_, err = pool.Exec(ctx, `INSERT INTO sessions(user_id,session_generation,token_digest,csrf_token,expires_at)
VALUES ($1,2,'owned-stale-generation-digest','owned-csrf',now()+interval '1 hour')`, id)
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "sessions_generation_current" {
		t.Fatal("stale explicit session admission was silently refreshed")
	}
	if err := pool.QueryRow(ctx, `SELECT session_generation FROM sessions WHERE id=$1`, sessionID).Scan(&generation); err != nil || generation != 1 || contextVersion() != before {
		t.Fatal("refused snapshot rewrite/decrease/insert changed authority")
	}
	var safeHelpers int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
WHERE n.nspname='public' AND p.proname IN ('advance_user_session_generation','stamp_session_generation')
AND NOT p.prosecdef AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='public.users'::regclass)
AND p.proconfig @> ARRAY['search_path=pg_catalog, pg_temp']
AND NOT EXISTS(SELECT 1 FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee=0 AND a.privilege_type='EXECUTE')`).Scan(&safeHelpers); err != nil || safeHelpers != 2 {
		t.Fatal("session helpers broadened owner/definer/search-path/PUBLIC execution boundary")
	}
}

func TestBrowserSessionGenerationOverflowRefusesWholeFence(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	for _, dimension := range []string{"session_generation", "request_epoch"} {
		t.Run(dimension, func(t *testing.T) {
			id := uuid.New()
			var sessionGen, requestEpoch int64 = 1, 1
			const maximum = int64(9223372036854775807)
			if dimension == "session_generation" {
				sessionGen = maximum
			} else {
				requestEpoch = maximum
			}
			if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject,session_generation,request_epoch)
VALUES ($1,$2,'Generation overflow','test',$3,$4,$5)`, id, dimension+"@example.test", dimension, sessionGen, requestEpoch); err != nil {
				t.Fatal(err)
			}
			statement := `UPDATE users SET session_generation=session_generation+1 WHERE id=$1`
			if dimension == "session_generation" {
				statement = `UPDATE users SET status='suspended' WHERE id=$1`
			}
			_, err := pool.Exec(ctx, statement, id)
			var pe *pgconn.PgError
			if !errors.As(err, &pe) || pe.Code != "22003" {
				t.Fatal("generation overflow did not refuse whole fence:", err)
			}
			var status string
			var gotGen, gotEpoch int64
			if err := pool.QueryRow(ctx, `SELECT status,session_generation,request_epoch FROM users WHERE id=$1`, id).Scan(&status, &gotGen, &gotEpoch); err != nil || status != "active" || gotGen != sessionGen || gotEpoch != requestEpoch {
				t.Fatal("generation overflow partially changed the subject")
			}
		})
	}
}
