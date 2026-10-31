package apikeys

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/authz"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestCreateRechecksSuspensionAfterUserLockWait(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
		VALUES ($1,'key-wait@example.test','Key wait','test','key-wait')`, userID); err != nil {
		t.Fatal(err)
	}
	blocker, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Rollback(context.Background())
	if _, err := blocker.Exec(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, userID); err != nil {
		t.Fatal(err)
	}
	var blockerPID int32
	if err := blocker.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID); err != nil {
		t.Fatal(err)
	}
	type result struct {
		created Created
		err     error
	}
	finished := make(chan result, 1)
	svc := New(pool, []byte("key-lifecycle-fixture-pepper"), nil)
	go func() {
		created, err := svc.Create(ctx, authz.Actor{UserID: userID}, CreateInput{Name: "must-not-create"})
		finished <- result{created, err}
	}()
	// Observe the actual final-writer lock wait; no elapsed-time scheduling.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_stat_activity a WHERE a.datname=current_database()
			AND position('-- name: GetUserForUpdate' IN a.query)>0
			AND $1::integer=ANY(pg_blocking_pids(a.pid)))`, blockerPID).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("key creation did not reach the user lock barrier")
		case <-tick.C:
		}
	}
	if _, err := blocker.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if err := blocker.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-finished:
		problem, ok := apperr.As(got.err)
		if !ok || problem.Status != http.StatusForbidden || got.created.Secret != "" {
			t.Fatal("creation did not refuse the suspended user after its lock wait")
		}
	case <-ctx.Done():
		t.Fatal("key creation did not finish")
	}
	var keys, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys),
		(SELECT count(*) FROM audit_log WHERE action='api_key.create')`).Scan(&keys, &audits); err != nil {
		t.Fatal(err)
	}
	if keys != 0 || audits != 0 {
		t.Fatal("refused creation left a key or creation audit")
	}
}

func TestCreateSuspensionPreservesExistingKeyReactivation(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	userID := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
		VALUES ($1,'key-standing@example.test','Key standing','test','key-standing')`, userID); err != nil {
		t.Fatal(err)
	}
	svc := New(pool, []byte("key-lifecycle-fixture-pepper"), nil)
	actor := authz.Actor{UserID: userID}
	first, err := svc.Create(ctx, actor, CreateInput{Name: "preserved"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='suspended' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, first.Secret); !errors.Is(err, ErrInvalid) {
		t.Fatal("suspended user's existing key authenticated")
	}
	created, err := svc.Create(ctx, actor, CreateInput{Name: "refused"})
	if problem, ok := apperr.As(err); !ok || problem.Status != http.StatusForbidden || created.Secret != "" {
		t.Fatal("suspended user created a new key")
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET status='active' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, first.Secret); err != nil {
		t.Fatal("reversible suspension destroyed an existing unrevoked key")
	}
	if _, err := svc.Create(ctx, actor, CreateInput{Name: "fresh-after-reactivation"}); err != nil {
		t.Fatal(err)
	}
	var keys, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys),
		(SELECT count(*) FROM audit_log WHERE action='api_key.create')`).Scan(&keys, &audits); err != nil {
		t.Fatal(err)
	}
	if keys != 2 || audits != 2 {
		t.Fatal("refused create changed key/audit inventory")
	}
}
