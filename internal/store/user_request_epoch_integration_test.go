package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestUserRequestEpochMonotonicAndApprovalJournalCoverage(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	id := uuid.New()
	var epoch int64
	if err := pool.QueryRow(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'epoch-store@example.test','Epoch store','test','epoch-store') RETURNING request_epoch`, id).Scan(&epoch); err != nil || epoch != 1 {
		t.Fatal("old-style insert did not receive initial epoch:", err)
	}
	var schema int64
	if err := pool.QueryRow(ctx, "SELECT max(version_id) FROM goose_db_version WHERE is_applied").Scan(&schema); err != nil || schema < 53 {
		t.Fatal("request epoch proof requires the current expanded schema53")
	}
	t.Log("REQUEST_EPOCH_SCHEMA53_APPLIED_OWNED_DB")
	current := func() int64 {
		t.Helper()
		var value int64
		if err := pool.QueryRow(ctx, "SELECT omp_private.omp_current_approval_context()").Scan(&value); err != nil {
			t.Fatal("read current approval context:", err)
		}
		return value
	}
	before := current()
	update := func(statement string, expected int64, authorityChanged bool) {
		t.Helper()
		if err := pool.QueryRow(ctx, statement, id).Scan(&epoch); err != nil || epoch != expected {
			t.Fatalf("request epoch: got=%d want=%d err=%v", epoch, expected, err)
		}
		after := current()
		if (authorityChanged && after <= before) || (!authorityChanged && after != before) {
			t.Fatal("approval context did not match actual authority change")
		}
		before = after
	}
	update("UPDATE users SET display_name='Profile-only change' WHERE id=$1 RETURNING request_epoch", 1, false)
	update("UPDATE users SET status='suspended' WHERE id=$1 RETURNING request_epoch", 2, true)
	update("UPDATE users SET status='active' WHERE id=$1 RETURNING request_epoch", 3, true)
	update("UPDATE users SET platform_role='platform_auditor' WHERE id=$1 RETURNING request_epoch", 4, true)
	update("UPDATE users SET platform_role=platform_role,status=status WHERE id=$1 RETURNING request_epoch", 4, false)
	update("UPDATE users SET request_epoch=request_epoch+1 WHERE id=$1 RETURNING request_epoch", 5, true)
	_, err := pool.Exec(ctx, "UPDATE users SET request_epoch=request_epoch-1 WHERE id=$1", id)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" || pe.ConstraintName != "users_request_epoch_monotonic" {
		t.Fatal("epoch decrease did not fail with exact monotonic constraint")
	}
	if err := pool.QueryRow(ctx, "SELECT request_epoch FROM users WHERE id=$1", id).Scan(&epoch); err != nil || epoch != 5 || current() != before {
		t.Fatal("refused decrease changed authority or its journal")
	}
}

func TestUserRequestEpochOverflowRefusesAccessChange(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	id := uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject,request_epoch)
VALUES ($1,'epoch-overflow@example.test','Epoch overflow','test','epoch-overflow',9223372036854775807)`, id); err != nil {
		t.Fatal("create owned maximum-epoch fixture:", err)
	}
	_, err := pool.Exec(ctx, "UPDATE users SET status='suspended' WHERE id=$1", id)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "22003" {
		t.Fatal("epoch overflow did not refuse the update")
	}
	var epoch int64
	var status string
	if err := pool.QueryRow(ctx, "SELECT request_epoch,status FROM users WHERE id=$1", id).Scan(&epoch, &status); err != nil || epoch != 9223372036854775807 || status != "active" {
		t.Fatal("failed epoch advance partially changed user standing")
	}
}
