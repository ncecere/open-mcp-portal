package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
	"github.com/ncecere/open-mcp-portal/migrations"
)

func TestSessionActivityMigration(t *testing.T) {
	runtime, _ := testutil.NewDB(t)
	pool := testutil.OwnerPool(t, runtime)
	ctx := context.Background()
	db := stdlib.OpenDBFromPool(pool)
	defer db.Close()
	provider, err := goose.NewProvider(goose.DialectPostgres, db, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	testutil.RemoveRetirementFencesForOldSchema(t, pool)
	if _, err := provider.DownTo(ctx, 26); err != nil {
		t.Fatal(err)
	}
	var userID string
	err = pool.QueryRow(ctx, `INSERT INTO users (oidc_issuer, oidc_subject, email) VALUES ('test', 'person', 'person@example.com') RETURNING id::text`).Scan(&userID)
	if err != nil {
		t.Fatal(err)
	}
	var sessionID string
	var created, expires time.Time
	err = pool.QueryRow(ctx, `INSERT INTO sessions (user_id, token_digest, csrf_token, created_at, expires_at) VALUES ($1, 'old-digest', 'csrf', now() - interval '1 hour', now() + interval '11 hours') RETURNING id::text, created_at, expires_at`, userID).Scan(&sessionID, &created, &expires)
	if err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
	var gotCreated, gotExpires, seen time.Time
	if err := pool.QueryRow(ctx, `SELECT created_at, expires_at, last_seen_at FROM sessions WHERE id=$1`, sessionID).Scan(&gotCreated, &gotExpires, &seen); err != nil {
		t.Fatal(err)
	}
	if !created.Equal(gotCreated) || !expires.Equal(gotExpires) || seen.Before(before) {
		t.Fatalf("upgrade changed lifetime or backdated activity: %s %s %s", gotCreated, gotExpires, seen)
	}
	// The previous release can still insert and read its original columns.
	if _, err := pool.Exec(ctx, `INSERT INTO sessions (user_id, token_digest, csrf_token, expires_at) VALUES ($1, 'old-release-insert', 'csrf', now() + interval '12 hours')`, userID); err != nil {
		t.Fatalf("previous release insert: %v", err)
	}
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE token_digest='old-release-insert' AND expires_at > now() AND last_seen_at IS NOT NULL`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("default activity = %d %v", count, err)
	}
	testutil.RemoveRetirementFencesForOldSchema(t, pool)
	if _, err := provider.DownTo(ctx, 26); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("rollback sessions = %d %v", count, err)
	}
	if _, err := provider.Up(ctx); err != nil {
		t.Fatal(err)
	}
}
