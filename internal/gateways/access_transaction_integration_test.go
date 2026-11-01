package gateways

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/ncecere/open-mcp-portal/internal/store"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestUsableInTxSeesOwningUncommittedGrantAndRefusesOtherQueries(t *testing.T) {
	pool, _ := testutil.NewDB(t)
	ctx := context.Background()
	userID, gatewayID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'gateway-tx@example.test','Gateway transaction','test','gateway-tx')`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateways(id,slug,name,owner_kind)
VALUES ($1,'gateway-tx','Gateway transaction','platform')`, gatewayID); err != nil {
		t.Fatal(err)
	}
	user, err := dbgen.New(pool).GetUser(ctx, userID)
	if err != nil {
		t.Fatal(err)
	}
	svc := New(pool, "http://localhost", nil)
	assertRefused := func(q *dbgen.Queries) {
		t.Helper()
		allowed, denied, err := svc.UsableInTx(ctx, q, user, []uuid.UUID{gatewayID})
		if err == nil || allowed != nil || denied != nil {
			t.Fatal("unregistered or expired queries accepted as transactional authority")
		}
	}
	assertRefused(nil)
	assertRefused(dbgen.New(pool))
	external, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertRefused(dbgen.New(external))
	var one int
	if err := external.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatal("refused helper disturbed its unregistered owner's transaction")
	}
	if err := external.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	var expired *dbgen.Queries
	rollback := errors.New("owned test transaction must roll back")
	err = store.InTx(ctx, pool, func(q *dbgen.Queries, tx pgx.Tx) error {
		expired = q
		if _, err := tx.Exec(ctx, `INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2)`, gatewayID, userID); err != nil {
			return err
		}
		allowed, denied, err := svc.UsableInTx(ctx, q, user, []uuid.UUID{gatewayID})
		if err != nil || len(allowed) != 1 || allowed[0].ID != gatewayID || len(denied) != 0 {
			t.Fatal("scoped reader did not see its owning uncommitted grant")
		}
		outside, missing, err := svc.Usable(ctx, user, []uuid.UUID{gatewayID})
		if err != nil || len(outside) != 0 || len(missing) != 1 || missing[0] != gatewayID {
			t.Fatal("pool control unexpectedly saw the uncommitted grant")
		}
		if err := tx.QueryRow(ctx, "SELECT 1").Scan(&one); err != nil || one != 1 {
			t.Fatal("scoped reader completed or poisoned its owner")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal("explicit owner rollback did not propagate:", err)
	}
	assertRefused(expired)
	allowed, denied, err := svc.Usable(ctx, user, []uuid.UUID{gatewayID})
	if err != nil || len(allowed) != 0 || len(denied) != 1 {
		t.Fatal("scoped helper committed the owner's deliberately rolled-back authority")
	}
}
