package apikeys

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/apperr"
	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// Real key creation must not leave its owning transaction for gateway access
// reads. A one-connection authenticated pool makes that escape deterministic.
func TestCreateGatewayScopeUsesOwningSingleConnectionTransaction(t *testing.T) {
	pool, dsn := testutil.NewDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	userID, gatewayID := uuid.New(), uuid.New()
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,email,display_name,oidc_issuer,oidc_subject)
VALUES ($1,'key-scope-tx@example.test','Key scope transaction','test','key-scope-tx')`, userID); err != nil {
		t.Fatal("subject fixture:", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateways(id,slug,name,owner_kind) VALUES ($1,'key-scope-tx','Key scope transaction','platform')`, gatewayID); err != nil {
		t.Fatal("gateway fixture:", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO gateway_grants(gateway_id,subject_kind,user_id) VALUES ($1,'user',$2)`, gatewayID, userID); err != nil {
		t.Fatal("gateway grant fixture:", err)
	}
	user, err := dbgen.New(pool).GetUser(ctx, userID)
	if err != nil {
		t.Fatal("admission fixture:", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("runtime pool configuration failed")
	}
	cfg.MaxConns, cfg.MinConns = 1, 0
	single, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal("single runtime pool creation failed")
	}
	defer single.Close()
	var sameRole, authenticated bool
	var originalRole string
	if err := pool.QueryRow(ctx, `SELECT current_user`).Scan(&originalRole); err != nil {
		t.Fatal("original authenticated role lookup failed")
	}
	if err := single.QueryRow(ctx, `SELECT current_user=$1,current_user=session_user`, originalRole).Scan(&sameRole, &authenticated); err != nil || !sameRole || !authenticated {
		t.Fatal("independently authenticated single runtime role mismatch")
	}
	t.Log("ACTUAL_KEY_GATEWAY_SINGLE_AUTHENTICATED_RUNTIME_REACHED")
	svc := New(single, []byte("key-scope-tx-fixture-pepper"), gateways.New(single, "http://localhost", nil))
	requestCtx, requestCancel := context.WithTimeout(ctx, 2*time.Second)
	created, err := svc.Create(requestCtx, (auth.Identity{User: user}).Actor("single-connection-key-scope", ""), CreateInput{Name: "scoped", GatewayIDs: []uuid.UUID{gatewayID}})
	requestCancel()
	if err != nil {
		t.Fatal("single-connection scoped create failed:", err)
	}
	if created.Secret == "" || len(created.Gateways) != 1 || created.Gateways[0].ID != gatewayID {
		t.Fatal("scoped create did not preserve original gateway and secret publication")
	}
	denied, err := svc.Create(ctx, (auth.Identity{User: user}).Actor("unknown-gateway-key-scope", ""), CreateInput{Name: "must-refuse", GatewayIDs: []uuid.UUID{uuid.New()}})
	problem, ok := apperr.As(err)
	if !ok || problem.Status != http.StatusUnprocessableEntity || problem.Code != "gateway_not_usable" || denied.Secret != "" {
		t.Fatal("unknown gateway did not refuse without a key")
	}
	var keys, audits int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM api_keys WHERE user_id=$1),
(SELECT count(*) FROM audit_log WHERE action='api_key.create' AND actor_user_id=$1)`, userID).Scan(&keys, &audits); err != nil || keys != 1 || audits != 1 {
		t.Fatal("scoped create/refusal changed key or audit inventory")
	}
}
