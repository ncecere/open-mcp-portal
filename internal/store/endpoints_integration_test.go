package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestEndpointSchemaAuthorityFenceAndHistoricalHealth(t *testing.T) {
	approvalModes(t, func(t *testing.T, pool *pgxpool.Pool) {
		ctx := context.Background()
		team, server, endpoint := uuid.New(), uuid.New(), uuid.New()
		roleExec(t, pool, `INSERT INTO teams(id,slug,name) VALUES($1,'endpoint','Endpoint')`, team)
		roleExec(t, pool, `INSERT INTO mcp_servers(id,team_id,slug,name,url) VALUES($1,$2,'endpoint','Endpoint','https://primary.example/mcp')`, server, team)
		before := approvalEpoch(t, pool)
		roleExec(t, pool, `INSERT INTO mcp_server_endpoints(id,server_id,position,url,auth_mode,credential_origin) VALUES($1,$2,1,'https://extra.example/mcp','none','https://extra.example')`, endpoint, server)
		if approvalEpoch(t, pool) <= before {
			t.Fatal("endpoint insert did not invalidate authority")
		}
		before = approvalEpoch(t, pool)
		roleExec(t, pool, `UPDATE mcp_server_endpoints SET enabled=false WHERE id=$1`, endpoint)
		if approvalEpoch(t, pool) <= before {
			t.Fatal("endpoint update did not invalidate authority")
		}
		// A lock on ONLY the new table must conflict with the owner-definer
		// fence. A journal lock alone is not sufficient evidence of coverage.
		writer, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Rollback(ctx)
		if _, err := writer.Exec(ctx, `LOCK TABLE public.mcp_server_endpoints IN ROW EXCLUSIVE MODE`); err != nil {
			t.Fatal(err)
		}
		fence, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer fence.Rollback(ctx)
		_, err = dbgen.New(fence).LockApprovalContext(ctx)
		var pg *pgconn.PgError
		if !errors.As(err, &pg) || pg.Code != "55P03" {
			t.Fatalf("endpoint table not fenced NOWAIT: %v", err)
		}
		_ = fence.Rollback(ctx)
		_ = writer.Rollback(ctx)
		for _, sql := range []string{
			`INSERT INTO mcp_server_endpoints(id,server_id,position,url,auth_mode,credential_origin) VALUES(gen_random_uuid(),$1,3,'https://third.example','none','https://third.example')`,
			`INSERT INTO mcp_server_endpoints(id,server_id,position,url,auth_mode,credential_origin) VALUES(gen_random_uuid(),$1,2,'https://extra.example/mcp','none','https://extra.example')`,
			`INSERT INTO mcp_server_endpoints(id,server_id,position,url,auth_mode,credential_origin,credentials_cipher) VALUES(gen_random_uuid(),$1,2,'https://invalid.example','none','https://invalid.example','\x00')`,
			`INSERT INTO mcp_server_endpoints(id,server_id,position,url,auth_mode,credential_origin) VALUES(gen_random_uuid(),$1,2,'https://invalid.example','static_header','https://invalid.example')`,
		} {
			if _, err := pool.Exec(ctx, sql, server); err == nil {
				t.Fatal("invalid endpoint row accepted")
			}
		}
		var primary int64
		if err := pool.QueryRow(ctx, `INSERT INTO mcp_health_checks(server_id,ok,latency_ms,trigger,status_since) VALUES($1,true,1,'manual',now()) RETURNING id`, server).Scan(&primary); err != nil {
			t.Fatal(err)
		}
		failure := "unavailable"
		if _, err := dbgen.New(pool).InsertMCPServerEndpointHealthCheck(ctx, dbgen.InsertMCPServerEndpointHealthCheckParams{ServerID: server, EndpointID: endpoint, EndpointPosition: 1, Ok: false, LatencyMs: 2, Trigger: "manual", ErrorClass: &failure, Message: "Owned fixture failure"}); err != nil {
			t.Fatal(err)
		}
		latest, err := dbgen.New(pool).LatestMCPHealthChecks(ctx, []uuid.UUID{server})
		if err != nil || len(latest) != 1 || latest[0].ID != primary {
			t.Fatalf("extra health replaced canonical primary: %+v %v", latest, err)
		}
		before = approvalEpoch(t, pool)
		roleExec(t, pool, `DELETE FROM mcp_server_endpoints WHERE id=$1`, endpoint)
		if approvalEpoch(t, pool) <= before {
			t.Fatal("endpoint deletion did not invalidate authority")
		}
		var retained int
		if err := pool.QueryRow(ctx, `SELECT count(*) FROM mcp_health_checks WHERE endpoint_id=$1 AND endpoint_position=1`, endpoint).Scan(&retained); err != nil || retained != 1 {
			t.Fatalf("endpoint deletion erased historical identity: %d %v", retained, err)
		}
	})
}
