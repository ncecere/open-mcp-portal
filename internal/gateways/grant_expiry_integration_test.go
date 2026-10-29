package gateways

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestGrantExpirySQLScopesServiceAccountsAndCleanup(t *testing.T) {
	ctx := context.Background()
	pool, _ := testutil.NewDB(t)
	q := dbgen.New(pool)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	user, team, gateway := uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO users(id,oidc_issuer,oidc_subject,email,groups) VALUES($1,'test','expiry','expiry@example.invalid','{example}')`, user)
	exec(`INSERT INTO teams(id,slug,name) VALUES($1,'expiry','Expiry')`, team)
	exec(`INSERT INTO team_members(team_id,user_id,role) VALUES($1,$2,'owner')`, team, user)
	exec(`INSERT INTO gateways(id,slug,name,owner_kind) VALUES($1,'expiry','Expiry','platform')`, gateway)
	exec(`INSERT INTO gateway_grants(gateway_id,subject_kind,team_id,tool_scope,expires_at) VALUES($1,'team',$2,'{"classes":["destructive"]}',clock_timestamp()-interval '1 second')`, gateway, team)
	exec(`INSERT INTO gateway_grants(gateway_id,subject_kind,user_id,tool_scope) VALUES($1,'user',$2,'{"classes":["read"]}')`, gateway, user)
	u, err := q.GetUser(ctx, user)
	if err != nil {
		t.Fatal(err)
	}
	g, err := q.GetGateway(ctx, gateway)
	if err != nil {
		t.Fatal(err)
	}
	caller, err := callerOf(ctx, q, g, u)
	if err != nil || !caller.Allowed() || !caller.ToolPolicy.Allows("read", "tool") || caller.ToolPolicy.Allows("destructive", "tool") {
		t.Fatalf("expired scoped alternative contributes authority: %+v %v", caller, err)
	}
	for _, test := range []struct {
		name string
		run  func() (bool, error)
	}{
		{"team predicate", func() (bool, error) {
			return q.TeamHasGatewayGrant(ctx, dbgen.TeamHasGatewayGrantParams{GatewayID: gateway, TeamID: uuid.NullUUID{UUID: team, Valid: true}})
		}},
		{"service-account caller", func() (bool, error) {
			c, err := serviceAccountCaller(ctx, q, g, team, "member")
			return c.Allowed(), err
		}},
		{"service-account list", func() (bool, error) {
			gs, err := q.ListGatewaysForServiceAccount(ctx, uuid.NullUUID{UUID: team, Valid: true})
			return len(gs) > 0, err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowed, err := test.run()
			if err != nil || allowed {
				t.Fatalf("expired team authority: allowed=%v err=%v", allowed, err)
			}
		})
	}
	before, err := q.GetApprovalContext(ctx)
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE gateway_grants SET expires_at=clock_timestamp()+interval '1 minute' WHERE subject_kind='team'`)
	after, err := q.GetApprovalContext(ctx)
	if err != nil || after <= before {
		t.Fatalf("expiry changed without authority invalidation: %d -> %d %v", before, after, err)
	}
	caller, err = callerOf(ctx, q, g, u)
	if err != nil || caller.ExpiresAt == nil || !caller.ExpiresAt.After(time.Now()) {
		t.Fatalf("live expiry snapshot missing: %+v %v", caller, err)
	}
	exec(`UPDATE gateway_grants SET expires_at=clock_timestamp()-interval '1 second' WHERE subject_kind='team'`)
	n, err := New(pool, "http://localhost", testutil.Logger()).CleanupGrants(ctx, 1)
	if err != nil || n != 1 {
		t.Fatalf("cleanup=%d %v", n, err)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_log WHERE action='gateway.grant_expire'`).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("expiry audit=%d %v", audits, err)
	}
}
