package httpapi_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

func TestServiceConnectionStorageAssignmentConstraints(t *testing.T) {
	e := newProvEnv(t)
	c := connectShared(t, e.owner, e.provider.Id, "constraints")
	sa := createSA(t, e.owner, map[string]any{"name": "constraint-ci"})
	own := e.scalar(`SELECT team_id::text FROM service_connections WHERE id=$1`, c.Id)
	foreign := e.scalar(`SELECT id::text FROM teams WHERE slug='other'`)
	otherProvider := e.scalar(`INSERT INTO auth_providers(slug,name,client_id,token_auth_method,pkce,authorization_url,token_url) VALUES('other-constraint','Other','client','none',true,'https://auth.example/a','https://auth.example/t') RETURNING id::text`)
	ctx := context.Background()
	for _, v := range []struct{ team, provider string }{{foreign, e.provider.Id.String()}, {own, otherProvider}} {
		_, err := e.app.Pool.Exec(ctx, `INSERT INTO service_connection_accounts(connection_id,team_id,provider_id,service_account_id) VALUES($1,$2,$3,$4)`, c.Id, v.team, v.provider, sa.Id)
		var pe *pgconn.PgError
		if !errors.As(err, &pe) || pe.Code != "23503" {
			t.Fatalf("mismatched composite FK accepted: %v", err)
		}
	}
	code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, nil)
	mustCode(t, "valid assignment", code, ec, 200, "")
	second := connectShared(t, e.owner, e.provider.Id, "constraints-2")
	_, err := e.app.Pool.Exec(ctx, `INSERT INTO service_connection_accounts(connection_id,team_id,provider_id,service_account_id) VALUES($1,$2,$3,$4)`, second.Id, own, e.provider.Id, sa.Id)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23505" {
		t.Fatalf("ambiguous account/provider assignment accepted: %v", err)
	}
}
func TestServiceConnectionAuditFailureRollsBackAssignment(t *testing.T) {
	e := newProvEnv(t)
	c := connectShared(t, e.owner, e.provider.Id, "atomic")
	sa := createSA(t, e.owner, map[string]any{"name": "atomic-ci"})
	_, err := testutil.OwnerPool(t, e.app.Pool).Exec(context.Background(), `CREATE FUNCTION fail_service_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action LIKE 'service_connection.%' THEN RAISE EXCEPTION 'audit unavailable'; END IF; RETURN NEW; END; $$;
 CREATE TRIGGER service_audit_failure BEFORE INSERT ON audit_log FOR EACH ROW EXECUTE FUNCTION fail_service_audit();`)
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, nil)
	if code != 500 {
		t.Fatalf("audit failure returned %d", code)
	}
	if n := e.scalar(`SELECT count(*)::text FROM service_connection_accounts WHERE connection_id=$1`, c.Id); n != "0" {
		t.Fatal("assignment escaped failed audit transaction")
	}
	var list []apitypes.ServiceConnection
	if code := e.owner.get(sharedBase, &list); code != 200 || len(list) != 1 || list[0].Revision != c.Revision {
		t.Fatal("failed update changed metadata revision")
	}
}
