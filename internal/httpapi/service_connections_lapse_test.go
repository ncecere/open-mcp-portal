package httpapi_test

import (
	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"testing"
)

func TestServiceConnectionConnectorRemovalAndDeletion(t *testing.T) {
	for _, kind := range []string{"remove", "delete"} {
		t.Run(kind, func(t *testing.T) {
			e := newProvEnv(t)
			sa := createSA(t, e.owner, map[string]any{"name": "lapse-ci"})
			key := createSAKey(t, e.owner, sa.Id.String(), map[string]any{"name": "ci"}).Secret
			c := connectShared(t, e.owner, e.provider.Id, "lapse")
			code, ec, _ := assignShared(t, e.owner, c, []uuid.UUID{sa.Id}, []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}})
			mustCode(t, "assign", code, ec, 200, "")
			// A connector with no audit-history FK also exercises the schema's SET
			// NULL deletion behavior independently of the platform's user lifecycle.
			user := e.scalar(`INSERT INTO users(oidc_issuer,oidc_subject,email) VALUES('test','connector','connector@example.com') RETURNING id::text`)
			e.scalar(`INSERT INTO team_members(team_id,user_id,role) SELECT id,$1,'admin' FROM teams WHERE slug='tools' RETURNING 'ok'`, user)
			e.scalar(`UPDATE service_connections SET connected_by=$2 WHERE id=$1 RETURNING 'ok'`, c.Id, user)
			if !e.providerReport(e.callTool(key, f3Tool)).Received {
				t.Fatal("eligible connector refused")
			}
			if kind == "remove" {
				e.scalar(`DELETE FROM team_members WHERE user_id=$1 RETURNING 'ok'`, user)
			} else {
				e.scalar(`DELETE FROM users WHERE id=$1 RETURNING 'ok'`, user)
			}
			serviceDenied(t, e.callTool(key, f3Tool), "service_connection_lapsed")
			if status := e.scalar(`SELECT status FROM service_connections WHERE id=$1`, c.Id); status != "active" {
				t.Fatal("derived lapse destroyed consent")
			}
		})
	}
}
