package httpapi_test

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/ncecere/open-mcp-portal/internal/gateways"
	"github.com/ncecere/open-mcp-portal/internal/httpapi"
	"github.com/ncecere/open-mcp-portal/internal/httpapi/apitypes"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
)

func TestServiceConnectionBoundProviderPreflightDoesNotWait(t *testing.T) {
	e, _, _, _, c := serviceOAuthSetup(t)
	gw := e.createGateway(e.owner, toolsTeam+"/gateways", "other-destination")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+gw.Id.String(), sel(e.capID(e.owner, e.server, "tool", "whoami")))
	// e.server is visible, but this OAuth provider is bound to another server.
	// Keep both possible blocking rows busy until the refusal is returned.
	pe := &provEnv{gwEnv: e.gwEnv}
	before := serviceMutationSnapshot(pe)
	g := pauseServiceMutation(t, pe, `SELECT 1 FROM service_connections WHERE id=$1 FOR UPDATE`, c.Id)
	if _, err := g.tx.Exec(g.ctx, `SELECT 1 FROM mcp_servers WHERE id=$1 FOR UPDATE`, e.server.Id); err != nil {
		t.Fatal(err)
	}
	done := g.launch("PUT", sharedBase+"/"+c.Id.String(), map[string]any{"accounts": []uuid.UUID{}, "servers": []apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}}}, c.Revision)
	g.finish(done, 404, "server_not_found")
	if after := serviceMutationSnapshot(pe); after != before {
		t.Fatal("wrong bound destination changed connection state")
	}
}

func TestServiceConnectionGrantReachabilityOncePerPass(t *testing.T) {
	var reads atomic.Int32
	e := newProvEnvHook(t, func(d *httpapi.Deps) {
		original := d.Providers.Reachable
		d.Providers.Reachable = func(ctx context.Context, u dbgen.User) ([]gateways.ReachableServer, error) {
			reads.Add(1)
			return original(ctx, u)
		}
	})
	second := e.createServer(e.owner, "tools", "second", e.fake.URL(), map[string]any{"requirement": map[string]any{"providerId": e.provider.Id, "scopes": []string{"repo"}}})
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+e.gateway.Id.String(), sel(e.capID(e.owner, e.server, "tool", "provider_token"), e.capID(e.owner, second, "tool", "provider_token")))
	c := sharedByNameAfterStart(t, e)
	reads.Store(0)
	code, ec, _ := assignShared(t, e.owner, c, nil, []apitypes.ServiceConnectionGrant{
		{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}},
		{ServerId: second.Id, Origin: registry.OriginOf(second.Url), Scopes: []string{"repo"}},
	})
	mustCode(t, "batch grant", code, ec, 200, "")
	if got := reads.Load(); got != 2 {
		t.Fatalf("reachability loads = %d, want one preflight and one authoritative pass", got)
	}
}

// Ineligible IDs must be rejected while either the connection (e.g. normal
// refresh) OR the destination row is busy. Neither lock may be reached first.
func TestServiceConnectionIneligibleGrantDoesNotWait(t *testing.T) {
	for _, kind := range []string{"foreign_private", "wrong_provider", "access_denied"} {
		for _, busy := range []string{"connection", "destination"} {
			t.Run(kind+"/"+busy, func(t *testing.T) {
				e := newProvEnv(t)
				c := sharedByNameAfterStart(t, e)
				sv, status, code := e.server, 409, "server_changed"
				switch kind {
				case "foreign_private":
					sv, status, code = e.other, 404, "server_not_found"
				case "wrong_provider":
					p := e.createProvider("different", e.oauth, nil)
					e.setRequirement(map[string]any{"providerId": p.Id, "scopes": []string{"repo"}})
				case "access_denied":
					e.setAccess(e.provider, "restricted", nil, nil)
					status, code = 422, "provider_not_allowed"
				}
				before := serviceMutationSnapshot(e)
				lock, target := `SELECT 1 FROM service_connections WHERE id=$1 FOR UPDATE`, c.Id
				if busy == "destination" {
					lock, target = `SELECT 1 FROM mcp_servers WHERE id=$1 FOR UPDATE`, sv.Id
					if kind == "foreign_private" {
						target = e.server.Id
					}
				}
				g := pauseServiceMutation(t, e, lock, target)
				grants := []apitypes.ServiceConnectionGrant{{ServerId: sv.Id, Origin: registry.OriginOf(sv.Url), Scopes: []string{"repo"}}}
				if kind == "foreign_private" {
					// An eligible destination before the ineligible ID must not be
					// locked either: preflight the entire batch before any lock.
					grants = append([]apitypes.ServiceConnectionGrant{{ServerId: e.server.Id, Origin: registry.OriginOf(e.server.Url), Scopes: []string{"repo"}}}, grants...)
				}
				done := g.launch("PUT", sharedBase+"/"+c.Id.String(), map[string]any{"accounts": []uuid.UUID{}, "servers": grants}, c.Revision)
				// Keep the blocking transaction open until the response: unlike a
				// time-based 'not yet waiting' assertion, success proves no wait.
				g.finish(done, status, code)
				if after := serviceMutationSnapshot(e); after != before {
					t.Fatal("ineligible preflight changed connection, consent or audit")
				}
				if e.oauth.TokenRequests() != 0 || e.oauth.RefreshRequests() != 0 {
					t.Fatal("metadata preflight performed provider HTTP")
				}
			})
		}
	}
}
