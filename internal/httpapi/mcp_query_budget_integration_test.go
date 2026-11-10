package httpapi_test

import (
	"strings"
	"testing"

	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The database round trips one gateway request makes. Each budget is the
// measured count: lower it when a change removes a statement, and treat a
// rise as a regression to justify (raise it in the same change, with the
// reason in the commit).
//
// The fixture is the plain case: a personal API key, a modern-era client
// and server, a static (no-auth) upstream, no approval rule, no capture.
var mcpQueryBudgets = map[string]int{
	"team/tools/list":     8,
	"team/tools/call":     33,
	"platform/tools/list": 7,
	"platform/tools/call": 31,
}

func TestMCPQueryBudget(t *testing.T) {
	e := newGwEnv(t, nil)
	e.fake.SetProtocol(testutil.ProtocolModern)
	echo := e.capID(e.owner, e.server, "tool", "echo")
	team := e.createGateway(e.owner, toolsTeam+"/gateways", "team-gw")
	e.mustSetCaps(e.owner, toolsTeam+"/gateways/"+team.Id.String(), sel(echo))
	e.publish(e.owner, e.server)
	platform := e.createGateway(e.admin, "/v1/admin/gateways", "platform-gw")
	e.mustSetCaps(e.admin, "/v1/admin/gateways/"+platform.Id.String(), sel(echo))
	code, ec := e.admin.call("POST", "/v1/admin/gateways/"+platform.Id.String()+"/grants",
		map[string]any{"subjectKind": "team", "team": "tools"}, nil, nil)
	mustCode(t, "grant", code, ec, 201, "")
	key := newKey(t, e.owner, "budget").Secret
	log := testutil.QueryLogOf(t, e.app.Pool)

	for _, gw := range []struct{ kind, slug string }{{"team", "team-gw"}, {"platform", "platform-gw"}} {
		_, _, listed := rawModern(t, e.app, gw.slug, key, "tools/list", map[string]any{}, nil, nil)
		tool := resultOf(t, listed)["tools"].([]any)[0].(map[string]any)["name"]
		requests := map[string]map[string]any{
			"tools/list": {},
			"tools/call": {"name": tool, "arguments": map[string]any{"text": "hi"}},
		}
		for method, params := range requests {
			name := gw.kind + "/" + method
			t.Run(name, func(t *testing.T) {
				send := func() {
					code, _, out := rawModern(t, e.app, gw.slug, key, method, params, nil, nil)
					if code != 200 || out["error"] != nil {
						t.Fatalf("%s = %d %v", method, code, out)
					}
				}
				// Warm the era, settings and identity caches first, then
				// take the quietest of a few runs: background loops share
				// the pool and can only add statements.
				send()
				send()
				var best []string
				for range 5 {
					if got := log.Record(send); best == nil || len(got) < len(best) {
						best = got
					}
				}
				budget := mcpQueryBudgets[name]
				t.Logf("%s: %d statements (budget %d)\n  %s", name, len(best), budget, strings.Join(best, "\n  "))
				if len(best) > budget {
					t.Errorf("%s made %d database round trips, over its budget of %d", name, len(best), budget)
				}
				if len(best) < budget {
					t.Errorf("%s made %d database round trips, under its budget of %d: lower the budget to lock the gain in", name, len(best), budget)
				}
			})
		}
	}
}
