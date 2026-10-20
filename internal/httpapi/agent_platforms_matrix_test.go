package httpapi_test

import (
	"fmt"
)

// Classification of the agent platform operations in the authorization
// matrix (decisions 65 and 66, docs/agent-platforms.md): trusted platforms
// and relay marks are platform admins (auditors read); the capability's
// present-person override is a team editor's. Automation tokens are refused
// on all of them by the token matrix (none is annotated x-omp-token-scopes).

// newAgentPlatform inserts a trusted platform and returns its ID.
func (e *matrixEnv) newAgentPlatform() string {
	n := e.next()
	return e.exec(`INSERT INTO agent_platforms (name, issuer, jwks_url, audience) VALUES ($1::text, $2::text, $3::text, 'https://portal.example.org') RETURNING id::text`,
		fmt.Sprintf("platform-%d", n), fmt.Sprintf("https://agents-%d.example.com", n), "http://127.0.0.1:9/jwks") // nothing listens there: a Test answers ok:false at once
}

// agentPlatform is a fresh platform when the call is expected to succeed,
// else the first one.
func (c *mctx) agentPlatform() string {
	if c.allowed {
		return c.e.newAgentPlatform()
	}
	return c.e.fixture(`SELECT id::text FROM agent_platforms ORDER BY created_at LIMIT 1`, func() string { return c.e.newAgentPlatform() })
}

// relay is a platform and a service account that relays for it (fresh when
// the call is expected to succeed).
func (c *mctx) relay() (platform, account string) {
	platform = c.agentPlatform()
	account = c.serviceAccount()
	c.e.exec(`UPDATE service_accounts SET relay_platform_id = $1 WHERE id = $2 RETURNING id::text`, platform, account)
	return platform, account
}

func init() {
	const base = "/v1/admin/agent-platforms"
	for op, p := range map[string]policy{
		"adminListAgentPlatforms": {own: platform, build: func(*mctx) request { return get(base) }},
		"adminCreateAgentPlatform": {own: padmin, build: func(c *mctx) request {
			n := c.e.next()
			return post(base, map[string]any{"name": fmt.Sprintf("created-%d", n), "issuer": fmt.Sprintf("https://created-%d.example.com", n)})
		}},
		"adminGetAgentPlatform": {own: platform, build: func(c *mctx) request { return get(base + "/" + c.agentPlatform()) }},
		"adminUpdateAgentPlatform": {own: padmin, build: func(c *mctx) request {
			return patch(base+"/"+c.agentPlatform(), map[string]any{"enabled": false}).h(rev1)
		}},
		"adminDeleteAgentPlatform": {own: padmin, build: func(c *mctx) request { return del(base + "/" + c.agentPlatform()) }},
		// The test fetches the platform's JWKS: a fixture host that doesn't
		// resolve is an answer ok:false, still a 200.
		"adminTestAgentPlatform": {own: padmin, build: func(c *mctx) request { return post(base+"/"+c.agentPlatform()+"/test", nil) }},
		"adminListAgentPlatformRelays": {own: platform, build: func(c *mctx) request {
			plat, _ := c.relay()
			return get(base + "/" + plat + "/relays")
		}},
		"adminSetServiceAccountRelay": {own: padmin, build: func(c *mctx) request {
			return put(base+"/"+c.agentPlatform()+"/relays/"+c.serviceAccount(), nil)
		}},
		"adminClearServiceAccountRelay": {own: padmin, build: func(c *mctx) request {
			plat, sa := c.relay()
			return del(base + "/" + plat + "/relays/" + sa)
		}},
		"setTeamMcpCapabilityPresentPerson": {scope: scopeTeam, own: editors, build: func(c *mctx) request {
			srv, capID := c.serverCapability()
			return request{method: "PUT", path: c.team("/mcp-servers/" + srv + "/capabilities/" + capID + "/present-person"),
				body: map[string]any{"mode": "required"}, headers: rev1}
		}},
	} {
		if _, dup := matrixPolicies[op]; dup {
			panic("duplicate matrix policy " + op)
		}
		matrixPolicies[op] = p
	}
}
