package httpapi_test

import (
	"fmt"
)

// matrixSCIMIssuer is the OIDC issuer the matrix app's provisioning binds to.
const matrixSCIMIssuer = "https://matrix-idp.example.test"

// provisioning ensures a directory and returns its current revision.
func (c *mctx) provisioning() string {
	return c.e.exec(`WITH ins AS (INSERT INTO scim_directories (issuer, enabled) VALUES ($1, true) ON CONFLICT (singleton) DO NOTHING RETURNING revision)
		SELECT revision::text FROM ins UNION ALL SELECT revision::text FROM scim_directories LIMIT 1`, matrixSCIMIssuer)
}

func (c *mctx) provisioningToken() string {
	c.provisioning()
	n := c.e.next()
	return c.e.exec(`INSERT INTO scim_tokens (directory_id, name, prefix, digest, expires_at)
		SELECT id, $1::text, 'ompscim_matrix00', encode(sha256($1::text::bytea), 'hex'), now() + interval '30 days' FROM scim_directories RETURNING id::text`,
		fmt.Sprintf("matrix-scim-%d", n))
}

// adoptable is a resource whose externalId matches an existing unmanaged person.
func (c *mctx) adoptable() string {
	c.provisioning()
	n := c.e.next()
	sub := fmt.Sprintf("matrix-adopt-%d", n)
	c.e.exec(`INSERT INTO users (email, display_name, oidc_issuer, oidc_subject) VALUES ($1, 'Adoptable', $2, $3) RETURNING id::text`,
		sub+"@example.test", matrixSCIMIssuer, sub)
	return c.e.exec(`INSERT INTO scim_users (directory_id, user_name, external_id) SELECT id, $1, $1 FROM scim_directories RETURNING id::text`, sub)
}

func (c *mctx) managedPerson() string {
	c.provisioning()
	n := c.e.next()
	sub := fmt.Sprintf("matrix-managed-%d", n)
	return c.e.exec(`INSERT INTO users (email, display_name, oidc_issuer, oidc_subject, directory_standing) VALUES ($1, 'Managed', $2, $3, 'active') RETURNING id::text`,
		sub+"@example.test", matrixSCIMIssuer, sub)
}

func (c *mctx) scimGroup() string {
	c.provisioning()
	return c.e.exec(`INSERT INTO scim_groups (directory_id, display_name) SELECT id, $1 FROM scim_directories RETURNING id::text`, fmt.Sprintf("matrix-group-%d", c.e.next()))
}

func init() {
	const base = "/v1/admin/provisioning"
	for op, p := range map[string]policy{
		"adminGetProvisioning": {own: platform, build: func(c *mctx) request { c.provisioning(); return get(base) }},
		"adminCreateProvisioning": {own: padmin, build: func(c *mctx) request {
			if c.allowed {
				c.e.run(`DELETE FROM scim_directories`)
			}
			return post(base, map[string]any{"enabled": false, "enrollment": "optional"})
		}},
		"adminUpdateProvisioning": {own: padmin, build: func(c *mctx) request {
			rev := c.provisioning()
			return patch(base, map[string]any{"enabled": true, "enrollment": "optional"}).h(map[string]string{"If-Match": `"` + rev + `"`})
		}},
		"adminListProvisioningTokens": {own: platform, build: func(c *mctx) request { c.provisioning(); return get(base + "/tokens") }},
		"adminCreateProvisioningToken": {own: padmin, build: func(c *mctx) request {
			c.provisioning()
			c.e.run(`UPDATE scim_tokens SET revoked_at = now() WHERE revoked_at IS NULL`)
			return post(base+"/tokens", map[string]any{"name": "matrix", "expiresInDays": 30})
		}},
		"adminRevokeProvisioningToken":  {own: padmin, build: func(c *mctx) request { return del(base + "/tokens/" + c.provisioningToken()) }},
		"adminListProvisionedUsers":     {own: platform, build: func(c *mctx) request { c.provisioning(); return get(base + "/users") }},
		"adminAdoptProvisionedUser":     {own: padmin, build: func(c *mctx) request { return post(base+"/users/"+c.adoptable()+"/adopt", nil) }},
		"adminUnlinkProvisionedPerson":  {own: padmin, build: func(c *mctx) request { return post(base+"/people/"+c.managedPerson()+"/unlink", nil) }},
		"adminListProvisionedGroups":    {own: platform, build: func(c *mctx) request { c.provisioning(); return get(base + "/groups") }},
		"adminListProvisioningMappings": {own: platform, build: func(*mctx) request { return get(base + "/mappings") }},
		"adminCreateProvisioningMapping": {own: padmin, build: func(c *mctx) request {
			return post(base+"/mappings", map[string]any{"groupId": c.scimGroup(), "teamId": c.e.b.id, "role": "member"})
		}},
		"adminDeleteProvisioningMapping": {own: padmin, build: func(c *mctx) request {
			id := c.e.exec(`INSERT INTO scim_group_mappings (group_id, team_id, role) VALUES ($1, $2, 'member') RETURNING id::text`, c.scimGroup(), c.e.b.id)
			return del(base + "/mappings/" + id)
		}},
	} {
		if _, dup := matrixPolicies[op]; dup {
			panic("matrix: " + op + " classified twice")
		}
		matrixPolicies[op] = p
	}
}
