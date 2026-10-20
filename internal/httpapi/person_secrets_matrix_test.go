package httpapi_test

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/ncecere/open-mcp-portal/internal/registry"
)

// The authorization matrix's rows for the person secret operations (decision
// 72). Every operation is session only; entering and removing a key is the
// person's own, so each signed-in caller does it for themselves, and a person
// can't reach another's (the request or the entry of the spare user answers
// 404). Platform admins revoke anyone's; auditors read.

var secretFixtures sync.Map // *matrixEnv -> server ID

// secretServer is a published server of team A in person_secret mode with an
// approved tool on the platform gateway, so every signed-in caller may use it.
func (e *matrixEnv) secretServer() string {
	if v, ok := secretFixtures.Load(e); ok {
		return v.(string)
	}
	id := e.newServer(e.a, "published")
	e.exec(`UPDATE mcp_servers SET auth_mode = 'person_secret', secret_placement = 'header', secret_name = 'X-Api-Key',
		secret_label = 'Matrix key' WHERE id = $1 RETURNING 'x'`, id)
	capID := e.exec(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint)
		VALUES ($1, 'tool', 'secret_tool', '{"name":"secret_tool"}', repeat('a', 64), repeat('a', 64)) RETURNING id::text`, id)
	e.exec(`INSERT INTO gateway_capabilities (gateway_id, capability_id) VALUES ($1, $2) RETURNING gateway_id::text`, e.platformGateway, capID)
	secretFixtures.Store(e, id)
	return id
}

// newPersonSecret makes sure a person has a key for the secret server.
func (e *matrixEnv) newPersonSecret(userID string) {
	e.exec(`INSERT INTO person_secrets (user_id, server_id, origin, secret_cipher) VALUES ($1, $2, $3, '\x00')
		ON CONFLICT (user_id, server_id) DO UPDATE SET status = 'active' RETURNING id::text`,
		userID, e.secretServer(), registry.OriginOf(e.fakeURL))
}

// newSecretRequest inserts an open link of a person and returns its ID.
func (e *matrixEnv) newSecretRequest(userID string) string {
	id := fmt.Sprintf("%043d", e.next())
	sum := sha256.Sum256([]byte(id))
	e.exec(`INSERT INTO secret_requests (id_digest, id_cipher, user_id, server_id, server_origin, reason, gateway_id, gateway_slug,
		gateway_name, capability_id, capability_kind, exposed_name, expires_at)
		VALUES ($1, '\x00', $2, $3, $4, 'secret_missing', $5, 'gw', 'Gateway', gen_random_uuid(), 'tool', 'srv__tool',
		        now() + interval '10 minutes') RETURNING id_digest`,
		base64.RawURLEncoding.EncodeToString(sum[:]), userID, e.secretServer(), registry.OriginOf(e.fakeURL), e.platformGateway)
	return id
}

func init() {
	matrixPolicies["listMyServerSecrets"] = policy{own: signedIn, build: func(*mctx) request { return get("/v1/me/server-secrets") }}
	matrixPolicies["setMyServerSecret"] = policy{own: signedIn, build: func(c *mctx) request {
		return put("/v1/me/server-secrets/"+c.e.secretServer(), map[string]any{"origin": registry.OriginOf(c.e.fakeURL), "value": "matrix-key-0123456789"})
	}}
	matrixPolicies["revokeMyServerSecret"] = policy{own: signedIn, build: func(c *mctx) request {
		if c.allowed {
			c.e.newPersonSecret(c.e.userIDs[c.who])
		}
		return del("/v1/me/server-secrets/" + c.e.secretServer())
	}}
	matrixPolicies["getSecretRequest"] = policy{own: signedIn, build: func(c *mctx) request {
		owner := c.e.spareUser
		if c.allowed {
			owner = c.e.userIDs[c.who]
		}
		return get("/v1/connect/secret-requests/" + c.e.newSecretRequest(owner))
	}}
	matrixPolicies["adminListUserServerSecrets"] = policy{own: platform, build: func(c *mctx) request {
		return get("/v1/admin/users/" + c.e.spareUser + "/server-secrets")
	}}
	matrixPolicies["adminRevokeUserServerSecret"] = policy{own: padmin, build: func(c *mctx) request {
		if c.allowed {
			c.e.newPersonSecret(c.e.spareUser)
		}
		return del("/v1/admin/users/" + c.e.spareUser + "/server-secrets/" + c.e.secretServer())
	}}
}
