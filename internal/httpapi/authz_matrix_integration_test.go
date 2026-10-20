package httpapi_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ncecere/open-mcp-portal/internal/auth"
	"github.com/ncecere/open-mcp-portal/internal/capture"
	"github.com/ncecere/open-mcp-portal/internal/config"
	"github.com/ncecere/open-mcp-portal/internal/httpx"
	"github.com/ncecere/open-mcp-portal/internal/registry"
	"github.com/ncecere/open-mcp-portal/internal/secrets"
	"github.com/ncecere/open-mcp-portal/internal/store/dbgen"
	"github.com/ncecere/open-mcp-portal/internal/testutil"
)

// The authorization matrix. Every operation in api/openapi.yaml is
// classified in matrixPolicies (authz_matrix_policy_test.go); this test calls
// every operation as every kind of caller:
//
//   - on the caller's own team (B), or globally: success exactly for the
//     classified callers, and 401, 403 or 404 for everyone else;
//   - on team A, of which the team-role callers are not members: denied for
//     everyone but the classified platform roles, and never with team A's
//     name or ID in a denied response.

// teamFix is one team's fixture.
type teamFix struct {
	slug, id, name string
	member         string // a member (role member) the callers are not, for update/remove
	invite         string // an open invite
	auditID        string // an entry of the team's audit log
	// server is a published, enabled MCP server with a changed capability
	// (capability), for reads and refused writes.
	server, capability string
	// gateway is a team gateway.
	gateway string
	// serviceAccount is a service account with one key (saKey).
	serviceAccount, saKey string
	// call is a call through the team's gateway, captured by the gateway.
	call string
	// oauthServer is a server in oauth mode (a public manual client).
	oauthServer string
}

type matrixEnv struct {
	t       *testing.T
	app     *testApp
	callers [numCallers]*session
	userIDs [numCallers]string
	a, b    teamFix
	// spareUser and spareTeam are targets of platform writes that are
	// refused; allowed writes get fresh ones.
	spareUser, spareTeam string
	// fakeURL is a fake MCP server every fixture server points at.
	fakeURL string
	// platformGateway is granted to team B and to every platform caller.
	platformGateway string
	// oauthClient is a registered OAuth client's ID.
	oauthClient string
	// provider is an enabled auth provider (a public client: no secret).
	provider string
	// requiringServer is a server of team A that requires provider (a
	// consent link is for one server).
	requiringServer string
	// allowableServer is a published server of team A that requires provider
	// (repo) with an approved tool on platformGateway: every signed-in caller
	// may use it, so each may allow it to use their connection.
	allowableServer string
	n               int
}

func (e *matrixEnv) next() int { e.n++; return e.n }

func (e *matrixEnv) exec(sql string, args ...any) string {
	e.t.Helper()
	var out string
	if err := e.app.Pool.QueryRow(context.Background(), sql, args...).Scan(&out); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// newUser inserts a user (as a sign-in would) and returns its ID.
func (e *matrixEnv) newUser(email, role string) string {
	return e.exec(`INSERT INTO users (oidc_issuer, oidc_subject, email, display_name, platform_role)
		VALUES ('matrix', $1, $2, $3, $4) RETURNING id::text`, email, email, email, role)
}

// sessionFor creates a browser session for a user directly in the database
// (the matrix needs more people than the development personas).
func (e *matrixEnv) sessionFor(userID string) *session {
	e.t.Helper()
	secret, csrf := httpx.NewID(32), httpx.NewID(32)
	e.exec(`INSERT INTO sessions (user_id, token_digest, csrf_token, expires_at)
		VALUES ($1, $2, $3, now() + interval '1 hour') RETURNING id::text`, userID, auth.Digest(secret), csrf)
	jar, _ := cookiejar.New(nil)
	jar.SetCookies(mustParse(e.t, e.app.URL), []*http.Cookie{{Name: auth.SessionCookieName(false), Value: secret, Path: "/"}})
	return &session{t: e.t, app: e.app, client: &http.Client{Jar: jar}, csrf: csrf}
}

func anonSession(t *testing.T, app *testApp) *session {
	jar, _ := cookiejar.New(nil)
	return &session{t: t, app: app, client: &http.Client{Jar: jar}}
}

func (e *matrixEnv) newTeam(slug, name string) teamFix {
	tf := teamFix{slug: slug, name: name}
	tf.id = e.exec(`INSERT INTO teams (slug, name) VALUES ($1, $2) RETURNING id::text`, slug, name)
	tf.member = e.newMember(tf, "member")
	tf.invite = e.newInvite(tf)
	tf.auditID = e.exec(`INSERT INTO audit_log (actor_kind, team_id, action, target_type, target_id)
		VALUES ('system', $1::uuid, 'team.create', 'team', $1::text) RETURNING id::text`, tf.id)
	tf.server = e.newServer(tf, "published")
	tf.capability = e.newChangedCapability(tf.server)
	tf.gateway = e.newGateway(tf.id)
	tf.serviceAccount = e.newServiceAccount(tf.id)
	tf.saKey = e.newServiceAccountKey(tf.serviceAccount)
	tf.call = e.newCapturedCall(tf.id, tf.gateway, tf.member)
	tf.oauthServer = e.newOAuthServer(tf)
	return tf
}

// newOAuthServer inserts a server in oauth mode with its server-bound
// provider (a public client, so starting a sign-in dials nothing).
func (e *matrixEnv) newOAuthServer(tf teamFix) string {
	n := e.next()
	id := e.exec(`INSERT INTO mcp_servers (team_id, slug, name, url, auth_mode) VALUES ($1, $2, $3, 'https://mcp.example.com/mcp', 'oauth')
		RETURNING id::text`, tf.id, fmt.Sprintf("oauth-srv-%d", n), fmt.Sprintf("OAuth server %d", n))
	e.exec(`INSERT INTO auth_providers (slug, name, kind, client_id, token_auth_method, pkce, authorization_url, token_url, server_id,
		registration, resource, issuer, authorization_server, resource_metadata_url, default_scopes)
		VALUES ($1, 'OAuth server', 'mcp_server', 'matrix-client', 'none', true, 'https://auth.example.com/authorize',
		'https://auth.example.com/token', $2, 'manual', 'https://mcp.example.com/mcp', 'https://auth.example.com', 'https://auth.example.com',
		'https://mcp.example.com/.well-known/oauth-protected-resource/mcp', '{repo}') RETURNING id::text`, fmt.Sprintf("mcp-%012d", n), id)
	return id
}

// newCapturedCall inserts a call through a team gateway with a payload its
// gateway's switch captured.
func (e *matrixEnv) newCapturedCall(teamID, gatewayID, userID string) string {
	id := e.exec(`INSERT INTO mcp_calls (method, exposed_name, gateway_id, gateway_slug, gateway_name, gateway_team_id, principal_kind,
		user_id, outcome) SELECT 'tools/call', 'srv__tool', g.id, g.slug, g.name, $1::uuid, 'api_key', $3::uuid, 'ok'
		FROM gateways g WHERE g.id = $2::uuid RETURNING id::text`, teamID, gatewayID, userID)
	callID, _ := strconv.ParseInt(id, 10, 64)
	key, _ := secrets.ParseKey(testEncryptionKey)
	box, _ := secrets.New(key)
	args, _ := box.Seal([]byte(`{"q":"matrix"}`), capture.AAD(callID, capture.PartArguments))
	e.exec(`INSERT INTO mcp_call_payloads (call_id, occurred_at, gateway_team_id, by_gateway, by_server, arguments_cipher, arguments_bytes)
		VALUES ($1::bigint, now(), $2::uuid, true, false, $3, 14) RETURNING call_id::text`, callID, teamID, args)
	return id
}

// newServiceAccount inserts a service account of a team.
func (e *matrixEnv) newServiceAccount(teamID string) string {
	return e.exec(`INSERT INTO service_accounts (team_id, name) VALUES ($1, $2) RETURNING id::text`, teamID, fmt.Sprintf("sa-%d", e.next()))
}

// newServiceAccountKey inserts a key of a service account.
func (e *matrixEnv) newServiceAccountKey(saID string) string {
	return e.exec(`INSERT INTO service_account_keys (service_account_id, name, prefix, digest, expires_at)
		VALUES ($1, 'k', 'omp_sa_matrix00', encode(sha256($2::bytea), 'hex'), now() + interval '1 day') RETURNING id::text`,
		saID, fmt.Sprintf("sa-key-%d", e.next()))
}

// consentQuery is an authorization request of the matrix's registered
// client for the fixture platform gateway.
func (e *matrixEnv) consentQuery() string {
	slug := e.exec(`SELECT slug FROM gateways WHERE id = $1`, e.platformGateway)
	q := url.Values{"client_id": {e.oauthClient}, "redirect_uri": {"http://127.0.0.1:4545/callback"}, "response_type": {"code"},
		"code_challenge": {strings.Repeat("c", 43)}, "code_challenge_method": {"S256"}, "resource": {e.app.URL + "/mcp/" + slug},
		"state": {"matrix"}}
	return q.Encode()
}

// newGateway inserts a gateway: a team gateway of teamID, or a platform
// gateway for "".
func (e *matrixEnv) newGateway(teamID string) string {
	n := e.next()
	kind := "team"
	if teamID == "" {
		kind = "platform"
	}
	return e.exec(`INSERT INTO gateways (slug, name, owner_kind, team_id) VALUES ($1, $2, $3, NULLIF($4, '')::uuid) RETURNING id::text`,
		fmt.Sprintf("gw-%d", n), fmt.Sprintf("Gateway %d", n), kind, teamID)
}

// newGrant inserts a group grant of a fresh platform gateway.
func (e *matrixEnv) newGrant() (gateway, grant string) {
	gateway = e.newGateway("")
	return gateway, e.exec(`INSERT INTO gateway_grants (gateway_id, subject_kind, group_name) VALUES ($1, 'group', 'g') RETURNING id::text`, gateway)
}

// newServer inserts a refreshed MCP server of the team in a publish state,
// pointing at the fake MCP server.
func (e *matrixEnv) newServer(tf teamFix, state string) string {
	n := e.next()
	return e.exec(`INSERT INTO mcp_servers (team_id, slug, name, url, publish_state, published_at, refreshed_at)
		VALUES ($1, $2, $3, $4, $5::text, CASE WHEN $5::text = 'published' THEN now() END, now()) RETURNING id::text`,
		tf.id, fmt.Sprintf("srv-%d", n), fmt.Sprintf("Server %d", n), e.fakeURL, state)
}

// newChangedCapability inserts a tool whose definition changed since it was
// approved.
// fingerprint is a capability's current fingerprint, as an approver's page would have it.
func (e *matrixEnv) fingerprint(capID string) string {
	return e.exec(`SELECT fingerprint FROM mcp_capabilities WHERE id = $1`, capID)
}

// digest is a server's reviewDigest as an admin's page would have it.
func (e *matrixEnv) digest(serverID string) string {
	e.t.Helper()
	ctx, q, id := context.Background(), dbgen.New(e.app.Pool), uuid.MustParse(serverID)
	sv, err := q.GetMCPServer(ctx, id)
	if err != nil {
		e.t.Fatal(err)
	}
	rows, err := q.ListMCPCapabilityFingerprints(ctx, []uuid.UUID{id})
	if err != nil {
		e.t.Fatal(err)
	}
	refs := make([]registry.CapabilityRef, len(rows))
	for i, r := range rows {
		refs[i] = registry.CapabilityRefOf(sv, r.Kind, r.Name, r.Fingerprint, r.RequiresPresentPerson)
	}
	return registry.ReviewDigest(sv, refs)
}

func (e *matrixEnv) newChangedCapability(serverID string) string {
	return e.exec(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint)
		VALUES ($1, 'tool', 'fixture_tool', '{"name":"fixture_tool"}', repeat('a', 64), repeat('b', 64)) RETURNING id::text`, serverID)
}

func (e *matrixEnv) newMember(tf teamFix, role string) string {
	id := e.newUser(fmt.Sprintf("m-%d@example.com", e.next()), "none")
	e.exec(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) RETURNING role`, tf.id, id, role)
	return id
}

func (e *matrixEnv) newInvite(tf teamFix) string {
	return e.exec(`INSERT INTO team_invites (team_id, email, role, expires_at)
		VALUES ($1, $2, 'member', now() + interval '1 day') RETURNING id::text`, tf.id, fmt.Sprintf("i-%d@example.com", e.next()))
}

func newMatrixEnv(t *testing.T) *matrixEnv { return newMatrixEnvWith(t, nil) }

// newMatrixEnvWith is newMatrixEnv with extra configuration.
func newMatrixEnvWith(t *testing.T, mutate func(*testConfig)) *matrixEnv {
	smtp := matrixSMTP(t)
	e := &matrixEnv{t: t, app: newTestApp(t, func(c *config.Config) {
		smtp(c)
		if mutate != nil {
			mutate(c)
		}
	}), fakeURL: testutil.NewFakeMCP(t).URL()}
	e.a = e.newTeam("alpha", "Alpha Confidential Team")
	e.b = e.newTeam("bravo", "Bravo Team")
	e.exec(`UPDATE teams SET publish_policy_override = 'self_publish' WHERE id = $1 RETURNING slug`, e.b.id)
	e.newMember(e.a, "owner")
	roles := map[caller]string{cMember: "member", cEditor: "editor", cTeamAdmin: "admin", cOwner: "owner"}
	platformRoles := map[caller]string{cPlatformAdmin: "platform_admin", cAuditor: "platform_auditor"}
	for c := cMember; c < numCallers; c++ {
		prole := platformRoles[c]
		if prole == "" {
			prole = "none"
		}
		id := e.newUser(fmt.Sprintf("%s@example.com", c), prole)
		if r, ok := roles[c]; ok {
			e.exec(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3) RETURNING role`, e.b.id, id, r)
		}
		e.userIDs[c] = id
		e.callers[c] = e.sessionFor(id)
	}
	e.callers[cAnon] = anonSession(t, e.app)
	e.platformGateway = e.newGateway("")
	e.exec(`INSERT INTO gateway_grants (gateway_id, subject_kind, team_id) VALUES ($1, 'team', $2) RETURNING id::text`, e.platformGateway, e.b.id)
	for _, c := range []caller{cPlatformAdmin, cAuditor} {
		e.exec(`INSERT INTO gateway_grants (gateway_id, subject_kind, user_id) VALUES ($1, 'user', $2) RETURNING id::text`, e.platformGateway, e.userIDs[c])
	}
	e.oauthClient = e.exec(`INSERT INTO oauth_clients (client_id, client_name, redirect_uris)
		VALUES ('ompcl_' || repeat('m', 43), 'Matrix client', ARRAY['http://127.0.0.1/callback']) RETURNING client_id`)
	e.spareUser = e.newUser("spare@example.com", "none")
	e.spareTeam = e.newTeam("spare", "Spare Team").slug
	e.provider = e.newProvider()
	e.requiringServer = e.newServer(e.a, "private")
	e.exec(`UPDATE mcp_servers SET auth_provider_id = $1, auth_scopes = '{repo}' WHERE id = $2 RETURNING 'x'`, e.provider, e.requiringServer)
	e.allowableServer = e.newServer(e.a, "published")
	e.exec(`UPDATE mcp_servers SET auth_provider_id = $1, auth_scopes = '{repo}' WHERE id = $2 RETURNING 'x'`, e.provider, e.allowableServer)
	capID := e.exec(`INSERT INTO mcp_capabilities (server_id, kind, name, definition, fingerprint, approved_fingerprint)
		VALUES ($1, 'tool', 'allow_tool', '{"name":"allow_tool"}', repeat('a', 64), repeat('a', 64)) RETURNING id::text`, e.allowableServer)
	e.exec(`INSERT INTO gateway_capabilities (gateway_id, capability_id) VALUES ($1, $2) RETURNING gateway_id::text`, e.platformGateway, capID)
	return e
}

// newProvider inserts an enabled auth provider (a public client with PKCE,
// no revocation endpoint, so disconnecting never dials anything).
func (e *matrixEnv) newProvider() string {
	n := e.next()
	return e.exec(`INSERT INTO auth_providers (slug, name, client_id, token_auth_method, pkce, authorization_url, token_url)
		VALUES ($1, $2, 'matrix-client', 'none', true, 'https://auth.example.com/authorize', 'https://auth.example.com/token')
		RETURNING id::text`, fmt.Sprintf("prov-%d", n), fmt.Sprintf("Provider %d", n))
}

// newConnection inserts a person's active connection to a fresh provider.
func (e *matrixEnv) newConnection(userID string) string {
	return e.exec(`INSERT INTO provider_connections (user_id, provider_id, status, access_token_cipher)
		VALUES ($1, $2, 'active', '\x00') RETURNING id::text`, userID, e.newProvider())
}

// newConnectRequest inserts an open consent link of a person and returns its ID.
func (e *matrixEnv) newConnectRequest(userID string) string {
	id := fmt.Sprintf("%043d", e.next())
	sum := sha256.Sum256([]byte(id))
	e.exec(`INSERT INTO provider_connect_requests (id_digest, id_cipher, user_id, provider_id, required_scopes, reason, gateway_id,
		gateway_slug, gateway_name, capability_id, capability_kind, exposed_name, expires_at, server_id, server_origin)
		VALUES ($1, '\x00', $2, $3, '{repo}', 'server_not_allowed', $4, 'gw', 'Gateway', gen_random_uuid(), 'tool', 'srv__tool',
		        now() + interval '10 minutes', $5, $6) RETURNING id_digest`,
		base64.RawURLEncoding.EncodeToString(sum[:]), userID, e.provider, e.platformGateway, e.requiringServer, registry.OriginOf(e.fakeURL))
	return id
}

// newActiveConnection makes sure a person has an active connection to the
// provider with scope repo (a consent link can be confirmed against it).
func (e *matrixEnv) newActiveConnection(userID string) {
	e.exec(`INSERT INTO provider_connections (user_id, provider_id, status, scopes, access_token_cipher)
		VALUES ($1, $2, 'active', '{repo}', '\x00') ON CONFLICT (user_id, provider_id) DO UPDATE SET status = 'active' RETURNING id::text`,
		userID, e.provider)
}

// allowConnection is a person's connection to the provider (active, with
// scope repo), and, when withGrant, an existing grant of the allowable
// server on it.
func (e *matrixEnv) allowConnection(userID string, withGrant bool) string {
	e.newActiveConnection(userID)
	id := e.exec(`SELECT id::text FROM provider_connections WHERE user_id = $1 AND provider_id = $2`, userID, e.provider)
	if withGrant {
		e.exec(`INSERT INTO provider_server_grants (connection_id, server_id, origin, scopes) VALUES ($1, $2, $3, '{repo}')
			ON CONFLICT (connection_id, server_id) DO UPDATE SET origin = EXCLUDED.origin RETURNING server_id::text`,
			id, e.allowableServer, registry.OriginOf(e.fakeURL))
	}
	return id
}

// mctx is what a request builder sees.
type mctx struct {
	e       *matrixEnv
	tf      *teamFix
	who     caller
	allowed bool // expected to succeed: destructive calls get fresh objects
}

func (c *mctx) team(suffix string) string { return "/v1/teams/" + c.tf.slug + suffix }

func (c *mctx) member() string {
	if c.allowed {
		return c.e.newMember(*c.tf, "member")
	}
	return c.tf.member
}

func (c *mctx) invite() string {
	if c.allowed {
		return c.e.newInvite(*c.tf)
	}
	return c.tf.invite
}

// server is a fresh server of the team in state when the call is expected
// to succeed, else the team's fixture server.
func (c *mctx) server(state string) string {
	if c.allowed {
		return c.e.newServer(*c.tf, state)
	}
	return c.tf.server
}

// changedCapability is a published server and its changed capability:
// fresh ones when the call is expected to succeed.
func (c *mctx) changedCapability() (server, capability string) {
	if c.allowed {
		srv := c.e.newServer(*c.tf, "published")
		return srv, c.e.newChangedCapability(srv)
	}
	return c.tf.server, c.tf.capability
}

// gateway is a fresh gateway of the team when the call is expected to
// succeed, else the team's fixture gateway.
func (c *mctx) gateway() string {
	if c.allowed {
		return c.e.newGateway(c.tf.id)
	}
	return c.tf.gateway
}

// platformGateway is a fresh platform gateway when the call is expected
// to succeed, else the fixture one.
func (c *mctx) platformGateway() string {
	if c.allowed {
		return c.e.newGateway("")
	}
	return c.e.platformGateway
}

// grant is a platform gateway's grant: a fresh one when the call is
// expected to succeed.
func (c *mctx) grant() (gateway, grant string) {
	if c.allowed {
		return c.e.newGrant()
	}
	return c.e.platformGateway, c.e.exec(`SELECT id::text FROM gateway_grants WHERE gateway_id = $1 LIMIT 1`, c.e.platformGateway)
}

// apiKey is a fresh key of the caller when the call is expected to
// succeed, else another person's key.
func (c *mctx) apiKey() string {
	owner := c.e.spareUser
	if c.allowed {
		owner = c.e.userIDs[c.who]
	}
	n := c.e.next()
	return c.e.exec(`INSERT INTO api_keys (user_id, name, prefix, digest, expires_at)
		VALUES ($1, 'k', 'omp_matrix00', encode(sha256($2::bytea), 'hex'), now() + interval '1 day') RETURNING id::text`,
		owner, fmt.Sprintf("matrix-%d", n))
}

// oauthGrant is a connected app (a grant on the fixture platform gateway):
// of the caller (mine) or of the spare user when the call is expected to
// succeed, else of another person.
func (c *mctx) oauthGrant(mine bool) string {
	owner := c.e.spareUser
	if c.allowed && mine {
		owner = c.e.userIDs[c.who]
	} else if !c.allowed && !mine {
		owner = c.e.userIDs[cMember]
	}
	return c.e.exec(`INSERT INTO oauth_grants (user_id, gateway_id, client_id, client_kind, client_name, resource)
		VALUES ($1, $2, $3, 'registered', 'Matrix client', 'x') RETURNING id::text`, owner, c.e.platformGateway, fmt.Sprintf("ompcl_matrix_%d", c.e.next()))
}

// serviceAccount is a fresh service account of the team when the call is
// expected to succeed, else the team's fixture one.
func (c *mctx) serviceAccount() string {
	if c.allowed {
		return c.e.newServiceAccount(c.tf.id)
	}
	return c.tf.serviceAccount
}

// serviceAccountKey is a service account and its key: fresh ones when the
// call is expected to succeed.
func (c *mctx) serviceAccountKey() (sa, key string) {
	if c.allowed {
		sa = c.e.newServiceAccount(c.tf.id)
		return sa, c.e.newServiceAccountKey(sa)
	}
	return c.tf.serviceAccount, c.tf.saKey
}

// authProvider is a fresh provider when the call is expected to succeed,
// else the fixture one.
func (c *mctx) authProvider() string {
	if c.allowed {
		return c.e.newProvider()
	}
	return c.e.provider
}

// connection is a connection of the caller (mine) or of the spare user when
// the call is expected to succeed, else of another person.
func (c *mctx) connection(mine bool) string {
	owner := c.e.spareUser
	if c.allowed && mine {
		owner = c.e.userIDs[c.who]
	} else if !c.allowed && !mine {
		owner = c.e.userIDs[cMember]
	}
	return c.e.newConnection(owner)
}

// connectRequest is a consent link of the caller when the call is expected
// to succeed, else of another person.
func (c *mctx) connectRequest() string {
	owner := c.e.spareUser
	if c.allowed {
		owner = c.e.userIDs[c.who]
	}
	return c.e.newConnectRequest(owner)
}

// confirmableRequest is connectRequest for the caller who is connected with
// the request's scopes.
func (c *mctx) confirmableRequest() string {
	if c.allowed {
		c.e.newActiveConnection(c.e.userIDs[c.who])
	}
	return c.connectRequest()
}

// allowTarget is a connection of the caller (the call is expected to
// succeed) or of another person, with the allowable server's grant when
// withGrant.
func (c *mctx) allowTarget(withGrant bool) string {
	owner := c.e.spareUser
	if c.allowed {
		owner = c.e.userIDs[c.who]
	}
	return c.e.allowConnection(owner, withGrant)
}

// serverCapability is a server and one of its capabilities: fresh ones (of
// revision 1) when the call is expected to succeed.
func (c *mctx) serverCapability() (server, capability string) {
	if c.allowed {
		srv := c.e.newServer(*c.tf, "private")
		return srv, c.e.newChangedCapability(srv)
	}
	return c.tf.server, c.tf.capability
}

func (c *mctx) user() string {
	if c.allowed {
		return c.e.newUser(fmt.Sprintf("u-%d@example.com", c.e.next()), "none")
	}
	return c.e.spareUser
}

func (c *mctx) spareTeam() string {
	if c.allowed {
		return c.e.newTeam(fmt.Sprintf("fresh-%d", c.e.next()), "Fresh").slug
	}
	return c.e.spareTeam
}

// call runs one request as who and checks the outcome.
func (e *matrixEnv) call(t *testing.T, op string, p policy, tf *teamFix, who caller, allowed, foreign bool) {
	t.Helper()
	c := &mctx{e: e, tf: tf, who: who, allowed: allowed}
	req := p.build(c)
	s := e.callers[who]
	switch {
	case req.anon:
		s = anonSession(t, e.app)
	case req.ownSession && who != cAnon:
		s = e.sessionFor(e.userIDs[who])
	}
	code, body := s.raw(req.method, req.path, req.body, req.headers)
	where := "own"
	if foreign {
		where = "team A"
	}
	label := fmt.Sprintf("%s as %s on %s (%s %s)", op, who, where, req.method, req.path)
	switch {
	case code >= 500:
		t.Errorf("%s: %d %s", label, code, body)
	case p.anyStatus:
	case allowed && (code < 200 || code > 299):
		t.Errorf("%s: want success, got %d %s", label, code, body)
	case !allowed && code != 401 && code != 403 && code != 404:
		t.Errorf("%s: want 401/403/404, got %d %s", label, code, body)
	}
	if foreign && !allowed && (strings.Contains(string(body), e.a.id) || strings.Contains(string(body), e.a.name)) {
		t.Errorf("%s: denied response leaks team A: %s", label, body)
	}
}

func TestAuthorizationMatrix(t *testing.T) {
	e := newMatrixEnv(t)
	ops := make([]string, 0, len(matrixPolicies))
	for op := range matrixPolicies {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		p := matrixPolicies[op]
		t.Run(op, func(t *testing.T) {
			if p.scope == scopeGlobal {
				for who := caller(0); who < numCallers; who++ {
					e.call(t, op, p, &e.b, who, p.own.has(who), false)
				}
				return
			}
			for _, who := range []caller{cAnon, cMember, cEditor, cTeamAdmin, cOwner} {
				e.call(t, op, p, &e.b, who, p.own.has(who), false)
			}
			for who := caller(0); who < numCallers; who++ {
				e.call(t, op, p, &e.a, who, p.foreign.has(who), true)
			}
		})
	}
}
