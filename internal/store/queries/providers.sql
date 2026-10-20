-- Delegated credentials (internal/providers): auth providers, people's
-- connections to them, consent links and authorization states.

-- name: InsertAuthProvider :one
INSERT INTO auth_providers (
    id, slug, name, preset, enabled, client_id, client_secret_cipher, client_secret_hint, token_auth_method, pkce,
    authorization_url, token_url, revocation_url, userinfo_url, default_scopes, scope_param, scope_separator,
    token_response_format, extra_authorize_params, logo_url, created_by, updated_by, access_mode, narrow_on_refresh
) VALUES (
    @id, @slug, @name, @preset, @enabled, @client_id, @client_secret_cipher, @client_secret_hint, @token_auth_method, @pkce,
    @authorization_url, @token_url, @revocation_url, @userinfo_url, @default_scopes, @scope_param, @scope_separator,
    @token_response_format, @extra_authorize_params, @logo_url, @created_by, @created_by, @access_mode, @narrow_on_refresh
)
RETURNING *;

-- name: GetAuthProvider :one
SELECT * FROM auth_providers WHERE id = $1;

-- name: LockAuthProvider :one
SELECT * FROM auth_providers WHERE id = $1 FOR UPDATE;

-- name: CountAuthProviders :one
-- Platform providers (the limit of 100 doesn't count server-bound ones).
SELECT count(*)::bigint FROM auth_providers WHERE kind = 'oauth2';

-- name: ListAllAuthProviders :many
-- Every provider, platform and server-bound (requirements and the runtime).
SELECT * FROM auth_providers ORDER BY name, id;

-- name: ListPlatformAuthProviders :many
SELECT * FROM auth_providers WHERE kind = 'oauth2' ORDER BY name, id;

-- name: UpdateAuthProvider :one
UPDATE auth_providers
SET name = @name, preset = @preset, enabled = @enabled, client_id = @client_id, client_secret_cipher = @client_secret_cipher,
    client_secret_hint = @client_secret_hint, token_auth_method = @token_auth_method, pkce = @pkce,
    authorization_url = @authorization_url, token_url = @token_url, revocation_url = @revocation_url,
    userinfo_url = @userinfo_url, default_scopes = @default_scopes, scope_param = @scope_param,
    scope_separator = @scope_separator, token_response_format = @token_response_format,
    extra_authorize_params = @extra_authorize_params, logo_url = @logo_url, narrow_on_refresh = @narrow_on_refresh,
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetAuthProviderAccessMode :one
-- The access list changed (decision 69): the provider's revision moves, so
-- an admin editing the provider elsewhere sees a conflict.
UPDATE auth_providers
SET access_mode = @access_mode, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ListAuthProviderTeams :many
SELECT t.id AS team_id, t.slug AS team_slug, t.name AS team_name, pt.added_at
FROM auth_provider_teams pt JOIN teams t ON t.id = pt.team_id
WHERE pt.provider_id = @provider_id
ORDER BY t.name, t.id;

-- name: ListAuthProviderServers :many
SELECT s.id AS server_id, s.slug AS server_slug, s.name AS server_name, t.slug AS team_slug, t.name AS team_name, ps.added_at
FROM auth_provider_servers ps
JOIN mcp_servers s ON s.id = ps.server_id
JOIN teams t ON t.id = s.team_id
WHERE ps.provider_id = @provider_id
ORDER BY s.name, s.id;

-- name: ClearAuthProviderTeams :exec
DELETE FROM auth_provider_teams WHERE provider_id = $1;

-- name: ClearAuthProviderServers :exec
DELETE FROM auth_provider_servers WHERE provider_id = $1;

-- name: AddAuthProviderTeams :exec
INSERT INTO auth_provider_teams (provider_id, team_id, added_by)
SELECT @provider_id, t, @added_by FROM unnest(@team_ids::uuid[]) AS t;

-- name: AddAuthProviderServers :exec
INSERT INTO auth_provider_servers (provider_id, server_id, added_by)
SELECT @provider_id, s, @added_by FROM unnest(@server_ids::uuid[]) AS s;

-- name: CountExistingTeams :one
SELECT count(*)::bigint FROM teams WHERE id = ANY(@ids::uuid[]);

-- name: CountExistingServers :one
SELECT count(*)::bigint FROM mcp_servers WHERE id = ANY(@ids::uuid[]);

-- name: ProviderAllowsTeam :one
-- Whether a team's servers may require the provider: it is open, or lists the team.
SELECT (p.access_mode = 'open'
        OR EXISTS (SELECT 1 FROM auth_provider_teams pt WHERE pt.provider_id = p.id AND pt.team_id = @team_id))::boolean AS allowed
FROM auth_providers p WHERE p.id = @provider_id;

-- name: ProviderAllowsServer :one
-- Whether a server may require the provider: it is open, or lists the
-- server's team or the server itself.
SELECT (p.access_mode = 'open'
        OR EXISTS (SELECT 1 FROM auth_provider_servers ps WHERE ps.provider_id = p.id AND ps.server_id = @server_id)
        OR EXISTS (SELECT 1 FROM auth_provider_teams pt JOIN mcp_servers s ON s.team_id = pt.team_id
                   WHERE pt.provider_id = p.id AND s.id = @server_id))::boolean AS allowed
FROM auth_providers p WHERE p.id = @provider_id;

-- name: ListProviderAccessEntries :many
-- Every restricted provider's listed teams and servers (the "connected" mark
-- of My gateways and the allowable-servers list read them once): one
-- 'restricted' row per restricted provider, then its 'team' and 'server' rows.
SELECT p.id AS provider_id, 'restricted'::text AS kind, p.id AS target_id
FROM auth_providers p WHERE p.access_mode = 'restricted'
UNION ALL
SELECT p.id, 'team'::text, pt.team_id
FROM auth_providers p JOIN auth_provider_teams pt ON pt.provider_id = p.id
WHERE p.access_mode = 'restricted'
UNION ALL
SELECT p.id, 'server'::text, ps.server_id
FROM auth_providers p JOIN auth_provider_servers ps ON ps.provider_id = p.id
WHERE p.access_mode = 'restricted';

-- name: ServersOutsideProviderAccess :many
-- Servers that require a restricted provider although neither their team nor
-- they are listed: their calls are refused (-32010 provider_not_allowed).
SELECT s.id, s.slug, s.name, t.slug AS team_slug, t.name AS team_name
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id
JOIN auth_providers p ON p.id = s.auth_provider_id
WHERE p.id = @provider_id AND p.access_mode = 'restricted'
  AND NOT EXISTS (SELECT 1 FROM auth_provider_servers ps WHERE ps.provider_id = p.id AND ps.server_id = s.id)
  AND NOT EXISTS (SELECT 1 FROM auth_provider_teams pt WHERE pt.provider_id = p.id AND pt.team_id = s.team_id)
ORDER BY s.name, s.id
LIMIT @page_size;

-- name: RotateProviderConnectionRefreshToken :exec
-- A narrowed refresh (decision 69) may rotate the refresh token; the stored
-- access token is left as it is.
UPDATE provider_connections SET refresh_token_cipher = @refresh_token_cipher, refreshed_at = now(), last_error_class = NULL
WHERE id = @id AND status = 'active';

-- name: ListConnectionsDueForRefresh :many
-- Active, refreshable connections to platform providers whose access token
-- expires before @expires_before and that were used since @used_since (the
-- background refresh).
SELECT pc.* FROM provider_connections pc
JOIN auth_providers p ON p.id = pc.provider_id
WHERE pc.status = 'active' AND pc.refresh_token_cipher IS NOT NULL AND pc.expires_at IS NOT NULL
  AND pc.expires_at < @expires_before::timestamptz AND pc.last_used_at IS NOT NULL AND pc.last_used_at > @used_since::timestamptz
  AND p.enabled AND p.kind = 'oauth2'
ORDER BY pc.expires_at, pc.id
LIMIT @page_size;

-- name: DeleteAuthProvider :exec
DELETE FROM auth_providers WHERE id = $1;

-- name: AuthProviderStats :many
-- Per provider: the MCP servers that require it, and the connections to it.
SELECT p.id AS provider_id,
       ((SELECT count(*) FROM mcp_servers s WHERE s.auth_provider_id = p.id)
        + (SELECT count(*) FROM auth_providers b WHERE b.link_provider_id = p.id))::bigint AS server_count,
       (SELECT count(*) FROM provider_connections pc WHERE pc.provider_id = p.id)::bigint AS connection_count,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = p.created_by), '')::text
           AS created_by_name
FROM auth_providers p
WHERE p.id = ANY(@ids::uuid[]);

-- name: ServersRequiringProvider :many
-- MCP servers that require a provider (as their requirement; a capability
-- override always names its server's provider) or, in oauth mode, link it
-- (registration platform_provider), at most limit, by name.
SELECT s.id, s.slug, s.name, t.slug AS team_slug
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id
WHERE s.auth_provider_id = @provider_id
   OR EXISTS (SELECT 1 FROM auth_providers b WHERE b.server_id = s.id AND b.link_provider_id = @provider_id)
ORDER BY s.name, s.id
LIMIT @page_size;

-- name: InsertServerProvider :one
-- The OAuth client of an MCP server in oauth mode (kind mcp_server).
INSERT INTO auth_providers (
    id, slug, name, kind, enabled, client_id, client_secret_cipher, client_secret_hint, token_auth_method, pkce,
    authorization_url, token_url, revocation_url, default_scopes, server_id, link_provider_id, registration, resource,
    resource_metadata_url, authorization_server, issuer, scopes_supported, send_resource, iss_param_supported,
    client_secret_expires_at, discovered_at, created_by, updated_by
) VALUES (
    @id, @slug, @name, 'mcp_server', true, @client_id, @client_secret_cipher, @client_secret_hint, @token_auth_method, true,
    @authorization_url, @token_url, @revocation_url, @default_scopes, @server_id, @link_provider_id, @registration, @resource,
    @resource_metadata_url, @authorization_server, @issuer, @scopes_supported, @send_resource, @iss_param_supported,
    @client_secret_expires_at, now(), @created_by, @created_by
)
RETURNING *;

-- name: UpdateServerProvider :one
UPDATE auth_providers
SET name = @name, client_id = @client_id, client_secret_cipher = @client_secret_cipher, client_secret_hint = @client_secret_hint,
    token_auth_method = @token_auth_method, authorization_url = @authorization_url, token_url = @token_url,
    revocation_url = @revocation_url, default_scopes = @default_scopes, link_provider_id = @link_provider_id,
    registration = @registration, resource = @resource, resource_metadata_url = @resource_metadata_url,
    authorization_server = @authorization_server, issuer = @issuer, scopes_supported = @scopes_supported,
    send_resource = @send_resource, iss_param_supported = @iss_param_supported,
    client_secret_expires_at = @client_secret_expires_at, discovered_at = now(),
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id AND kind = 'mcp_server'
RETURNING *;

-- name: RenameServerProvider :exec
-- A server-bound provider is named after its server.
UPDATE auth_providers SET name = @name, updated_at = now() WHERE server_id = @server_id;

-- name: GetServerProvider :one
SELECT * FROM auth_providers WHERE server_id = $1;

-- name: ServerProviders :many
-- The server-bound providers of servers, with their connection counts.
SELECT sqlc.embed(p), (SELECT count(*) FROM provider_connections pc WHERE pc.provider_id = p.id)::bigint AS connection_count
FROM auth_providers p
WHERE p.server_id = ANY(@server_ids::uuid[]);

-- name: LinkedServerProviders :many
-- Server-bound providers that use a platform provider's client.
SELECT * FROM auth_providers WHERE link_provider_id = @link_provider_id ORDER BY id;

-- name: DeleteServerProvider :exec
DELETE FROM auth_providers WHERE server_id = @server_id AND kind = 'mcp_server';

-- name: GetProviderConnection :one
SELECT * FROM provider_connections WHERE user_id = @user_id AND provider_id = @provider_id;

-- name: LockProviderConnection :one
SELECT * FROM provider_connections WHERE user_id = @user_id AND provider_id = @provider_id FOR UPDATE;

-- name: GetProviderConnectionByID :one
SELECT * FROM provider_connections WHERE id = $1;

-- name: LockProviderConnectionByID :one
SELECT * FROM provider_connections WHERE id = $1 FOR UPDATE;

-- name: InsertProviderConnection :one
INSERT INTO provider_connections (id, user_id, provider_id, status, scopes, account_label, access_token_cipher,
                                  refresh_token_cipher, expires_at)
VALUES (@id, @user_id, @provider_id, 'active', @scopes, @account_label, @access_token_cipher, @refresh_token_cipher, @expires_at)
RETURNING *;

-- name: ReconnectProviderConnection :one
-- New tokens after consent: active again, with the granted scopes.
UPDATE provider_connections
SET status = 'active', scopes = @scopes, account_label = COALESCE(sqlc.narg(account_label)::text, account_label),
    access_token_cipher = @access_token_cipher, refresh_token_cipher = @refresh_token_cipher, expires_at = @expires_at,
    connected_at = now(), refreshed_at = NULL, last_error_class = NULL
WHERE id = @id
RETURNING *;

-- name: SetProviderConnectionRefreshed :one
UPDATE provider_connections
SET access_token_cipher = @access_token_cipher, refresh_token_cipher = @refresh_token_cipher, expires_at = @expires_at,
    scopes = @scopes, refreshed_at = now(), last_error_class = NULL
WHERE id = @id
RETURNING *;

-- name: MarkProviderConnectionReconsent :exec
-- Erases the tokens; the row, scopes and label stay so the person sees what
-- to reconnect.
UPDATE provider_connections
SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL, expires_at = NULL,
    last_error_class = @error_class
WHERE id = @id;

-- name: MarkProviderConnectionsReconsent :execrows
-- Every connection to a provider whose client ID changed: their tokens
-- belong to the old app.
UPDATE provider_connections
SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL, expires_at = NULL,
    last_error_class = 'client_changed'
WHERE provider_id = @provider_id AND status = 'active';

-- name: ResetProviderConnections :execrows
-- Erases the tokens of every active connection to a provider (an oauth
-- server's URL, authorization server or client changed), with the reason.
UPDATE provider_connections
SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL, expires_at = NULL,
    last_error_class = @error_class
WHERE provider_id = @provider_id AND status = 'active';

-- name: TouchProviderConnection :exec
UPDATE provider_connections SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: DeleteProviderConnection :exec
DELETE FROM provider_connections WHERE id = $1;

-- name: ListProviderConnectionsForUser :many
-- A person's connections with their providers (and, for a server-bound
-- provider, its server and team), by provider name.
SELECT sqlc.embed(pc), p.slug AS provider_slug, p.name AS provider_name, p.preset AS provider_preset,
       p.logo_url AS provider_logo_url, p.kind AS provider_kind, p.narrow_on_refresh AS provider_narrows, s.id AS server_id, s.slug AS server_slug,
       s.name AS server_name, t.slug AS server_team_slug
FROM provider_connections pc
JOIN auth_providers p ON p.id = pc.provider_id
LEFT JOIN mcp_servers s ON s.id = p.server_id
LEFT JOIN teams t ON t.id = s.team_id
WHERE pc.user_id = @user_id
ORDER BY p.name, p.id;

-- name: GetServerRef :one
SELECT s.id, s.slug, s.name, t.slug AS team_slug, t.name AS team_name FROM mcp_servers s JOIN teams t ON t.id = s.team_id WHERE s.id = $1;

-- name: ListProviderConnectionsForProvider :many
SELECT * FROM provider_connections WHERE provider_id = @provider_id ORDER BY id;

-- name: InsertConnectRequest :one
INSERT INTO provider_connect_requests (
    id_digest, id_cipher, user_id, provider_id, required_scopes, reason, gateway_id, gateway_slug, gateway_name,
    capability_id, capability_kind, exposed_name, capability_title, expires_at, server_id, server_origin
) VALUES (
    @id_digest, @id_cipher, @user_id, @provider_id, @required_scopes, @reason, @gateway_id, @gateway_slug, @gateway_name,
    @capability_id, @capability_kind, @exposed_name, @capability_title, @expires_at, @server_id, @server_origin
)
RETURNING *;

-- name: FindOpenConnectRequest :one
-- A person's unused request for the same capability, provider, scopes, server
-- and server origin that stays valid for at least valid_until, to answer with
-- the same link.
SELECT * FROM provider_connect_requests
WHERE user_id = @user_id AND provider_id = @provider_id AND gateway_id = @gateway_id AND capability_id = @capability_id
  AND server_id = @server_id AND server_origin = @server_origin
  AND required_scopes = @required_scopes::text[] AND used_at IS NULL AND expires_at > @valid_until
ORDER BY created_at DESC
LIMIT 1;

-- name: GetConnectRequest :one
SELECT * FROM provider_connect_requests WHERE id_digest = $1;

-- name: MarkConnectRequestUsed :execrows
UPDATE provider_connect_requests SET used_at = now() WHERE id_digest = $1 AND used_at IS NULL;

-- name: TrimOpenConnectRequests :execrows
-- Keeps a person's newest keep open requests; older open ones are dropped.
DELETE FROM provider_connect_requests
WHERE id_digest IN (
    SELECT r.id_digest FROM provider_connect_requests r
    WHERE r.user_id = @user_id AND r.used_at IS NULL AND r.expires_at > now()
    ORDER BY r.created_at DESC, r.id_digest
    OFFSET @keep::int
);

-- name: DeleteStaleConnectRequests :execrows
-- Requests that expired before before (they answer 410 until then).
DELETE FROM provider_connect_requests WHERE expires_at < @before;

-- name: InsertProviderAuthState :exec
INSERT INTO provider_auth_states (state_digest, user_id, session_digest, provider_id, scopes, required_scopes,
                                  code_verifier_cipher, request_digest, return_to, expires_at, setup_server_id, resource)
VALUES (@state_digest, @user_id, @session_digest, @provider_id, @scopes, @required_scopes, @code_verifier_cipher,
        @request_digest, @return_to, @expires_at, @setup_server_id, @resource);

-- name: TakeProviderAuthState :one
-- A state is single use: it is deleted before anything else is checked.
DELETE FROM provider_auth_states WHERE state_digest = $1 RETURNING *;

-- name: DeleteExpiredProviderAuthStates :execrows
DELETE FROM provider_auth_states WHERE expires_at < now();

-- name: GetProviderServerGrant :one
SELECT * FROM provider_server_grants WHERE connection_id = @connection_id AND server_id = @server_id;

-- name: LockProviderServerGrant :one
SELECT * FROM provider_server_grants WHERE connection_id = @connection_id AND server_id = @server_id FOR UPDATE;

-- name: UpsertProviderServerGrant :one
-- The person allows a server to use a connection, at an origin, for scopes.
INSERT INTO provider_server_grants (connection_id, server_id, origin, scopes)
VALUES (@connection_id, @server_id, @origin, @scopes)
ON CONFLICT (connection_id, server_id)
DO UPDATE SET origin = EXCLUDED.origin, scopes = EXCLUDED.scopes, consented_at = now()
RETURNING *;

-- name: DeleteProviderServerGrantsForServer :execrows
-- A server's URL origin or provider changed, or it was deleted: nobody's
-- consent counts for what it is now.
DELETE FROM provider_server_grants WHERE server_id = @server_id;

-- name: DeleteProviderServerGrant :execrows
-- The person takes back one server's allowance of one connection.
DELETE FROM provider_server_grants WHERE connection_id = @connection_id AND server_id = @server_id;

-- name: ListProviderServerGrantsForUser :many
-- The servers a person's connections are allowed for, by server name.
SELECT g.connection_id, g.server_id, g.origin, g.scopes, g.consented_at, s.slug AS server_slug, s.name AS server_name,
       t.slug AS team_slug, t.name AS team_name
FROM provider_server_grants g
JOIN provider_connections pc ON pc.id = g.connection_id
JOIN mcp_servers s ON s.id = g.server_id
JOIN teams t ON t.id = s.team_id
WHERE pc.user_id = @user_id
ORDER BY s.name, s.id;
