-- OAuth sign-in for MCP clients (internal/oauth).

-- name: GetOAuthSettings :one
SELECT * FROM oauth_settings WHERE id = 1;

-- name: GetOAuthUserForApproval :one
-- Serializes grant creation/replacement without blocking the user FK's KEY
-- SHARE lock in token-issue/revocation audits (which already hold the grant).
SELECT * FROM users WHERE id = $1 FOR NO KEY UPDATE;

-- name: LockOAuthSettings :one
SELECT * FROM oauth_settings WHERE id = 1 FOR UPDATE;

-- name: UpdateOAuthClientSettings :one
UPDATE oauth_settings
SET trusted_clients = @trusted_clients, open_registration = @open_registration, revision = revision + 1,
    updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: GetOAuthClient :one
-- A registered client used since unused_since, and one that has received
-- tokens or was registered after unauthorized_since (a registration that
-- never completed an authorization lives for 24 hours).
SELECT * FROM oauth_clients
WHERE client_id = @client_id AND last_used_at > @unused_since
  AND (authorized_at IS NOT NULL OR created_at > @unauthorized_since);

-- name: InsertOAuthClient :one
INSERT INTO oauth_clients (client_id, client_name, redirect_uris, client_uri, logo_uri, registered_from)
VALUES (@client_id, @client_name, @redirect_uris, @client_uri, @logo_uri, sqlc.narg(registered_from))
RETURNING *;

-- name: MarkOAuthClientAuthorized :exec
-- The first time a registered client receives tokens (a no-op afterwards).
UPDATE oauth_clients SET authorized_at = now() WHERE client_id = $1 AND authorized_at IS NULL;

-- name: TouchOAuthClient :exec
UPDATE oauth_clients SET last_used_at = now()
WHERE client_id = $1 AND last_used_at < now() - interval '1 minute';

-- name: LockOAuthClients :exec
-- Serialises registrations across replicas (transaction lock), so the cap on
-- live registered clients holds under concurrent requests.
SELECT pg_advisory_xact_lock(hashtextextended('omp.oauth-clients', 0));

-- name: CountLiveOAuthClients :one
-- Registered clients ResolveClient accepts: used since unused_since, and
-- authorized or registered after unauthorized_since.
SELECT count(*) FROM oauth_clients
WHERE last_used_at > @unused_since AND (authorized_at IS NOT NULL OR created_at > @unauthorized_since);

-- name: CountPendingOAuthClientsFrom :one
-- Registrations from one address that have not received tokens yet and are
-- still live: the only kind a caller can create without a person.
SELECT count(*) FROM oauth_clients
WHERE registered_from = @registered_from AND authorized_at IS NULL AND created_at > @unauthorized_since;

-- name: DeleteUnusedOAuthClients :exec
-- Registrations unused since unused_since, and the ones that never received
-- tokens within the shorter life.
DELETE FROM oauth_clients
WHERE last_used_at <= @unused_since OR (authorized_at IS NULL AND created_at <= @unauthorized_since);

-- name: GetActiveOAuthGrant :one
SELECT * FROM oauth_grants
WHERE user_id = @user_id AND client_id = @client_id AND gateway_id = @gateway_id AND revoked_at IS NULL;

-- name: InsertOAuthGrant :one
INSERT INTO oauth_grants (user_id, gateway_id, client_id, client_kind, client_name, client_uri, logo_uri, resource, authorized_at, tool_scope)
VALUES (@user_id, @gateway_id, @client_id, @client_kind, @client_name, @client_uri, @logo_uri, @resource, now(), sqlc.narg(tool_scope))
RETURNING *;

-- name: RenewOAuthGrant :exec
-- The person signed the app in again: its refresh tokens get a new absolute lifetime.
UPDATE oauth_grants SET authorized_at = now() WHERE id = $1;

-- name: LockOAuthGrant :one
SELECT * FROM oauth_grants WHERE id = $1 FOR UPDATE;

-- name: RevokeOAuthGrant :execrows
UPDATE oauth_grants SET revoked_at = now(), revoked_reason = @reason
WHERE id = @id AND revoked_at IS NULL;

-- name: DeleteOAuthGrantTokens :exec
DELETE FROM oauth_tokens WHERE grant_id = $1;

-- name: DeleteOAuthGrantCodes :exec
DELETE FROM oauth_codes WHERE grant_id = $1;

-- name: TouchOAuthGrant :exec
-- Records a use, at most once a minute.
UPDATE oauth_grants SET last_used_at = now()
WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: ListUserOAuthGrants :many
-- A person's active grants, newest first, with each gateway.
SELECT sqlc.embed(gr), g.slug AS gateway_slug, g.name AS gateway_name
FROM oauth_grants gr
JOIN gateways g ON g.id = gr.gateway_id
WHERE gr.user_id = $1 AND gr.revoked_at IS NULL
ORDER BY gr.created_at DESC, gr.id DESC;

-- name: DeleteExpiredOAuthCodes :exec
DELETE FROM oauth_codes WHERE expires_at <= now();

-- name: InsertOAuthCode :exec
INSERT INTO oauth_codes (code_hash, grant_id, client_id, redirect_uri, code_challenge, resource, expires_at)
VALUES (@code_hash, @grant_id, @client_id, @redirect_uri, @code_challenge, @resource, @expires_at);

-- name: TakeOAuthCode :one
-- Consumes a code: it is deleted whether or not the exchange succeeds.
DELETE FROM oauth_codes WHERE code_hash = $1 RETURNING *;

-- name: DeleteExpiredOAuthTokens :exec
DELETE FROM oauth_tokens WHERE expires_at <= now();

-- name: InsertOAuthToken :exec
INSERT INTO oauth_tokens (grant_id, kind, token_hash, resource, expires_at, pepper_id)
VALUES (@grant_id, @kind, @token_hash, @resource, @expires_at, sqlc.narg(pepper_id));

-- name: GetOAuthToken :one
-- A token of a kind by its digest, with its grant, person and gateway.
SELECT sqlc.embed(t), sqlc.embed(gr), sqlc.embed(u), g.slug AS gateway_slug
FROM oauth_tokens t
JOIN oauth_grants gr ON gr.id = t.grant_id
JOIN users u ON u.id = gr.user_id
JOIN gateways g ON g.id = gr.gateway_id
WHERE t.token_hash = @token_hash AND t.kind = @kind;

-- name: LockOAuthToken :one
SELECT * FROM oauth_tokens WHERE id = $1 FOR UPDATE;

-- name: RotateOAuthToken :execrows
UPDATE oauth_tokens SET rotated_at = now() WHERE id = $1 AND rotated_at IS NULL;

-- name: DeleteOAuthToken :exec
DELETE FROM oauth_tokens WHERE id = $1;
