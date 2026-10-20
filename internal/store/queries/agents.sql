-- Trusted agent platforms, relay service accounts and the replay table of
-- their identity tokens (internal/agentidentity; docs/agent-platforms.md).

-- name: ListAgentPlatforms :many
-- Every platform by name, with how many service accounts relay for it.
SELECT sqlc.embed(p),
       (SELECT count(*) FROM service_accounts sa WHERE sa.relay_platform_id = p.id)::bigint AS relay_count
FROM agent_platforms p
ORDER BY p.name, p.id;

-- name: GetAgentPlatform :one
SELECT * FROM agent_platforms WHERE id = $1;

-- name: LockAgentPlatform :one
SELECT * FROM agent_platforms WHERE id = $1 FOR UPDATE;

-- name: GetAgentPlatformByIssuer :one
SELECT * FROM agent_platforms WHERE issuer = $1;

-- name: CountAgentPlatforms :one
SELECT count(*)::bigint FROM agent_platforms;

-- name: InsertAgentPlatform :one
INSERT INTO agent_platforms (name, issuer, jwks_url, audience, enabled, created_by, updated_by)
VALUES (@name, @issuer, @jwks_url, @audience, @enabled, @created_by, @created_by)
RETURNING *;

-- name: UpdateAgentPlatform :one
-- A new issuer or JWKS URL forgets the last fetch result (it described
-- another endpoint).
UPDATE agent_platforms
SET name = @name, issuer = @issuer, jwks_url = @jwks_url, audience = @audience, enabled = @enabled,
    jwks_checked_at = CASE WHEN jwks_url = @jwks_url AND issuer = @issuer THEN jwks_checked_at END,
    jwks_ok         = CASE WHEN jwks_url = @jwks_url AND issuer = @issuer THEN jwks_ok END,
    jwks_error      = CASE WHEN jwks_url = @jwks_url AND issuer = @issuer THEN jwks_error END,
    jwks_key_ids    = CASE WHEN jwks_url = @jwks_url AND issuer = @issuer THEN jwks_key_ids ELSE '{}' END,
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteAgentPlatform :exec
DELETE FROM agent_platforms WHERE id = $1;

-- name: SetAgentPlatformJWKSResult :exec
-- The result of the latest JWKS fetch (by the platform's current URL).
UPDATE agent_platforms
SET jwks_checked_at = now(), jwks_ok = @ok, jwks_error = sqlc.narg(error)::text, jwks_key_ids = @key_ids::text[]
WHERE id = @id AND jwks_url = @jwks_url;

-- name: InsertAgentTokenJTI :execrows
-- Records a token's jti until it can no longer be valid. Zero rows: the jti
-- was seen already (a replay).
INSERT INTO agent_token_jtis (platform_id, jti, expires_at)
VALUES (@platform_id, @jti, @expires_at)
ON CONFLICT (platform_id, jti) DO NOTHING;

-- name: DeleteExpiredAgentTokenJTIs :execrows
DELETE FROM agent_token_jtis WHERE expires_at < now() - interval '1 minute';

-- name: GetUserByIdentity :one
-- A person by the issuer and subject of their sign-in.
SELECT * FROM users WHERE oidc_issuer = @oidc_issuer AND oidc_subject = @oidc_subject;

-- name: GetServiceAccountRelayView :one
-- A service account with its team, for marking it as a relay.
SELECT sqlc.embed(sa), t.slug AS team_slug, t.name AS team_name, t.status AS team_status
FROM service_accounts sa
JOIN teams t ON t.id = sa.team_id
WHERE sa.id = $1;

-- name: LockServiceAccountByID :one
SELECT * FROM service_accounts WHERE id = $1 FOR UPDATE;

-- name: SetServiceAccountRelay :one
-- Marks (or, with a NULL platform, unmarks) a service account as a relay.
-- The revision moves so a team admin's open edit is stale.
UPDATE service_accounts
SET relay_platform_id = sqlc.narg(platform_id)::uuid,
    relay_marked_by = CASE WHEN sqlc.narg(platform_id)::uuid IS NULL THEN NULL ELSE sqlc.narg(marked_by)::uuid END,
    relay_marked_at = CASE WHEN sqlc.narg(platform_id)::uuid IS NULL THEN NULL ELSE now() END,
    revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ListRelayServiceAccounts :many
-- The service accounts that relay for a platform, with their teams.
SELECT sqlc.embed(sa), t.slug AS team_slug, t.name AS team_name
FROM service_accounts sa
JOIN teams t ON t.id = sa.team_id
WHERE sa.relay_platform_id = $1
ORDER BY t.slug, sa.name, sa.id;

-- name: SetMCPCapabilityPresentPerson :one
-- A capability's present-person override (NULL: follow the server).
UPDATE mcp_capabilities SET requires_present_person = sqlc.narg(requires_present_person)::boolean
WHERE id = @id AND server_id = @server_id
RETURNING *;
