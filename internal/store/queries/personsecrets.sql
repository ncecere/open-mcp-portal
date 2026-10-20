-- Per-person secrets as an upstream auth mode (migration 00024, decision 72,
-- docs/person-secrets.md). Secret values are sealed in secret_cipher and are
-- never selected into a view: only the hint is shown.

-- name: SetMCPServerSecretConfig :one
-- How a person_secret server's secret travels. Outside that mode every field
-- is cleared (and the setup person is forgotten); the setup person is kept
-- while the mode stays and cleared when keep_setup is false (the secrets were
-- reset).
UPDATE mcp_servers
SET secret_placement = @secret_placement, secret_name = @secret_name, secret_prefix = @secret_prefix,
    secret_label = @secret_label, secret_help = @secret_help,
    secret_setup_user_id = CASE WHEN @keep_setup::boolean THEN secret_setup_user_id END,
    secret_setup_at = CASE WHEN @keep_setup::boolean THEN secret_setup_at END
WHERE id = @id
RETURNING *;

-- name: SetMCPServerSecretSetup :one
-- The person whose own secret reads the server's capabilities (decision 42).
UPDATE mcp_servers SET secret_setup_user_id = @user_id, secret_setup_at = now(), revision = revision + 1, updated_at = now()
WHERE id = @id AND auth_mode = 'person_secret'
RETURNING *;

-- name: GetPersonSecret :one
SELECT * FROM person_secrets WHERE user_id = @user_id AND server_id = @server_id;

-- name: LockPersonSecret :one
SELECT * FROM person_secrets WHERE user_id = @user_id AND server_id = @server_id FOR UPDATE;

-- name: InsertPersonSecret :one
INSERT INTO person_secrets (id, user_id, server_id, origin, secret_cipher, hint, allow_agents)
VALUES (@id, @user_id, @server_id, @origin, @secret_cipher, @hint, @allow_agents)
RETURNING *;

-- name: ReplacePersonSecret :one
-- A new value for the same row (its ID, and so the AAD, stays): active again.
UPDATE person_secrets
SET origin = @origin, secret_cipher = @secret_cipher, hint = @hint, status = 'active', rotated_at = now(), rejected_at = NULL,
    allow_agents = @allow_agents
WHERE id = @id
RETURNING *;

-- name: SetPersonSecretAllowAgents :one
UPDATE person_secrets SET allow_agents = @allow_agents WHERE id = @id RETURNING *;

-- name: RejectPersonSecret :execrows
-- The server refused the secret with 401 or 403. Only the value that was
-- sent (secret_cipher as read for the call): a secret replaced meanwhile is
-- not marked.
UPDATE person_secrets SET status = 'rejected', rejected_at = now()
WHERE id = @id AND status = 'active' AND secret_cipher = @secret_cipher;

-- name: TouchPersonSecret :exec
-- Updated at most once a minute.
UPDATE person_secrets SET last_used_at = now()
WHERE id = @id AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: DeletePersonSecret :one
DELETE FROM person_secrets WHERE user_id = @user_id AND server_id = @server_id RETURNING *;

-- name: DeletePersonSecretsForServer :execrows
DELETE FROM person_secrets WHERE server_id = @server_id;

-- name: CountPersonSecretsForServers :many
SELECT server_id, count(*)::bigint AS people, count(*) FILTER (WHERE status = 'rejected')::bigint AS rejected
FROM person_secrets WHERE server_id = ANY(@server_ids::uuid[]) GROUP BY server_id;

-- name: ListPersonSecretsForUser :many
-- A person's secrets with the server and team they are for, by server name.
SELECT ps.*, s.slug AS server_slug, s.name AS server_name, s.url AS server_url, s.auth_mode AS server_auth_mode,
       s.secret_placement, s.secret_name, s.secret_prefix, s.secret_label, s.secret_help,
       t.slug AS team_slug, t.name AS team_name
FROM person_secrets ps
JOIN mcp_servers s ON s.id = ps.server_id
JOIN teams t ON t.id = s.team_id
WHERE ps.user_id = @user_id
ORDER BY s.name, ps.id;

-- name: InsertSecretRequest :one
INSERT INTO secret_requests (
    id_digest, id_cipher, user_id, server_id, server_origin, reason, gateway_id, gateway_slug, gateway_name,
    capability_id, capability_kind, exposed_name, capability_title, expires_at
) VALUES (
    @id_digest, @id_cipher, @user_id, @server_id, @server_origin, @reason, @gateway_id, @gateway_slug, @gateway_name,
    @capability_id, @capability_kind, @exposed_name, @capability_title, @expires_at
)
RETURNING *;

-- name: FindOpenSecretRequest :one
-- A person's unused request for the same capability, server, origin and
-- reason that stays valid for at least valid_until, to answer with the same
-- link.
SELECT * FROM secret_requests
WHERE user_id = @user_id AND gateway_id = @gateway_id AND capability_id = @capability_id
  AND server_id = @server_id AND server_origin = @server_origin AND reason = @reason
  AND used_at IS NULL AND expires_at > @valid_until
ORDER BY created_at DESC
LIMIT 1;

-- name: GetSecretRequest :one
SELECT * FROM secret_requests WHERE id_digest = $1;

-- name: MarkSecretRequestUsed :execrows
UPDATE secret_requests SET used_at = now() WHERE id_digest = $1 AND used_at IS NULL;

-- name: MarkSecretRequestsUsedFor :execrows
-- Once a person has entered a secret for a server, its open links are done.
UPDATE secret_requests SET used_at = now() WHERE user_id = @user_id AND server_id = @server_id AND used_at IS NULL;

-- name: TrimOpenSecretRequests :execrows
-- Keeps a person's newest keep open requests; older open ones are dropped.
DELETE FROM secret_requests
WHERE id_digest IN (
    SELECT r.id_digest FROM secret_requests r
    WHERE r.user_id = @user_id AND r.used_at IS NULL AND r.expires_at > now()
    ORDER BY r.created_at DESC, r.id_digest
    OFFSET @keep::int
);

-- name: DeleteStaleSecretRequests :execrows
DELETE FROM secret_requests WHERE expires_at < @before;
