-- name: LockServiceConsentSession :one
SELECT id FROM sessions WHERE id = @id AND user_id = @user_id
AND expires_at > @as_of::timestamptz AND last_seen_at > @idle_since::timestamptz FOR UPDATE;

-- name: LockServiceConnectionTeam :exec
SELECT pg_advisory_xact_lock(hashtextextended('service-connections:' || @team_id::text,0));

-- name: CountTeamServiceConnections :one
SELECT count(*)::bigint FROM service_connections WHERE team_id = $1;

-- name: GetServiceConnection :one
SELECT * FROM service_connections WHERE id = $1;

-- name: LockServiceConnection :one
SELECT * FROM service_connections WHERE id = $1 FOR UPDATE;

-- name: ListServiceConnections :many
SELECT * FROM service_connections
WHERE (sqlc.narg(team_id)::uuid IS NULL OR team_id = sqlc.narg(team_id))
AND (sqlc.narg(after_id)::uuid IS NULL OR id > sqlc.narg(after_id))
ORDER BY id LIMIT @page_size;

-- name: InsertServiceConnection :one
INSERT INTO service_connections (team_id, provider_id, name, scopes, connected_by)
VALUES (@team_id, @provider_id, @name, @scopes, @connected_by) RETURNING *;

-- name: AdvanceServiceConnection :one
UPDATE service_connections SET revision = revision + 1, generation = generation + 1, updated_at = now()
WHERE id = $1 RETURNING *;

-- name: StoreServiceConnectionTokens :one
UPDATE service_connections SET status = 'active', scopes = @scopes, account_label = @account_label,
access_token_cipher = @access_token_cipher, refresh_token_cipher = @refresh_token_cipher,
expires_at = @expires_at, connected_by = @connected_by, connected_at = now(), last_error_class = NULL,
revision = revision + 1, generation = generation + 1, updated_at = now()
WHERE id = @id RETURNING *;

-- name: RefreshServiceConnectionTokens :one
UPDATE service_connections SET scopes = @scopes, access_token_cipher = @access_token_cipher,
refresh_token_cipher = @refresh_token_cipher, expires_at = @expires_at, refreshed_at = now(), updated_at = now()
WHERE id = @id RETURNING *;

-- name: RotateServiceConnectionRefresh :exec
UPDATE service_connections SET refresh_token_cipher = @refresh_token_cipher, refreshed_at = now() WHERE id = @id;

-- name: MarkServiceConnectionReconsent :exec
UPDATE service_connections SET status = 'needs_reconsent', access_token_cipher = NULL, refresh_token_cipher = NULL,
last_error_class = @last_error_class, generation = generation + 1, revision = revision + 1, updated_at = now()
WHERE id = @id;

-- name: TouchServiceConnection :exec
UPDATE service_connections SET last_used_at = now() WHERE id = $1 AND (last_used_at IS NULL OR last_used_at < now() - interval '1 minute');

-- name: DeleteServiceConnection :exec
DELETE FROM service_connections WHERE id = $1;

-- name: GetServiceConnectionAssignment :one
SELECT connection_id FROM service_connection_accounts WHERE service_account_id = @service_account_id AND provider_id = @provider_id;

-- name: ListServiceConnectionAccounts :many
SELECT service_account_id FROM service_connection_accounts WHERE connection_id = $1 ORDER BY service_account_id;

-- name: ClearServiceConnectionAccounts :exec
DELETE FROM service_connection_accounts WHERE connection_id = $1;

-- name: InsertServiceConnectionAccount :exec
INSERT INTO service_connection_accounts (connection_id, team_id, provider_id, service_account_id)
VALUES (@connection_id, @team_id, @provider_id, @service_account_id);

-- name: ListServiceConnectionGrants :many
SELECT * FROM service_connection_server_grants WHERE connection_id = $1 ORDER BY server_id;

-- name: GetServiceConnectionGrant :one
SELECT * FROM service_connection_server_grants WHERE connection_id = @connection_id AND server_id = @server_id;

-- name: ClearServiceConnectionGrants :exec
DELETE FROM service_connection_server_grants WHERE connection_id = $1;

-- name: InsertServiceConnectionGrant :exec
INSERT INTO service_connection_server_grants (connection_id, server_id, origin, scopes, granted_by)
VALUES (@connection_id, @server_id, @origin, @scopes, @granted_by);

-- name: ServiceConnectionAdminActive :one
SELECT EXISTS (SELECT 1 FROM users u JOIN team_members tm ON tm.user_id = u.id
JOIN teams t ON t.id = tm.team_id WHERE u.id = @user_id AND u.status = 'active'
AND tm.team_id = @team_id AND tm.role IN ('owner','admin') AND t.status = 'active')::bool;

-- name: InsertServiceConnectionAuthState :exec
INSERT INTO service_connection_auth_states (state_digest, user_id, session_digest, connection_id, revision, generation,
provider_id, provider_revision, client_revision, scopes, code_verifier_cipher, resource, expires_at)
VALUES (@state_digest, @user_id, @session_digest, @connection_id, @revision, @generation,
@provider_id, @provider_revision, @client_revision, @scopes, @code_verifier_cipher, @resource, @expires_at);

-- name: GetServiceConnectionAuthState :one
SELECT * FROM service_connection_auth_states WHERE state_digest = $1;

-- name: TakeServiceConnectionAuthState :one
DELETE FROM service_connection_auth_states WHERE state_digest = $1 RETURNING *;

-- name: DeleteServiceConnectionAuthStates :exec
DELETE FROM service_connection_auth_states WHERE connection_id = $1;

-- name: DeleteExpiredServiceConnectionAuthStates :execrows
DELETE FROM service_connection_auth_states WHERE expires_at < now();
