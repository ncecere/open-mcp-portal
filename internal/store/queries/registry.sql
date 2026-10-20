-- The MCP server registry: servers, capabilities, health checks and the
-- publishing policy (internal/registry).

-- name: GetPlatformSettings :one
SELECT * FROM platform_settings WHERE id = 1;

-- name: LockPlatformSettings :one
SELECT * FROM platform_settings WHERE id = 1 FOR UPDATE;

-- name: UpdatePublishDefaultPolicy :one
UPDATE platform_settings
SET publish_default_policy = @policy, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: GetNetworkSettings :one
SELECT * FROM network_settings WHERE id = 1;

-- name: LockNetworkSettings :one
SELECT * FROM network_settings WHERE id = 1 FOR UPDATE;

-- name: UpdateNetworkEntries :one
UPDATE network_settings
SET entries = @entries, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: SetTeamPublishOverride :one
UPDATE teams
SET publish_policy_override = sqlc.narg(override)::text, revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: InsertMCPServer :one
INSERT INTO mcp_servers (
    id, team_id, slug, name, description, url, auth_header_name, auth_value_cipher, auth_value_hint,
    timeout_seconds, enabled, auth_provider_id, auth_scopes, auth_mode, send_identity, created_by, updated_by
) VALUES (
    @id, @team_id, @slug, @name, @description, @url, @auth_header_name, @auth_value_cipher, @auth_value_hint,
    @timeout_seconds, @enabled, @auth_provider_id, @auth_scopes, @auth_mode, @send_identity, @created_by, @created_by
)
RETURNING *;

-- name: GetMCPServer :one
SELECT * FROM mcp_servers WHERE id = $1;

-- name: LockMCPServer :one
SELECT * FROM mcp_servers WHERE id = $1 FOR UPDATE;

-- name: UpdateMCPServer :one
UPDATE mcp_servers
SET name = @name, description = @description, url = @url, auth_header_name = @auth_header_name,
    auth_value_cipher = @auth_value_cipher, auth_value_hint = @auth_value_hint,
    timeout_seconds = @timeout_seconds, enabled = @enabled, auth_provider_id = @auth_provider_id, auth_scopes = @auth_scopes,
    auth_mode = @auth_mode, send_identity = @send_identity, requires_present_person = @requires_present_person,
    oauth_setup_user_id = CASE WHEN @auth_mode::text = 'oauth' THEN oauth_setup_user_id END,
    oauth_setup_at = CASE WHEN @auth_mode::text = 'oauth' THEN oauth_setup_at END,
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: SetMCPServerOAuthSetup :one
-- The person whose sign-in reads the server's capabilities (decision 42).
UPDATE mcp_servers SET oauth_setup_user_id = @user_id, oauth_setup_at = now(), revision = revision + 1, updated_at = now()
WHERE id = @id AND auth_mode = 'oauth'
RETURNING *;

-- name: BumpMCPServerRevision :one
UPDATE mcp_servers SET revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ResetMCPCapabilityScopeOverrides :execrows
-- The server's requirement was removed or now names another provider:
-- overrides with other scopes of the old provider go back to inherit.
UPDATE mcp_capabilities SET requirement_mode = 'inherit', requirement_scopes = '{}'
WHERE server_id = @server_id AND requirement_mode = 'scopes';

-- name: SetMCPCapabilityRequirement :one
UPDATE mcp_capabilities SET requirement_mode = @requirement_mode, requirement_scopes = @requirement_scopes
WHERE id = @id AND server_id = @server_id
RETURNING *;

-- name: DeleteMCPServer :exec
DELETE FROM mcp_servers WHERE id = $1;

-- name: SetMCPServerPublishState :one
-- Moves a server to a publish state. The request columns are set when it
-- is requested (pending or self-published), the review columns when a
-- platform admin reviews it; published_at is kept while published.
UPDATE mcp_servers
SET publish_state        = @publish_state,
    publish_requested_at = CASE WHEN @requested::bool THEN now() ELSE publish_requested_at END,
    publish_requested_by = CASE WHEN @requested::bool THEN sqlc.narg(actor)::uuid ELSE publish_requested_by END,
    publish_request_note = CASE WHEN @requested::bool THEN sqlc.narg(note)::text ELSE publish_request_note END,
    publish_reviewed_at  = CASE WHEN @reviewed::bool THEN now() WHEN @requested::bool THEN NULL ELSE publish_reviewed_at END,
    publish_reviewed_by  = CASE WHEN @reviewed::bool THEN sqlc.narg(actor)::uuid WHEN @requested::bool THEN NULL ELSE publish_reviewed_by END,
    publish_review_note  = CASE WHEN @reviewed::bool THEN sqlc.narg(note)::text WHEN @requested::bool THEN NULL ELSE publish_review_note END,
    published_at         = CASE WHEN @publish_state::text = 'published' THEN coalesce(published_at, now()) ELSE NULL END,
    revision             = revision + 1,
    updated_by           = sqlc.narg(actor)::uuid,
    updated_at           = now()
WHERE id = @id
RETURNING *;

-- name: SetMCPServerRefreshed :exec
UPDATE mcp_servers SET refreshed_at = now(), last_refresh_error = NULL WHERE id = $1;

-- name: SetMCPServerProtocol :exec
-- The era and version the portal last negotiated with the server (set when a
-- refresh, test or health check reads it).
UPDATE mcp_servers SET protocol_era = @era, protocol_version = @version, protocol_negotiated_at = now() WHERE id = @id;

-- name: ClearMCPServerRefreshed :exec
-- A new URL: the stored capabilities (and the protocol negotiated) were read
-- from the old endpoint.
UPDATE mcp_servers SET refreshed_at = NULL, protocol_era = NULL, protocol_version = NULL, protocol_negotiated_at = NULL WHERE id = $1;

-- name: SetMCPServerRefreshError :exec
UPDATE mcp_servers SET last_refresh_error = @message WHERE id = @id;

-- name: ListMCPServers :many
-- One page of servers ordered by (name, id), with their team and reviewer.
-- team_id narrows to one team; publish_state to one state; changes_only to
-- published servers with capabilities waiting for approval; catalog to
-- published, enabled servers of active teams; provider_id to servers that
-- require that auth provider. search is LIKE-escaped by the caller.
SELECT sqlc.embed(s), t.slug AS team_slug, t.name AS team_name, t.publish_policy_override AS team_policy_override,
       t.status AS team_status,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = s.publish_reviewed_by), '')::text
           AS reviewed_by_name
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id
WHERE (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
  AND (sqlc.narg(publish_state)::text IS NULL OR s.publish_state = sqlc.narg(publish_state)::text)
  AND (sqlc.narg(provider_id)::uuid IS NULL OR s.auth_provider_id = sqlc.narg(provider_id)::uuid
       OR EXISTS (SELECT 1 FROM auth_providers b WHERE b.server_id = s.id AND b.link_provider_id = sqlc.narg(provider_id)::uuid))
  AND (sqlc.narg(auth_mode)::text IS NULL OR s.auth_mode = sqlc.narg(auth_mode)::text
       OR (sqlc.narg(auth_mode)::text = 'static_header' AND s.auth_mode = 'none' AND s.auth_header_name IS NOT NULL))
  AND (NOT @catalog::bool OR (s.publish_state = 'published' AND s.enabled AND t.status = 'active'))
  AND (NOT @changes_only::bool OR (s.publish_state = 'published' AND EXISTS (
        SELECT 1 FROM mcp_capabilities c
        WHERE c.server_id = s.id AND c.gone_at IS NULL AND c.approved_fingerprint IS DISTINCT FROM c.fingerprint)))
  AND (sqlc.narg(search)::text IS NULL
       OR s.name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR s.slug ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR (@catalog::bool AND s.description ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'))
  AND (sqlc.narg(after_name)::text IS NULL OR (s.name, s.id) > (sqlc.narg(after_name)::text, sqlc.narg(after_id)::uuid))
ORDER BY s.name, s.id
LIMIT @page_size;

-- name: GetMCPServerView :one
SELECT sqlc.embed(s), t.slug AS team_slug, t.name AS team_name, t.publish_policy_override AS team_policy_override,
       t.status AS team_status,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = s.publish_reviewed_by), '')::text
           AS reviewed_by_name
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id
WHERE s.id = $1;

-- name: MCPCapabilityStats :many
-- Per server and kind: listed capabilities, the approved ones, and the
-- listed ones whose current definition is not approved.
SELECT c.server_id, c.kind,
       count(*) FILTER (WHERE c.gone_at IS NULL)::bigint AS listed,
       count(*) FILTER (WHERE c.gone_at IS NULL AND c.approved_fingerprint = c.fingerprint)::bigint AS approved,
       count(*) FILTER (WHERE c.gone_at IS NULL AND c.approved_fingerprint IS DISTINCT FROM c.fingerprint)::bigint AS unapproved
FROM mcp_capabilities c
WHERE c.server_id = ANY(@server_ids::uuid[])
GROUP BY c.server_id, c.kind;

-- name: ListMCPCapabilityFingerprints :many
-- What a reviewer's digest covers: the listed (not gone) capabilities of
-- servers, as (kind, name, fingerprint) and the capability's own present-person
-- override (NULL: the server's switch decides).
SELECT c.server_id, c.kind, c.name, c.fingerprint, c.requires_present_person
FROM mcp_capabilities c
WHERE c.server_id = ANY(@server_ids::uuid[]) AND c.gone_at IS NULL
ORDER BY c.server_id, c.kind, c.name;

-- name: ListMCPCapabilities :many
-- A server's capabilities ordered by kind (tool, resource, template,
-- prompt) and name, gone ones included, with who approved each.
SELECT sqlc.embed(c),
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = c.approved_by), '')::text
           AS approved_by_name
FROM mcp_capabilities c
WHERE c.server_id = @server_id
  AND (sqlc.narg(kind)::text IS NULL OR c.kind = sqlc.narg(kind)::text)
ORDER BY CASE c.kind WHEN 'tool' THEN 0 WHEN 'resource' THEN 1 WHEN 'resource_template' THEN 2 ELSE 3 END, c.name;

-- name: ListApprovedMCPCapabilities :many
-- The catalog's capabilities of a server: listed and approved.
SELECT * FROM mcp_capabilities c
WHERE c.server_id = @server_id AND c.gone_at IS NULL AND c.approved_fingerprint = c.fingerprint
ORDER BY CASE c.kind WHEN 'tool' THEN 0 WHEN 'resource' THEN 1 WHEN 'resource_template' THEN 2 ELSE 3 END, c.name;

-- name: LockMCPCapability :one
SELECT * FROM mcp_capabilities WHERE id = @id AND server_id = @server_id FOR UPDATE;

-- name: UpsertMCPCapability :exec
-- Stores a listed capability. The approval columns are never touched here:
-- a changed definition (fingerprint) is unapproved by definition.
INSERT INTO mcp_capabilities (server_id, kind, name, title, description, definition, fingerprint)
VALUES (@server_id, @kind, @name, @title, @description, @definition, @fingerprint)
ON CONFLICT (server_id, kind, name) DO UPDATE
SET title = EXCLUDED.title, description = EXCLUDED.description, definition = EXCLUDED.definition,
    fingerprint = EXCLUDED.fingerprint, last_seen_at = now(), gone_at = NULL;

-- name: MarkMCPCapabilitiesGone :many
-- Marks the server's listed capabilities that the refresh didn't list as
-- gone, and withdraws their approval.
UPDATE mcp_capabilities c
SET gone_at = now(), approved_fingerprint = NULL, approved_by = NULL, approved_at = NULL
WHERE c.server_id = @server_id AND c.gone_at IS NULL
  -- listed holds "kind name" for every capability the refresh listed.
  AND NOT ((c.kind || ' ' || c.name) = ANY(@listed::text[]))
RETURNING c.kind, c.name;

-- name: ApproveMCPCapability :one
UPDATE mcp_capabilities
SET approved_fingerprint = fingerprint, approved_by = @approved_by, approved_at = now()
WHERE id = @id AND gone_at IS NULL
RETURNING *;

-- name: ApproveListedMCPCapabilities :execrows
-- Approves every listed capability of a server whose current definition is
-- not approved yet (publishing).
UPDATE mcp_capabilities
SET approved_fingerprint = fingerprint, approved_by = @approved_by, approved_at = now()
WHERE server_id = @server_id AND gone_at IS NULL AND approved_fingerprint IS DISTINCT FROM fingerprint;

-- name: InsertMCPHealthCheck :one
-- Stores a check. status_since is carried over from the server's previous
-- check while the outcome stays the same.
INSERT INTO mcp_health_checks (server_id, ok, latency_ms, trigger, triggered_by, error_class, http_status, message, status_since,
                               sign_in_required)
SELECT @server_id, @ok::bool, @latency_ms, @trigger, @triggered_by, @error_class, @http_status, @message,
       COALESCE((SELECT CASE WHEN p.ok = @ok::bool THEN p.status_since END
                 FROM mcp_health_checks p WHERE p.server_id = @server_id
                 ORDER BY p.checked_at DESC, p.id DESC LIMIT 1), now()),
       @sign_in_required::bool
RETURNING *;

-- name: PruneMCPHealthChecks :execrows
-- Keeps a server's latest keep checks.
DELETE FROM mcp_health_checks d
WHERE d.server_id = @server_id::uuid
  AND d.id NOT IN (SELECT h.id FROM mcp_health_checks h WHERE h.server_id = @server_id::uuid
                   ORDER BY h.checked_at DESC, h.id DESC LIMIT @keep::int);

-- name: ForgetMCPHealthChecks :exec
DELETE FROM mcp_health_checks WHERE server_id = $1;

-- name: ListMCPHealthChecks :many
SELECT * FROM mcp_health_checks WHERE server_id = @server_id ORDER BY checked_at DESC, id DESC LIMIT @page_size;

-- name: LatestMCPHealthChecks :many
SELECT DISTINCT ON (h.server_id) h.*
FROM mcp_health_checks h
WHERE h.server_id = ANY(@server_ids::uuid[])
ORDER BY h.server_id, h.checked_at DESC, h.id DESC;

-- name: ListMCPServersDueForCheck :many
-- Enabled servers of active teams whose latest check is older than
-- due_before (or that have none): the health loop's targets. Several
-- replicas taking turns therefore don't test a server twice in one interval.
SELECT s.* FROM mcp_servers s
JOIN teams t ON t.id = s.team_id
WHERE s.enabled AND t.status = 'active'
  AND NOT EXISTS (SELECT 1 FROM mcp_health_checks h WHERE h.server_id = s.id AND h.checked_at >= @due_before)
ORDER BY s.id;

-- name: ListMCPServerCredentials :many
-- A server's own credential parts in order (empty: the legacy header columns
-- of mcp_servers, if any, are its only part).
SELECT * FROM mcp_server_credentials WHERE server_id = $1 ORDER BY position;

-- name: ListMCPServerCredentialsFor :many
SELECT * FROM mcp_server_credentials WHERE server_id = ANY(@ids::uuid[]) ORDER BY server_id, position;

-- name: InsertMCPServerCredential :one
INSERT INTO mcp_server_credentials (id, server_id, position, kind, name, value_cipher, secondary_cipher, hint, created_at)
VALUES (@id, @server_id, @position, @kind, @name, @value_cipher, @secondary_cipher, @hint, @created_at)
RETURNING *;

-- name: DeleteMCPServerCredentials :exec
DELETE FROM mcp_server_credentials WHERE server_id = $1;
