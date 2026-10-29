-- Gateways, their selected capabilities and grants (internal/gateways).

-- name: InsertGateway :one
INSERT INTO gateways (id, slug, name, description, owner_kind, team_id, enabled, capture_payloads, rate_limit_per_minute,
                      created_by, updated_by)
VALUES (@id, @slug, @name, @description, @owner_kind, sqlc.narg(team_id), @enabled, @capture_payloads,
        sqlc.narg(rate_limit_per_minute), @created_by, @created_by)
RETURNING *;

-- name: GetGateway :one
SELECT * FROM gateways WHERE id = $1;

-- name: GetGatewayBySlug :one
SELECT * FROM gateways WHERE slug = $1;

-- name: LockGateway :one
SELECT * FROM gateways WHERE id = $1 FOR UPDATE;

-- name: UpdateGateway :one
UPDATE gateways
SET name = @name, description = @description, enabled = @enabled, capture_payloads = @capture_payloads,
    rate_limit_per_minute = sqlc.narg(rate_limit_per_minute),
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: BumpGatewayRevision :one
UPDATE gateways SET revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: DeleteGateway :exec
DELETE FROM gateways WHERE id = $1;

-- name: ListGateways :many
-- One page of gateways ordered by (name, id), with a team gateway's team.
-- search is LIKE-escaped by the caller.
SELECT sqlc.embed(g), COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name
FROM gateways g
LEFT JOIN teams t ON t.id = g.team_id
WHERE (sqlc.narg(team_id)::uuid IS NULL OR g.team_id = sqlc.narg(team_id)::uuid)
  AND (sqlc.narg(owner_kind)::text IS NULL OR g.owner_kind = sqlc.narg(owner_kind)::text)
  AND (sqlc.narg(search)::text IS NULL
       OR g.name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR g.slug ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\')
  AND (sqlc.narg(after_name)::text IS NULL OR (g.name, g.id) > (sqlc.narg(after_name)::text, sqlc.narg(after_id)::uuid))
ORDER BY g.name, g.id
LIMIT @page_size;

-- name: GetGatewayView :one
SELECT sqlc.embed(g), COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name
FROM gateways g
LEFT JOIN teams t ON t.id = g.team_id
WHERE g.id = $1;

-- name: GatewayStats :many
-- Per gateway: selected capabilities, the ones not served right now, and
-- grants. "Served" mirrors gateways.Availability: listed, the server's team
-- and a team gateway's own team active, its server enabled, and either the
-- team gateway's own server or published with the current definition
-- approved.
SELECT g.id AS gateway_id,
       (SELECT count(*) FROM gateway_capabilities gc WHERE gc.gateway_id = g.id)::bigint AS capability_count,
       (SELECT count(*)
        FROM gateway_capabilities gc
        JOIN mcp_capabilities c ON c.id = gc.capability_id
        JOIN mcp_servers s ON s.id = c.server_id
        JOIN teams st ON st.id = s.team_id
        WHERE gc.gateway_id = g.id
          AND NOT COALESCE(c.gone_at IS NULL AND c.kind IN ('tool', 'prompt', 'resource', 'resource_template')
                           AND (gc.base_fingerprint IS NULL OR (
                               gc.base_fingerprint = c.fingerprint AND c.kind = 'tool'
                               AND NOT EXISTS (SELECT 1 FROM jsonb_object_keys(gc.constraints) AS arg
                                               WHERE NOT COALESCE((c.definition->'inputSchema'->'properties') ? arg, false))))
                           AND st.status = 'active' AND COALESCE(gt.status, 'active') = 'active' AND s.enabled
                           AND ((g.owner_kind = 'team' AND s.team_id = g.team_id)
                                OR (s.publish_state = 'published' AND c.approved_fingerprint = c.fingerprint)), false)
       )::bigint AS unavailable_count,
       (SELECT count(*) FROM gateway_grants gg WHERE gg.gateway_id = g.id
          AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp()))::bigint AS grant_count
FROM gateways g
LEFT JOIN teams gt ON gt.id = g.team_id
WHERE g.id = ANY(@ids::uuid[]);

-- name: ListGatewaySelection :many
-- A gateway's selected capabilities with their servers and the servers'
-- teams, ordered by server and name (tools, prompts, resources, templates).
SELECT sqlc.embed(c), sqlc.embed(s), sqlc.embed(gc), t.slug AS team_slug, t.name AS team_name, t.status AS team_status
FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id = gc.capability_id
JOIN mcp_servers s ON s.id = c.server_id
JOIN teams t ON t.id = s.team_id
WHERE gc.gateway_id = @gateway_id
ORDER BY s.name, s.id,
         CASE c.kind WHEN 'tool' THEN 0 WHEN 'prompt' THEN 1 WHEN 'resource' THEN 2 ELSE 3 END, c.name;

-- name: RemoveGatewayCapabilitiesExcept :exec
DELETE FROM gateway_capabilities
WHERE gateway_id = @gateway_id AND NOT (capability_id = ANY(@keep::uuid[]));

-- name: UpsertGatewayCapability :exec
INSERT INTO gateway_capabilities (gateway_id, capability_id, min_team_role, added_by)
VALUES (@gateway_id, @capability_id, sqlc.narg(min_team_role), @added_by)
ON CONFLICT (gateway_id, capability_id) DO UPDATE SET min_team_role = EXCLUDED.min_team_role;

-- name: SetGatewayCapabilityCuration :exec
UPDATE gateway_capabilities SET name_override = sqlc.narg(name_override),
    description_override = sqlc.narg(description_override), constraints = sqlc.narg(constraints),
    base_fingerprint = sqlc.narg(base_fingerprint), curated_by = sqlc.narg(curated_by),
    curated_at = sqlc.narg(curated_at)
WHERE gateway_id = @gateway_id AND capability_id = @capability_id;

-- name: ListGatewayOptions :many
-- One page of the tools, prompts, resources and resource templates a
-- gateway may select, ordered by (server name, server id, name, id):
-- listed, of an enabled server of an active team, and either a server of
-- team_id (a team gateway's own team; NULL for a platform gateway) or
-- published with the current definition approved. Resource templates must
-- use only RFC 6570 level 1-2 {var} and {+var} expressions (the same rule as
-- gateways.TemplateSupported). by_ids narrows to ids; server_id to one
-- server; search is LIKE-escaped by the caller.
SELECT c.id, c.kind, c.name, c.title, c.description, c.requirement_mode, c.requirement_scopes, c.tool_class,
       s.id AS server_id, s.slug AS server_slug, s.name AS server_name, s.team_id AS server_team_id,
       s.auth_provider_id AS server_auth_provider_id, s.auth_scopes AS server_auth_scopes, s.auth_mode AS server_auth_mode,
       s.capture_payloads AS server_capture_payloads,
       t.slug AS team_slug, t.name AS team_name
FROM mcp_capabilities c
JOIN mcp_servers s ON s.id = c.server_id
JOIN teams t ON t.id = s.team_id
WHERE c.kind IN ('tool', 'prompt', 'resource', 'resource_template') AND c.gone_at IS NULL AND s.enabled AND t.status = 'active'
  AND (c.kind <> 'resource_template' OR c.name ~ '^([^{}]|\{\+?[A-Za-z0-9_]([A-Za-z0-9_.]|%[0-9A-Fa-f]{2})*\})*$')
  AND ((sqlc.narg(team_id)::uuid IS NOT NULL AND s.team_id = sqlc.narg(team_id)::uuid)
       OR (s.publish_state = 'published' AND c.approved_fingerprint = c.fingerprint))
  AND (sqlc.narg(kind)::text IS NULL OR c.kind = sqlc.narg(kind)::text)
  AND (sqlc.narg(server_id)::uuid IS NULL OR s.id = sqlc.narg(server_id)::uuid)
  AND (NOT @by_ids::bool OR c.id = ANY(@ids::uuid[]))
  AND (sqlc.narg(search)::text IS NULL
       OR c.name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR c.title ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR s.name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR s.slug ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\')
  AND (sqlc.narg(after_server_name)::text IS NULL
       OR (s.name, s.id, c.name, c.id) > (sqlc.narg(after_server_name)::text, sqlc.narg(after_server_id)::uuid,
                                          sqlc.narg(after_name)::text, sqlc.narg(after_id)::uuid))
ORDER BY s.name, s.id, c.name, c.id
LIMIT @page_size;

-- name: ListGatewayGrants :many
SELECT sqlc.embed(gg),
       COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name,
       COALESCE(u.email::text, '')::text AS user_email, COALESCE(u.display_name, '')::text AS user_display_name,
       COALESCE(u.status, '')::text AS user_status,
       COALESCE((SELECT COALESCE(NULLIF(a.display_name, ''), a.email::text) FROM users a WHERE a.id = gg.added_by), '')::text
           AS added_by_name
FROM gateway_grants gg
LEFT JOIN teams t ON t.id = gg.team_id
LEFT JOIN users u ON u.id = gg.user_id
WHERE gg.gateway_id = @gateway_id
ORDER BY gg.added_at, gg.id;

-- name: InsertGatewayGrant :one
INSERT INTO gateway_grants (gateway_id, subject_kind, team_id, user_id, group_name, added_by, tool_scope, expires_at)
VALUES (@gateway_id, @subject_kind, sqlc.narg(team_id), sqlc.narg(user_id), sqlc.narg(group_name), @added_by, sqlc.narg(tool_scope), sqlc.narg(expires_at))
RETURNING *;

-- name: DeleteGatewayGrant :one
DELETE FROM gateway_grants WHERE id = @id AND gateway_id = @gateway_id
RETURNING *;

-- name: GatewayGrantGroupsForUser :many
-- The person's groups a gateway is granted to.
SELECT DISTINCT gg.group_name::text AS group_name
FROM gateway_grants gg
WHERE gg.gateway_id = @gateway_id AND gg.group_name = ANY(@groups::text[])
  AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
ORDER BY 1;

-- name: GatewayGrantKindsForUser :many
-- Kept until the runtime switches to scoped matching rows.
SELECT DISTINCT gg.subject_kind
FROM gateway_grants gg
WHERE gg.gateway_id = @gateway_id
  AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
  AND (gg.user_id = @user_id
       OR gg.team_id IN (SELECT m.team_id FROM team_members m WHERE m.user_id = @user_id)
       OR gg.group_name = ANY(@groups::text[]));

-- name: GatewayGrantsForUser :many
-- How a person reaches a gateway through its grants: their team's grant,
-- their own, or one of their groups'.
SELECT gg.*
FROM gateway_grants gg
WHERE gg.gateway_id = @gateway_id
  AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
  AND (gg.user_id = @user_id
       OR gg.team_id IN (SELECT m.team_id FROM team_members m WHERE m.user_id = @user_id)
       OR gg.group_name = ANY(@groups::text[]));

-- name: ListGatewaysForUser :many
-- Enabled gateways a person may use: their active teams' gateways (with
-- their role) and platform gateways granted to them, their teams or their
-- groups, with the groups that match.
SELECT sqlc.embed(g), COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name,
       COALESCE(m.role, '')::text AS member_role,
       ARRAY(SELECT DISTINCT gg.subject_kind FROM gateway_grants gg
             WHERE gg.gateway_id = g.id
               AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
               AND (gg.user_id = @user_id
                    OR gg.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = @user_id)
                    OR gg.group_name = ANY(@groups::text[])))::text[] AS grant_kinds,
       ARRAY(SELECT DISTINCT gg.group_name FROM gateway_grants gg
             WHERE gg.gateway_id = g.id AND gg.group_name = ANY(@groups::text[])
               AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
             ORDER BY gg.group_name)::text[] AS grant_groups
FROM gateways g
LEFT JOIN teams t ON t.id = g.team_id
LEFT JOIN team_members m ON g.owner_kind = 'team' AND m.team_id = g.team_id AND m.user_id = @user_id
WHERE g.enabled
  AND ((g.owner_kind = 'team' AND m.user_id IS NOT NULL AND t.status = 'active')
       OR (g.owner_kind = 'platform' AND EXISTS (
            SELECT 1 FROM gateway_grants gg
            WHERE gg.gateway_id = g.id
              AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp())
              AND (gg.user_id = @user_id
                   OR gg.team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = @user_id)
                   OR gg.group_name = ANY(@groups::text[])))))
ORDER BY g.name, g.id;

-- name: GetCapability :one
SELECT * FROM mcp_capabilities WHERE id = $1;

-- name: LockCapabilityForCuration :one
SELECT * FROM mcp_capabilities WHERE id = $1 FOR SHARE;

-- name: ListUsableGatewayCandidates :many
-- Gateways by ID, for checking which a person may use (API key scopes).
SELECT * FROM gateways WHERE id = ANY(@ids::uuid[]);

-- name: ListGatewaysForServiceAccount :many
-- Enabled gateways a service account of a team may use: the team's own
-- gateways while the team is active, and platform gateways granted to the
-- team (decision 23), by name.
SELECT sqlc.embed(g), COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name
FROM gateways g
LEFT JOIN teams t ON t.id = g.team_id
WHERE g.enabled
  AND ((g.owner_kind = 'team' AND g.team_id = @team_id AND t.status = 'active')
       OR (g.owner_kind = 'platform' AND EXISTS (
            SELECT 1 FROM gateway_grants gg WHERE gg.gateway_id = g.id AND gg.team_id = @team_id
              AND (gg.expires_at IS NULL OR gg.expires_at > clock_timestamp()))))
ORDER BY g.name, g.id;
