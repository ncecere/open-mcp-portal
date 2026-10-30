-- Server governance (internal/registry, decision 88): owner, on-call contact,
-- sensitivity, lifecycle, re-review dates, transfers and the governance loop.

-- name: SetMCPServerGovernance :one
-- Writes the governance columns. bump moves the revision when this is the only
-- change of the request (an update that changed other settings bumped it).
UPDATE mcp_servers
SET owner_user_id = sqlc.narg(owner_user_id)::uuid, oncall_contact = sqlc.narg(oncall_contact)::text,
    sensitivity = @sensitivity, lifecycle = @lifecycle,
    deprecated_at = sqlc.narg(deprecated_at)::timestamptz, sunset_at = sqlc.narg(sunset_at)::timestamptz,
    replacement_server_id = sqlc.narg(replacement_server_id)::uuid,
    revision = CASE WHEN @bump::bool THEN revision + 1 ELSE revision END,
    updated_by = sqlc.narg(updated_by)::uuid, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: GovernanceOwnerEligible :one
-- Whether the person is an active user and an editor or above of the team.
SELECT EXISTS (
    SELECT 1 FROM users u
    JOIN team_members m ON m.user_id = u.id AND m.team_id = @team_id AND m.role IN ('owner', 'admin', 'editor')
    WHERE u.id = @user_id AND u.status = 'active')::boolean AS eligible;

-- name: GovernanceReplacement :one
-- The fields a replacement is checked by (it must exist, be published or the
-- same team's, and not point back at the server).
SELECT s.id, s.team_id, s.publish_state, s.lifecycle, s.replacement_server_id
FROM mcp_servers s WHERE s.id = $1;

-- name: RecomputeMCPServerReviewDue :execrows
-- review_due_at = last_reviewed_at + the platform interval of the server's
-- sensitivity, for published servers (NULL for any other, and with no
-- interval). server_id narrows to one server; NULL does every server (the
-- intervals changed). Not a revision change: nobody edits it.
UPDATE mcp_servers s SET review_due_at = calc.due
FROM (
    SELECT x.id,
           CASE WHEN x.publish_state = 'published' AND x.last_reviewed_at IS NOT NULL AND d.days > 0
                THEN x.last_reviewed_at + make_interval(days => d.days) END AS due
    FROM mcp_servers x
    CROSS JOIN LATERAL (
        SELECT CASE x.sensitivity WHEN 'public' THEN ps.review_interval_days_public
                                  WHEN 'internal' THEN ps.review_interval_days_internal
                                  WHEN 'confidential' THEN ps.review_interval_days_confidential
                                  ELSE ps.review_interval_days_restricted END AS days
        FROM platform_settings ps WHERE ps.id = 1) d
    WHERE sqlc.narg(server_id)::uuid IS NULL OR x.id = sqlc.narg(server_id)::uuid
) calc
WHERE s.id = calc.id AND s.review_due_at IS DISTINCT FROM calc.due;

-- name: UpdateGovernanceSettings :one
UPDATE platform_settings
SET review_interval_days_public = @public, review_interval_days_internal = @internal,
    review_interval_days_confidential = @confidential, review_interval_days_restricted = @restricted,
    governance_return_overdue = @return_overdue,
    governance_revision = governance_revision + 1, governance_updated_by = sqlc.narg(updated_by)::uuid,
    governance_updated_at = now()
WHERE id = 1
RETURNING *;

-- Transfers.

-- name: InsertServerTransfer :one
INSERT INTO server_transfers (server_id, from_team_id, to_team_id, server_revision, note, requested_by)
VALUES (@server_id, @from_team_id, @to_team_id, @server_revision, sqlc.narg(note)::text, sqlc.narg(requested_by)::uuid)
RETURNING *;

-- name: GetServerTransfer :one
SELECT * FROM server_transfers WHERE id = $1;

-- name: LockServerTransfer :one
SELECT * FROM server_transfers WHERE id = $1 FOR UPDATE;

-- name: PendingServerTransfer :one
SELECT * FROM server_transfers WHERE server_id = $1 AND state = 'pending';

-- name: DecideServerTransfer :one
-- Closes a pending transfer (compare-and-set on the state and revision).
UPDATE server_transfers
SET state = @state, decided_by = sqlc.narg(actor)::uuid,
    accepted_by = CASE WHEN @state::text IN ('accepted', 'forced') THEN sqlc.narg(actor)::uuid END,
    decided_at = now(), revision = revision + 1
WHERE id = @id AND state = 'pending' AND revision = @revision
RETURNING *;

-- name: InsertForcedServerTransfer :one
-- The record of a platform admin's transfer: decided as it is made.
INSERT INTO server_transfers (server_id, from_team_id, to_team_id, server_revision, state, note, requested_by, accepted_by, decided_by, decided_at)
VALUES (@server_id, @from_team_id, @to_team_id, @server_revision, 'forced', sqlc.narg(note)::text,
        sqlc.narg(actor)::uuid, sqlc.narg(actor)::uuid, sqlc.narg(actor)::uuid, now())
RETURNING *;

-- name: ListServerTransfers :many
-- A team's transfers, newest first: out of it and into it. pending_only keeps
-- the open ones.
SELECT sqlc.embed(t), s.slug AS server_slug, s.name AS server_name,
       ft.slug AS from_team_slug, ft.name AS from_team_name, tt.slug AS to_team_slug, tt.name AS to_team_name,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = t.requested_by), '')::text AS requested_by_name
FROM server_transfers t
JOIN mcp_servers s ON s.id = t.server_id
JOIN teams ft ON ft.id = t.from_team_id
JOIN teams tt ON tt.id = t.to_team_id
WHERE (t.from_team_id = @team_id OR t.to_team_id = @team_id) AND (NOT @pending_only::bool OR t.state = 'pending')
ORDER BY t.requested_at DESC, t.id DESC
LIMIT @page_size;

-- name: GetServerTransferView :one
SELECT sqlc.embed(t), s.slug AS server_slug, s.name AS server_name,
       ft.slug AS from_team_slug, ft.name AS from_team_name, tt.slug AS to_team_slug, tt.name AS to_team_name,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = t.requested_by), '')::text AS requested_by_name
FROM server_transfers t
JOIN mcp_servers s ON s.id = t.server_id
JOIN teams ft ON ft.id = t.from_team_id
JOIN teams tt ON tt.id = t.to_team_id
WHERE t.id = $1;

-- name: MoveMCPServerToTeam :one
-- A transfer: the server belongs to another team. Everything bound to the
-- server (capabilities, selections, grants, sealed values) stays; the owner
-- is the new team's to name.
UPDATE mcp_servers
SET team_id = @team_id, owner_user_id = sqlc.narg(owner_user_id)::uuid,
    revision = revision + 1, updated_by = sqlc.narg(updated_by)::uuid, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: MoveServerApprovalRules :execrows
-- Approval rules of the server belong to its team, so the team that gave the
-- server away cannot loosen them any more.
UPDATE approval_rules SET team_id = @to_team_id, revision = revision + 1, updated_at = now()
WHERE target_kind = 'server' AND target_id = @server_id AND team_id = @from_team_id;

-- name: ProviderBlocksTeam :one
-- Whether the server's required provider is restricted and lists neither the
-- team nor the server: moving the server there would stop its calls.
SELECT (s.auth_provider_id IS NOT NULL AND p.kind <> 'mcp_server' AND p.access_mode = 'restricted'
        AND NOT EXISTS (SELECT 1 FROM auth_provider_teams pt WHERE pt.provider_id = p.id AND pt.team_id = @team_id)
        AND NOT EXISTS (SELECT 1 FROM auth_provider_servers ps WHERE ps.provider_id = p.id AND ps.server_id = s.id))::boolean AS blocked
FROM mcp_servers s LEFT JOIN auth_providers p ON p.id = s.auth_provider_id
WHERE s.id = @server_id;

-- The governance loop.

-- name: GovernanceRecordNotice :one
-- Records that people were told once: false when another run (or replica) did.
INSERT INTO server_governance_notices (kind, server_id, gateway_id, stamp)
VALUES (@kind, @server_id, sqlc.narg(gateway_id)::uuid, @stamp)
ON CONFLICT DO NOTHING
RETURNING id;

-- name: GovernanceReviewDue :many
-- Published servers of active teams whose re-review is due, oldest first.
SELECT sqlc.embed(s), t.slug AS team_slug, t.name AS team_name, t.publish_policy_override AS team_policy_override
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'published' AND s.review_due_at IS NOT NULL AND s.review_due_at <= @now::timestamptz
ORDER BY s.review_due_at, s.id
LIMIT @page_size;

-- name: GovernanceReviewDueUnnotified :many
-- The same, for which nobody has been told for this due date.
SELECT sqlc.embed(s), t.slug AS team_slug, t.name AS team_name, t.publish_policy_override AS team_policy_override
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'published' AND s.review_due_at IS NOT NULL AND s.review_due_at <= @now::timestamptz
  AND NOT EXISTS (SELECT 1 FROM server_governance_notices n
                  WHERE n.kind = 'review_due' AND n.server_id = s.id AND n.gateway_id IS NULL AND n.stamp = s.review_due_at)
ORDER BY s.review_due_at, s.id
LIMIT @page_size;

-- name: GovernanceSunsetSoonServers :many
-- Deprecated servers of active teams whose sunset is within the window and
-- not yet reached, told to nobody for this sunset date.
SELECT sqlc.embed(s), t.slug AS team_slug, t.name AS team_name
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.lifecycle = 'deprecated' AND s.sunset_at IS NOT NULL
  AND s.sunset_at > @now::timestamptz AND s.sunset_at <= @window_end::timestamptz
  AND NOT EXISTS (SELECT 1 FROM server_governance_notices n
                  WHERE n.kind = 'sunset_soon' AND n.server_id = s.id AND n.gateway_id IS NULL AND n.stamp = s.sunset_at)
ORDER BY s.sunset_at, s.id
LIMIT @page_size;

-- name: GovernanceDeprecatedPairs :many
-- Gateways (enabled; a team gateway's team active) that select a capability of
-- a deprecated server not yet sunset, whose owners have not been told about
-- this deprecation.
SELECT DISTINCT ON (s.id, g.id) s.id AS server_id, s.slug AS server_slug, s.name AS server_name, s.team_id AS server_team_id,
       s.deprecated_at, s.sunset_at, s.replacement_server_id,
       g.id AS gateway_id, g.slug AS gateway_slug, g.name AS gateway_name, g.owner_kind, g.team_id AS gateway_team_id
FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id = gc.capability_id AND c.gone_at IS NULL
JOIN mcp_servers s ON s.id = c.server_id
JOIN teams st ON st.id = s.team_id AND st.status = 'active'
JOIN gateways g ON g.id = gc.gateway_id AND g.enabled
LEFT JOIN teams gt ON gt.id = g.team_id
WHERE s.lifecycle = 'deprecated' AND (g.owner_kind = 'platform' OR gt.status = 'active')
  AND (s.sunset_at IS NULL OR s.sunset_at > @now::timestamptz)
  AND (s.publish_state = 'published' OR s.team_id = g.team_id)
  AND NOT EXISTS (SELECT 1 FROM server_governance_notices n
                  WHERE n.kind = 'deprecated' AND n.server_id = s.id AND n.gateway_id = g.id AND n.stamp = s.deprecated_at)
ORDER BY s.id, g.id
LIMIT @page_size;

-- name: GovernanceSunsetSoonPairs :many
-- The same for a sunset inside the window, whose gateway owners have not been
-- told about this sunset date.
SELECT DISTINCT ON (s.id, g.id) s.id AS server_id, s.slug AS server_slug, s.name AS server_name, s.team_id AS server_team_id,
       s.deprecated_at, s.sunset_at, s.replacement_server_id,
       g.id AS gateway_id, g.slug AS gateway_slug, g.name AS gateway_name, g.owner_kind, g.team_id AS gateway_team_id
FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id = gc.capability_id AND c.gone_at IS NULL
JOIN mcp_servers s ON s.id = c.server_id
JOIN teams st ON st.id = s.team_id AND st.status = 'active'
JOIN gateways g ON g.id = gc.gateway_id AND g.enabled
LEFT JOIN teams gt ON gt.id = g.team_id
WHERE s.lifecycle = 'deprecated' AND s.sunset_at IS NOT NULL
  AND s.sunset_at > @now::timestamptz AND s.sunset_at <= @window_end::timestamptz
  AND (g.owner_kind = 'platform' OR gt.status = 'active')
  AND (s.publish_state = 'published' OR s.team_id = g.team_id)
  AND NOT EXISTS (SELECT 1 FROM server_governance_notices n
                  WHERE n.kind = 'sunset_soon' AND n.server_id = s.id AND n.gateway_id = g.id AND n.stamp = s.sunset_at)
ORDER BY s.id, g.id
LIMIT @page_size;

-- name: GovernanceSelectingGateways :many
-- The gateways selecting a capability of one server, for the notice sent in
-- the transaction of a deprecation.
SELECT DISTINCT g.id AS gateway_id, g.slug AS gateway_slug, g.name AS gateway_name, g.owner_kind, g.team_id AS gateway_team_id
FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id = gc.capability_id AND c.gone_at IS NULL
JOIN gateways g ON g.id = gc.gateway_id AND g.enabled
WHERE c.server_id = @server_id
ORDER BY g.id;

-- Views.

-- name: GovernanceOwnerViews :many
-- The named owner of each server, and whether they are still an active editor
-- or above of its team.
SELECT s.id AS server_id, COALESCE(NULLIF(u.display_name, ''), u.email::text)::text AS owner_name,
       (u.status = 'active' AND EXISTS (SELECT 1 FROM team_members m
                                        WHERE m.team_id = s.team_id AND m.user_id = u.id AND m.role IN ('owner', 'admin', 'editor')))::boolean AS eligible
FROM mcp_servers s JOIN users u ON u.id = s.owner_user_id
WHERE s.id = ANY(@server_ids::uuid[]);

-- name: GovernanceReplacementViews :many
SELECT s.id AS server_id, r.id AS replacement_id, r.slug, r.name, r.team_id, r.publish_state, rt.slug AS team_slug, rt.name AS team_name
FROM mcp_servers s
JOIN mcp_servers r ON r.id = s.replacement_server_id
JOIN teams rt ON rt.id = r.team_id
WHERE s.id = ANY(@server_ids::uuid[]);

-- name: GovernancePendingTransfers :many
SELECT t.id, t.server_id, t.from_team_id, t.to_team_id, tt.slug AS to_team_slug, tt.name AS to_team_name, t.requested_at, t.revision
FROM server_transfers t JOIN teams tt ON tt.id = t.to_team_id
WHERE t.state = 'pending' AND t.server_id = ANY(@server_ids::uuid[]);

-- name: GovernanceOwnerRecipient :one
-- The server's named owner as a notification recipient, while an active editor
-- or above of its team.
SELECT u.id, u.email::text AS email, u.display_name, u.platform_role, u.email_verified
FROM mcp_servers s
JOIN users u ON u.id = s.owner_user_id AND u.status = 'active'
JOIN team_members m ON m.team_id = s.team_id AND m.user_id = u.id AND m.role IN ('owner', 'admin', 'editor')
WHERE s.id = @server_id;

-- name: GovernanceTeamGatewaySelections :one
-- How many selections of the server's capabilities the team's own gateways
-- hold (they keep them after a transfer, as catalog selections).
SELECT count(*)::bigint AS selections
FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id = gc.capability_id
JOIN gateways g ON g.id = gc.gateway_id
WHERE c.server_id = @server_id AND g.owner_kind = 'team' AND g.team_id = @team_id;

-- name: GovernanceDeleteNotice :exec
-- Takes a recorded notice back when its event could not be stored, so the
-- next run tells the people.
DELETE FROM server_governance_notices WHERE id = $1;
