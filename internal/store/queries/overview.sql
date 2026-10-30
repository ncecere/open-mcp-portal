-- The admin overview and team attention (internal/overview; docs/admin-overview.md).
-- Every kind is one indexed query with a LIMIT; the total comes with the rows
-- (a window count before the LIMIT), so no second pass is needed. "Active
-- team" means not archived.

-- name: OverviewCounts :one
SELECT
    (SELECT count(*) FROM users WHERE status = 'active')::bigint AS users,
    (SELECT count(*) FROM teams WHERE status = 'active')::bigint AS teams,
    (SELECT count(*) FROM mcp_servers s JOIN teams t ON t.id = s.team_id AND t.status = 'active')::bigint AS servers,
    (SELECT count(*) FROM mcp_servers s JOIN teams t ON t.id = s.team_id AND t.status = 'active'
      WHERE s.publish_state = 'published')::bigint AS published_servers,
    (SELECT count(*) FROM gateways g LEFT JOIN teams t ON t.id = g.team_id
      WHERE g.owner_kind = 'platform' OR t.status = 'active')::bigint AS gateways,
    (SELECT count(*) FROM service_accounts sa JOIN teams t ON t.id = sa.team_id AND t.status = 'active')::bigint AS service_accounts,
    (SELECT count(*) FROM automation_tokens WHERE revoked_at IS NULL AND expires_at > now())::bigint AS automation_tokens;

-- name: OverviewActivity :one
-- The 24 hourly rollup buckets ending with the current hour. errors is every
-- outcome but ok, as Admin > Usage counts them.
SELECT COALESCE(sum(calls), 0)::bigint AS calls,
       COALESCE(sum(calls) FILTER (WHERE outcome <> 'ok'), 0)::bigint AS errors,
       COALESCE(sum(calls) FILTER (WHERE outcome = 'rate_limited'), 0)::bigint AS rate_limited
FROM usage_hourly
WHERE hour >= date_trunc('hour', now()) - interval '23 hours' AND hour < date_trunc('hour', now()) + interval '1 hour';

-- name: AttentionFailingServers :many
-- Enabled servers of active teams whose latest health check failed; at is
-- the time the failure began. published_only: the platform's view (published
-- servers only); otherwise one team's (team_id), any publish state.
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name, h.status_since,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
JOIN LATERAL (
    SELECT c.ok, c.status_since FROM mcp_health_checks c WHERE c.server_id = s.id ORDER BY c.checked_at DESC, c.id DESC LIMIT 1
) h ON NOT h.ok
WHERE s.enabled
  AND (NOT @published_only::bool OR s.publish_state = 'published')
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY h.status_since, s.name, s.id
LIMIT @page_size;

-- name: AttentionLapsedSignins :many
-- Enabled oauth servers whose setup sign-in needs re-consent (its person is
-- still an active editor or above); at is when it lapsed (the audit entry;
-- the epoch when none is recorded).
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name,
       lapse.at::timestamptz AS lapsed_at,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
JOIN auth_providers p ON p.server_id = s.id
JOIN provider_connections c ON c.provider_id = p.id AND c.user_id = s.oauth_setup_user_id AND c.status = 'needs_reconsent'
JOIN users u ON u.id = c.user_id AND u.status = 'active'
JOIN team_members m ON m.team_id = s.team_id AND m.user_id = u.id AND m.role IN ('owner', 'admin', 'editor')
CROSS JOIN LATERAL (
    SELECT COALESCE(max(a.occurred_at), 'epoch'::timestamptz) AS at FROM audit_log a
    WHERE a.target_type = 'provider_connection' AND a.target_id = c.id::text AND a.action = 'provider_connection.refresh_failed'
) lapse
WHERE s.auth_mode = 'oauth' AND s.enabled
  AND (NOT @published_only::bool OR s.publish_state = 'published')
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY (lapse.at = 'epoch'::timestamptz), lapse.at, s.name, s.id
LIMIT @page_size;

-- name: AttentionPendingReviews :one
-- Servers waiting for a platform review in active teams (all, or one team's).
SELECT count(*)::bigint AS pending, COALESCE(min(s.publish_requested_at), 'epoch'::timestamptz)::timestamptz AS oldest
FROM mcp_servers s JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'pending' AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid);

-- name: AttentionChangedCapabilities :many
-- Published, enabled servers of active teams with changed or new capabilities
-- held back (not approved); count says how many.
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name, h.held::bigint AS held,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
JOIN LATERAL (
    SELECT count(*) AS held FROM mcp_capabilities c
    WHERE c.server_id = s.id AND c.gone_at IS NULL AND c.approved_fingerprint IS DISTINCT FROM c.fingerprint
) h ON h.held > 0
WHERE s.publish_state = 'published' AND s.enabled
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY s.name, s.id
LIMIT @page_size;

-- name: AttentionPersonalKeys :one
-- Personal keys of active people expiring within 14 days.
SELECT count(*)::bigint AS keys, COALESCE(min(k.expires_at), 'epoch'::timestamptz)::timestamptz AS earliest
FROM api_keys k JOIN users u ON u.id = k.user_id AND u.status = 'active'
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '14 days';

-- name: AttentionServiceAccountKeys :many
-- Per team (active teams), the service account keys expiring within 14 days.
SELECT t.id AS team_id, t.slug AS team_slug, t.name AS team_name, count(*)::bigint AS keys, COALESCE(min(k.expires_at), 'epoch'::timestamptz)::timestamptz AS earliest,
       (count(*) OVER ())::bigint AS groups, (sum(count(*)) OVER ())::bigint AS total
FROM service_account_keys k
JOIN service_accounts sa ON sa.id = k.service_account_id
JOIN teams t ON t.id = sa.team_id AND t.status = 'active'
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '14 days'
  AND (sqlc.narg(team_id)::uuid IS NULL OR t.id = sqlc.narg(team_id)::uuid)
GROUP BY t.id
ORDER BY min(k.expires_at), t.name, t.id
LIMIT @page_size;

-- name: AttentionAutomationTokens :many
-- Tokens expiring within 14 days: one group for platform tokens (team NULL)
-- and one per active team. include_platform: the platform view.
SELECT t.id AS team_id, COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name,
       count(*)::bigint AS tokens, COALESCE(min(k.expires_at), 'epoch'::timestamptz)::timestamptz AS earliest,
       (count(*) OVER ())::bigint AS groups, (sum(count(*)) OVER ())::bigint AS total
FROM automation_tokens k
LEFT JOIN teams t ON t.id = k.team_id
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '14 days'
  AND (k.team_id IS NULL OR t.status = 'active')
  AND ((@include_platform::bool AND k.team_id IS NULL AND sqlc.narg(team_id)::uuid IS NULL)
       OR (k.team_id IS NOT NULL AND (sqlc.narg(team_id)::uuid IS NULL OR k.team_id = sqlc.narg(team_id)::uuid)))
GROUP BY t.id
ORDER BY min(k.expires_at), t.name NULLS FIRST, t.id
LIMIT @page_size;

-- name: AttentionConnections :one
-- People's connections that need re-consent (active people; a server's setup
-- sign-in is counted as upstream_signin_lapsed instead).
SELECT count(*)::bigint AS connections
FROM provider_connections c
JOIN users u ON u.id = c.user_id AND u.status = 'active'
JOIN auth_providers p ON p.id = c.provider_id
WHERE c.status = 'needs_reconsent'
  AND NOT EXISTS (SELECT 1 FROM mcp_servers s WHERE s.id = p.server_id AND s.oauth_setup_user_id = c.user_id);

-- name: AttentionDisabledGateways :one
SELECT count(*)::bigint AS gateways
FROM gateways g LEFT JOIN teams t ON t.id = g.team_id
WHERE NOT g.enabled AND (g.owner_kind = 'platform' OR t.status = 'active');

-- name: AttentionFailingDestinations :one
-- Webhook destinations stopped automatically or failing 3 or more times in a
-- row (all of them, or one team's).
SELECT count(*)::bigint AS destinations, COALESCE(max(d.last_failure_at), 'epoch'::timestamptz)::timestamptz AS latest
FROM notification_destinations d LEFT JOIN teams t ON t.id = d.team_id
WHERE (d.disabled_reason = 'failures' OR d.consecutive_failures >= 3)
  AND (d.team_id IS NULL OR t.status = 'active')
  AND (sqlc.narg(team_id)::uuid IS NULL OR d.team_id = sqlc.narg(team_id)::uuid);

-- name: AttentionEmailFailure :one
-- The latest failed email delivery within 24 hours (the epoch when none).
SELECT COALESCE(max(last_attempt_at), 'epoch'::timestamptz)::timestamptz AS latest FROM notification_outbox
WHERE channel = 'email' AND state = 'failed' AND last_attempt_at > now() - interval '24 hours';

-- name: AttentionExpiringCertificates :many
-- Enabled servers of active teams whose client certificate (mTLS) has expired
-- or expires within 14 days; at is the expiry. published_only: the platform's
-- view (published servers only); otherwise one team's (team_id), any state.
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name, c.client_not_after,
       (count(*) OVER ())::bigint AS total
FROM mcp_server_tls c
JOIN mcp_servers s ON s.id = c.server_id AND s.enabled
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE c.client_not_after IS NOT NULL AND c.client_not_after <= now() + interval '14 days'
  AND (NOT @published_only::bool OR s.publish_state = 'published')
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY c.client_not_after, s.name, s.id
LIMIT @page_size;

-- name: AttentionReviewDue :many
-- Published servers of active teams whose re-review is due (decision 88); at
-- is the due date. team_id narrows to one team's.
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name, s.review_due_at,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'published' AND s.review_due_at IS NOT NULL AND s.review_due_at <= @now::timestamptz
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY s.review_due_at, s.name, s.id
LIMIT @page_size;

-- name: AttentionOwnerlessServers :many
-- Published servers of active teams nobody is accountable for: no owner is
-- named, or the owner is no longer an active editor or above of the team (they
-- left it, lost their role, were suspended or deleted).
SELECT s.id, s.slug, s.name, t.id AS team_id, t.slug AS team_slug, t.name AS team_name, (s.owner_user_id IS NOT NULL)::boolean AS owner_left,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'published'
  AND NOT EXISTS (SELECT 1 FROM users u
                  JOIN team_members m ON m.user_id = u.id AND m.team_id = s.team_id AND m.role IN ('owner', 'admin', 'editor')
                  WHERE u.id = s.owner_user_id AND u.status = 'active')
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY (s.owner_user_id IS NULL), s.name, s.id
LIMIT @page_size;

-- name: AttentionUnlabelledServers :many
-- Published servers of active teams whose sensitivity label nobody confirmed:
-- a stored 'internal' is the column's default until an owner or admin of the
-- team sends a sensitivity (decision 88). Bookkeeping only: nothing is blocked.
SELECT s.id, s.slug, s.name, s.sensitivity, t.id AS team_id, t.slug AS team_slug, t.name AS team_name,
       (count(*) OVER ())::bigint AS total
FROM mcp_servers s
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE s.publish_state = 'published' AND s.sensitivity_confirmed_at IS NULL
  AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id = sqlc.narg(team_id)::uuid)
ORDER BY s.name, s.id
LIMIT @page_size;

-- name: AttentionPendingTransfers :one
-- Transfers waiting for a team's owners to accept, and the oldest request.
SELECT count(*)::bigint AS pending, COALESCE(min(t.requested_at), 'epoch'::timestamptz)::timestamptz AS oldest
FROM server_transfers t
JOIN mcp_servers s ON s.id = t.server_id
WHERE t.state = 'pending' AND t.to_team_id = @team_id;
