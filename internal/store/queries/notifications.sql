-- Notifications (internal/notify; docs/notifications.md).

-- name: InsertNotificationEvent :execrows
-- Idempotent through dedup_key: 0 rows when the event was emitted before.
INSERT INTO notification_events (event, dedup_key, team_id, subject_type, subject_id, recipient_user_id, actor_user_id, payload)
VALUES (@event, @dedup_key, @team_id, @subject_type, @subject_id, @recipient_user_id, @actor_user_id, @payload)
ON CONFLICT (dedup_key) DO NOTHING;

-- name: LockNextUnfannedEvent :one
SELECT * FROM notification_events WHERE fanned_out_at IS NULL ORDER BY id LIMIT 1 FOR UPDATE SKIP LOCKED;

-- name: MarkNotificationEventFannedOut :exec
UPDATE notification_events SET fanned_out_at = now() WHERE id = @id;

-- name: GetNotificationEvent :one
SELECT * FROM notification_events WHERE id = @id;

-- name: FindNotificationEventByKeyPrefix :one
-- An event of a kind and subject whose dedup key starts with prefix (LIKE-escaped).
SELECT id, occurred_at FROM notification_events
WHERE event = @event AND subject_id = @subject_id AND dedup_key LIKE @prefix::text || '%' ESCAPE '\'
ORDER BY id DESC LIMIT 1;

-- name: LatestMCPHealthChecksOfServer :many
SELECT * FROM mcp_health_checks WHERE server_id = @server_id ORDER BY checked_at DESC, id DESC LIMIT @page_size;

-- name: GetNotificationServer :one
SELECT s.id, s.slug, s.name, s.team_id, s.publish_state, s.enabled, s.publish_requested_at, s.publish_reviewed_at, s.publish_request_note,
       s.publish_review_note, s.oauth_setup_user_id, s.auth_mode,
       COALESCE((SELECT COALESCE(NULLIF(u.display_name, ''), u.email::text) FROM users u WHERE u.id = s.oauth_setup_user_id), '')::text AS setup_name
FROM mcp_servers s WHERE s.id = @id;

-- name: ListHeldCapabilities :many
-- A server's listed capabilities whose current definition is not approved
-- (changed since approval, or new): held back from the catalog.
SELECT kind, name, fingerprint, (approved_fingerprint IS NOT NULL)::bool AS changed
FROM mcp_capabilities
WHERE server_id = @server_id AND gone_at IS NULL AND approved_fingerprint IS DISTINCT FROM fingerprint
ORDER BY CASE kind WHEN 'tool' THEN 0 WHEN 'resource' THEN 1 WHEN 'resource_template' THEN 2 ELSE 3 END, name;

-- name: GetNotificationConnection :one
SELECT c.id, c.user_id, c.connected_at, p.id AS provider_id, p.slug AS provider_slug, p.name AS provider_name, p.kind AS provider_kind,
       p.server_id AS provider_server_id
FROM provider_connections c JOIN auth_providers p ON p.id = c.provider_id
WHERE c.id = @id;

-- name: GetNotificationActorName :one
SELECT COALESCE(NULLIF(display_name, ''), email::text)::text AS name FROM users WHERE id = @id;

-- name: ListTeamRecipients :many
-- Active people holding one of the roles in an active team.
SELECT u.id, u.email::text AS email, u.display_name, u.platform_role, u.email_verified
FROM team_members m
JOIN teams t ON t.id = m.team_id AND t.status = 'active'
JOIN users u ON u.id = m.user_id AND u.status = 'active'
WHERE m.team_id = @team_id AND m.role = ANY(@roles::text[])
ORDER BY u.id;

-- name: ListPlatformAdminRecipients :many
SELECT u.id, u.email::text AS email, u.display_name, u.platform_role, u.email_verified
FROM users u WHERE u.platform_role = 'platform_admin' AND u.status = 'active' ORDER BY u.id;

-- name: GetActiveRecipient :one
SELECT u.id, u.email::text AS email, u.display_name, u.platform_role, u.email_verified FROM users u WHERE u.id = @id AND u.status = 'active';

-- name: ListNotificationPreferencesForUsers :many
SELECT user_id, event, channel, enabled FROM notification_preferences
WHERE user_id = ANY(@user_ids::uuid[]) AND event = @event;

-- name: ListNotificationPreferences :many
SELECT event, channel, enabled FROM notification_preferences WHERE user_id = @user_id;

-- name: UpsertNotificationPreference :exec
INSERT INTO notification_preferences (user_id, event, channel, enabled) VALUES (@user_id, @event, @channel, @enabled)
ON CONFLICT (user_id, event, channel) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now();

-- name: DeleteNotificationPreference :exec
-- Back to the default (rows only exist where they differ).
DELETE FROM notification_preferences WHERE user_id = @user_id AND event = @event AND channel = @channel;

-- name: InsertNotificationInbox :execrows
INSERT INTO notification_inbox (user_id, event_id, event, team_id, title, body, link)
VALUES (@user_id, @event_id, @event, @team_id, @title, @body, @link)
ON CONFLICT (user_id, event_id) DO NOTHING;

-- name: ListNotificationInbox :many
-- A person's notifications newest first, with their team's current name.
SELECT i.id, i.event, i.team_id, i.title, i.body, i.link, i.created_at, i.read_at,
       COALESCE(t.slug, '')::text AS team_slug, COALESCE(t.name, '')::text AS team_name
FROM notification_inbox i
LEFT JOIN teams t ON t.id = i.team_id
WHERE i.user_id = @user_id
  AND (NOT @unread_only::bool OR i.read_at IS NULL)
  AND (sqlc.narg(before_id)::bigint IS NULL OR i.id < sqlc.narg(before_id)::bigint)
ORDER BY i.id DESC
LIMIT @page_size;

-- name: CountUnreadNotifications :one
SELECT count(*) FROM notification_inbox WHERE user_id = @user_id AND read_at IS NULL;

-- name: MarkNotificationRead :execrows
-- 0 rows: not the person's, or gone (use GetNotificationInboxOwner to tell
-- an already-read one from a missing one).
UPDATE notification_inbox SET read_at = COALESCE(read_at, now()) WHERE id = @id AND user_id = @user_id;

-- name: MarkAllNotificationsRead :execrows
UPDATE notification_inbox SET read_at = now() WHERE user_id = @user_id AND read_at IS NULL;

-- name: PurgeNotificationInbox :execrows
WITH doomed AS (SELECT id FROM notification_inbox WHERE created_at < now() - interval '90 days' ORDER BY id LIMIT @batch_size)
DELETE FROM notification_inbox WHERE id IN (SELECT id FROM doomed);

-- name: PurgeNotificationEvents :execrows
WITH doomed AS (SELECT id FROM notification_events WHERE occurred_at < now() - interval '14 days' ORDER BY id LIMIT @batch_size)
DELETE FROM notification_events WHERE id IN (SELECT id FROM doomed);

-- name: PurgeNotificationOutbox :execrows
WITH doomed AS (SELECT id FROM notification_outbox WHERE created_at < now() - interval '14 days' ORDER BY id LIMIT @batch_size)
DELETE FROM notification_outbox WHERE id IN (SELECT id FROM doomed);

-- Destinations.

-- name: InsertNotificationDestination :one
INSERT INTO notification_destinations (id, scope, team_id, name, format, url_cipher, url_display, secret_cipher, secret_hint, secret_rotated_at,
                                       events, team_events, enabled, created_by, created_by_name, updated_by)
VALUES (@id, @scope, @team_id, @name, @format, @url_cipher, @url_display, @secret_cipher, @secret_hint,
        CASE WHEN @secret_cipher::bytea IS NULL THEN NULL ELSE now() END,
        @events, @team_events, @enabled, @created_by, @created_by_name, @created_by)
RETURNING *;

-- name: GetNotificationDestination :one
SELECT * FROM notification_destinations WHERE id = @id;

-- name: LockNotificationDestination :one
SELECT * FROM notification_destinations WHERE id = @id FOR UPDATE;

-- name: ListNotificationDestinations :many
-- A team's destinations, or the platform's (team_id NULL).
SELECT * FROM notification_destinations
WHERE (sqlc.narg(team_id)::uuid IS NULL AND scope = 'platform') OR team_id = sqlc.narg(team_id)::uuid
ORDER BY lower(name), id;

-- name: CountNotificationDestinations :one
SELECT count(*) FROM notification_destinations
WHERE (sqlc.narg(team_id)::uuid IS NULL AND scope = 'platform') OR team_id = sqlc.narg(team_id)::uuid;

-- name: UpdateNotificationDestination :one
UPDATE notification_destinations
SET name = @name, url_cipher = @url_cipher, url_display = @url_display, events = @events, team_events = @team_events,
    enabled = @enabled, disabled_reason = @disabled_reason, consecutive_failures = @consecutive_failures,
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: RotateNotificationDestinationSecret :one
UPDATE notification_destinations
SET secret_previous_cipher = @secret_previous_cipher, secret_previous_until = @secret_previous_until,
    secret_cipher = @secret_cipher, secret_hint = @secret_hint, secret_rotated_at = now(),
    revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: ClearNotificationDestinationPreviousSecret :exec
UPDATE notification_destinations SET secret_previous_cipher = NULL, secret_previous_until = NULL
WHERE id = @id AND secret_previous_until IS NOT NULL AND secret_previous_until <= now();

-- name: DeleteNotificationDestination :exec
DELETE FROM notification_destinations WHERE id = @id;

-- name: ListDestinationsForEvent :many
-- Enabled destinations that take an event: the team's own, and platform
-- ones (every platform destination takes publish.requested and platform
-- tokens' key.expiring; team events only with team_events).
SELECT * FROM notification_destinations
WHERE enabled AND @event::text = ANY(events)
  AND ((scope = 'team' AND team_id = sqlc.narg(team_id)::uuid)
       OR (scope = 'platform' AND (team_events OR NOT @team_event::bool)))
ORDER BY id;

-- name: RecordDestinationSuccess :exec
UPDATE notification_destinations
SET consecutive_failures = 0, last_success_at = now(), last_error_class = NULL
WHERE id = @id;

-- name: RecordDestinationFailure :one
UPDATE notification_destinations
SET consecutive_failures = consecutive_failures + 1, last_failure_at = now(), last_error_class = @error_class
WHERE id = @id
RETURNING *;

-- name: StopNotificationDestination :one
-- Automatic stop after repeated failures.
UPDATE notification_destinations
SET enabled = false, disabled_reason = 'failures', revision = revision + 1, updated_at = now()
WHERE id = @id AND enabled
RETURNING *;

-- Outbox.

-- name: InsertNotificationOutbox :execrows
INSERT INTO notification_outbox (event_id, channel, user_id, destination_id, state, error_class, dedup_key)
VALUES (@event_id, @channel, @user_id, @destination_id, @state, @error_class, @dedup_key)
ON CONFLICT (dedup_key) DO NOTHING;

-- name: ClaimDueNotificationOutbox :many
-- Takes up to batch due rows for this run, at most per_target for any one
-- destination or person (so a slow endpoint can't take a whole run); their
-- next attempt moves lease_seconds ahead, so a run that dies leaves them to
-- the next one. Only the dispatcher's leader claims, so no row lock is needed.
UPDATE notification_outbox o
SET next_attempt_at = now() + make_interval(secs => @lease_seconds::int)
WHERE o.id IN (
    SELECT r.id FROM (
        SELECT d.id, d.next_attempt_at,
               row_number() OVER (PARTITION BY COALESCE(d.destination_id::text, d.user_id::text) ORDER BY d.next_attempt_at, d.id) AS rn
        FROM notification_outbox d
        WHERE d.state = 'pending' AND d.next_attempt_at <= now()
    ) r
    WHERE r.rn <= @per_target::int
    ORDER BY r.next_attempt_at, r.id
    LIMIT @batch
)
RETURNING o.*;

-- name: RecordNotificationOutboxResult :exec
UPDATE notification_outbox
SET state = @state, attempts = @attempts, last_attempt_at = now(),
    sent_at = CASE WHEN @state::text = 'sent' THEN now() END,
    http_status = @http_status, error_class = @error_class,
    next_attempt_at = COALESCE(sqlc.narg(next_attempt_at)::timestamptz, next_attempt_at)
WHERE id = @id;

-- name: EmailsQueuedForUserSince :one
-- Emails to a person in the last hour that count against the hourly cap
-- (sent or still pending).
SELECT count(*) FROM notification_outbox
WHERE user_id = @user_id AND channel = 'email' AND state IN ('pending', 'sent') AND created_at > now() - interval '1 hour';

-- name: ListNotificationDeliveries :many
-- The last queue rows of one destination, newest first.
SELECT o.id, e.public_id AS event_public_id, e.event, o.state, o.attempts, o.created_at, o.last_attempt_at, o.next_attempt_at, o.sent_at,
       o.http_status, o.error_class
FROM notification_outbox o JOIN notification_events e ON e.id = o.event_id
WHERE o.destination_id = @destination_id
ORDER BY o.id DESC
LIMIT @page_size;

-- name: NotificationQueueStats :one
SELECT count(*) FILTER (WHERE state = 'pending')::bigint AS pending,
       COALESCE(min(created_at) FILTER (WHERE state = 'pending'), 'epoch'::timestamptz)::timestamptz AS oldest_pending_at,
       count(*) FILTER (WHERE state = 'failed' AND last_attempt_at > now() - interval '24 hours')::bigint AS failed_24h,
       count(*) FILTER (WHERE channel = 'email' AND state = 'sent' AND sent_at > now() - interval '24 hours')::bigint AS email_sent_24h,
       count(*) FILTER (WHERE channel = 'email' AND state = 'failed' AND last_attempt_at > now() - interval '24 hours')::bigint AS email_failed_24h
FROM notification_outbox
WHERE created_at > now() - interval '14 days';

-- name: NotificationDestinationStats :one
SELECT count(*) FILTER (WHERE scope = 'team')::bigint AS team_destinations,
       count(*) FILTER (WHERE scope = 'platform')::bigint AS platform_destinations,
       count(*) FILTER (WHERE disabled_reason = 'failures')::bigint AS stopped
FROM notification_destinations;

-- name: GetNotificationState :one
SELECT * FROM notification_state WHERE id = 1;

-- name: TouchNotificationRun :exec
UPDATE notification_state SET last_run_at = now() WHERE id = 1;

-- name: TouchNotificationKeyScan :exec
UPDATE notification_state SET key_scan_at = now() WHERE id = 1;

-- name: ExpireOldPendingNotificationOutbox :many
-- A delivery still undelivered 24 hours after it was queued fails as expired.
UPDATE notification_outbox SET state = 'failed', error_class = 'expired', last_attempt_at = now()
WHERE state = 'pending' AND created_at < now() - interval '24 hours'
RETURNING id, destination_id, channel;

-- Key expiry scan (docs/notifications.md): active keys and tokens made for
-- more than 7 days that expire within 7 days.

-- name: ListExpiringPersonalKeys :many
SELECT k.id, k.name, k.expires_at, k.user_id
FROM api_keys k JOIN users u ON u.id = k.user_id AND u.status = 'active'
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '7 days'
  AND k.expires_at - k.created_at > interval '7 days'
ORDER BY k.expires_at, k.id
LIMIT 500;

-- name: ListExpiringServiceAccountKeys :many
SELECT k.id, k.name, k.expires_at, sa.id AS service_account_id, sa.name AS service_account_name, sa.team_id
FROM service_account_keys k
JOIN service_accounts sa ON sa.id = k.service_account_id
JOIN teams t ON t.id = sa.team_id AND t.status = 'active'
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '7 days'
  AND k.expires_at - k.created_at > interval '7 days'
ORDER BY k.expires_at, k.id
LIMIT 500;

-- name: ListExpiringAutomationTokens :many
SELECT k.id, k.name, k.kind, k.expires_at, k.team_id
FROM automation_tokens k
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.expires_at <= now() + interval '7 days'
  AND k.expires_at - k.created_at > interval '7 days'
ORDER BY k.expires_at, k.id
LIMIT 500;

-- name: ListUserTeamRoles :many
-- The distinct roles a person holds in active teams.
SELECT DISTINCT m.role::text AS role FROM team_members m JOIN teams t ON t.id = m.team_id AND t.status = 'active' WHERE m.user_id = @user_id;

-- name: CountRecentAudit :one
-- Audit entries of an action within the last hour, of one target (target_id)
-- or one actor: the rate limit of tests.
SELECT count(*) FROM audit_log
WHERE action = @action AND occurred_at > now() - interval '1 hour'
  AND (sqlc.narg(target_id)::text IS NULL OR target_id = sqlc.narg(target_id)::text)
  AND (sqlc.narg(actor_user_id)::uuid IS NULL OR actor_user_id = sqlc.narg(actor_user_id)::uuid);

-- name: GetNotificationUser :one
SELECT id, email::text AS email, display_name, status, platform_role, email_verified FROM users WHERE id = @id;

-- name: SetUserEmailVerified :exec
-- Whether the identity provider vouched for the address at this sign-in.
UPDATE users SET email_verified = @verified WHERE id = @id AND email_verified IS DISTINCT FROM @verified;

-- name: LockPlatformNotificationDestinations :exec
-- Serialises creating platform destinations, so the limit of 10 holds.
SELECT pg_advisory_xact_lock(hashtextextended('omp.notification-destinations.platform', 0));

-- name: ListExpiringServerCertificates :many
-- Enabled servers of active teams whose client certificate (mTLS) expires
-- within 14 days and has not expired yet (decision 74); the fingerprint makes
-- a renewed certificate a new subject for its own warning.
SELECT s.id, s.slug, s.name, s.team_id, c.client_not_after, c.client_cert_sha256
FROM mcp_server_tls c
JOIN mcp_servers s ON s.id = c.server_id AND s.enabled
JOIN teams t ON t.id = s.team_id AND t.status = 'active'
WHERE c.client_not_after IS NOT NULL AND c.client_not_after > now() AND c.client_not_after <= now() + interval '14 days'
ORDER BY c.client_not_after, s.id
LIMIT 500;
