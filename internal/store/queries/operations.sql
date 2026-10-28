-- Phase 6 (docs/phase6-operations.md): rate limits, payload capture,
-- retention, usage rollups and key rotation.

-- name: HitRateLimits :many
-- Counts one event in the current one-minute window (the database clock)
-- of every bucket, in sorted order so concurrent requests lock rows in the
-- same order. reset_seconds is how long until the window ends.
INSERT INTO rate_limit_counters AS c (bucket, window_start)
SELECT b.bucket, date_trunc('minute', now())
FROM unnest(@buckets::text[]) AS b(bucket)
ORDER BY b.bucket
ON CONFLICT (bucket, window_start) DO UPDATE SET count = c.count + 1
RETURNING c.bucket, c.count,
    EXTRACT(EPOCH FROM (c.window_start + interval '1 minute' - clock_timestamp()))::float8 AS reset_seconds;

-- name: DeleteOldRateLimitCounters :execrows
DELETE FROM rate_limit_counters WHERE window_start < now() - interval '2 minutes';

-- name: GetLimitSettings :one
SELECT * FROM limit_settings WHERE id = 1;

-- name: LockLimitSettings :one
SELECT * FROM limit_settings WHERE id = 1 FOR UPDATE;

-- name: UpdateLimitSettings :one
UPDATE limit_settings
SET items = @items, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: SetTeamLimitOverrides :one
UPDATE teams SET limit_overrides = @overrides, revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: CountCappedTeams :one
-- Active teams whose override of a key is above a ceiling.
SELECT count(*) FROM teams
WHERE status = 'active' AND jsonb_typeof(limit_overrides -> @key::text) = 'number'
  AND (limit_overrides ->> @key::text)::bigint > @ceiling::bigint;

-- name: CountCappedGateways :one
SELECT count(*) FROM gateways WHERE rate_limit_per_minute > @ceiling::bigint;

-- name: GetCaptureSettings :one
SELECT * FROM capture_settings WHERE id = 1;

-- name: LockCaptureSettings :one
SELECT * FROM capture_settings WHERE id = 1 FOR UPDATE;

-- name: UpdateCapturePatterns :one
UPDATE capture_settings
SET patterns = @patterns, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: SetMCPServerCapture :exec
-- Sets the capture switch of a server (the caller bumps the revision with
-- the rest of the change).
UPDATE mcp_servers SET capture_payloads = @capture_payloads WHERE id = @id;

-- name: InsertMCPCallPayload :exec
INSERT INTO mcp_call_payloads (
    call_id, occurred_at, gateway_team_id, server_team_id, by_gateway, by_server, arguments_cipher, result_cipher,
    arguments_bytes, result_bytes, arguments_truncated, result_truncated, arguments_redactions, result_redactions
) VALUES (
    @call_id, @occurred_at, @gateway_team_id, @server_team_id, @by_gateway, @by_server, @arguments_cipher, @result_cipher,
    @arguments_bytes, @result_bytes, @arguments_truncated, @result_truncated, @arguments_redactions, @result_redactions
);

-- name: GetMCPCallPayload :one
SELECT * FROM mcp_call_payloads WHERE call_id = $1;

-- name: GetRetentionSettings :one
SELECT * FROM retention_settings WHERE id = 1;

-- name: LockRetentionSettings :one
SELECT * FROM retention_settings WHERE id = 1 FOR UPDATE;

-- name: UpdateRetentionPeriods :one
UPDATE retention_settings
SET periods = @periods, revision = revision + 1, updated_by = @updated_by, updated_at = now()
WHERE id = 1
RETURNING *;

-- name: SetRetentionLastRun :exec
UPDATE retention_settings SET last_run = @last_run WHERE id = 1;

-- name: SetTeamRetentionOverrides :one
UPDATE teams SET retention_overrides = @overrides, revision = revision + 1, updated_at = now()
WHERE id = @id
RETURNING *;

-- name: PurgeMCPCallPayloads :execrows
-- One batch of captured payloads older than their period: the shortest of
-- the captured_payloads periods of the teams involved (the gateway's and
-- the server's, while they exist), else the platform period.
WITH doomed AS (
    SELECT p.call_id
    FROM mcp_call_payloads p
    LEFT JOIN teams gt ON gt.id = p.gateway_team_id
    LEFT JOIN teams st ON st.id = p.server_team_id
    WHERE p.occurred_at < now() - make_interval(days => COALESCE(LEAST(
        CASE WHEN gt.id IS NOT NULL THEN COALESCE((gt.retention_overrides ->> 'captured_payloads')::int, @platform_days::int) END,
        CASE WHEN st.id IS NOT NULL THEN COALESCE((st.retention_overrides ->> 'captured_payloads')::int, @platform_days::int) END),
        @platform_days::int))
    ORDER BY p.call_id
    LIMIT @batch_size
    FOR UPDATE OF p SKIP LOCKED
)
DELETE FROM mcp_call_payloads WHERE call_id IN (SELECT call_id FROM doomed);

-- name: PurgeMCPCalls :one
-- Missing functions are a migration error, never a direct DELETE fallback.
SELECT public.omp_purge_mcp_calls(@watermark::timestamptz, @platform_days::int, @batch_size::int)::bigint AS deleted;

-- name: PurgeAuditLog :one
SELECT public.omp_purge_audit_log(@days::int, @batch_size::int)::bigint AS deleted;

-- name: PurgeUsageRollups :execrows
WITH doomed AS (
    SELECT id FROM usage_hourly WHERE hour < now() - make_interval(days => @days::int) ORDER BY id LIMIT @batch_size
)
DELETE FROM usage_hourly WHERE id IN (SELECT id FROM doomed);

-- name: GetUsageRollupState :one
SELECT * FROM usage_rollup_state WHERE id = 1;

-- name: SetUsageRolledUpTo :exec
UPDATE usage_rollup_state SET rolled_up_to = @rolled_up_to, updated_at = now() WHERE id = 1;

-- name: OldestMCPCall :one
SELECT COALESCE(min(occurred_at), now())::timestamptz AS oldest FROM mcp_calls;

-- name: DeleteUsageHour :execrows
DELETE FROM usage_hourly WHERE hour = @hour;

-- name: InsertUsageHour :execrows
-- Aggregates one hour of call records. latency_buckets counts calls per
-- bucket of internal/usage.LatencyBucketsMs (upper bounds), then +Inf.
INSERT INTO usage_hourly (
    hour, gateway_id, gateway_slug, gateway_name, gateway_team_id, server_id, server_slug, server_name, server_team_id,
    capability_id, exposed_name, method, principal_kind, service_account_team_id, outcome,
    calls, latency_sum_ms, latency_buckets, request_bytes, response_bytes
)
SELECT $1::timestamptz, c.gateway_id, max(c.gateway_slug), max(c.gateway_name), c.gateway_team_id, c.server_id,
       max(c.server_slug), max(c.server_name), c.server_team_id, c.capability_id, c.exposed_name, c.method,
       c.principal_kind, c.service_account_team_id, c.outcome,
       count(*), sum(c.latency_ms)::bigint,
       ARRAY[
           count(*) FILTER (WHERE c.latency_ms <= 5),
           count(*) FILTER (WHERE c.latency_ms > 5 AND c.latency_ms <= 10),
           count(*) FILTER (WHERE c.latency_ms > 10 AND c.latency_ms <= 25),
           count(*) FILTER (WHERE c.latency_ms > 25 AND c.latency_ms <= 50),
           count(*) FILTER (WHERE c.latency_ms > 50 AND c.latency_ms <= 100),
           count(*) FILTER (WHERE c.latency_ms > 100 AND c.latency_ms <= 250),
           count(*) FILTER (WHERE c.latency_ms > 250 AND c.latency_ms <= 500),
           count(*) FILTER (WHERE c.latency_ms > 500 AND c.latency_ms <= 1000),
           count(*) FILTER (WHERE c.latency_ms > 1000 AND c.latency_ms <= 2500),
           count(*) FILTER (WHERE c.latency_ms > 2500 AND c.latency_ms <= 5000),
           count(*) FILTER (WHERE c.latency_ms > 5000 AND c.latency_ms <= 10000),
           count(*) FILTER (WHERE c.latency_ms > 10000 AND c.latency_ms <= 30000),
           count(*) FILTER (WHERE c.latency_ms > 30000 AND c.latency_ms <= 60000),
           count(*) FILTER (WHERE c.latency_ms > 60000 AND c.latency_ms <= 120000),
           count(*) FILTER (WHERE c.latency_ms > 120000)
       ]::bigint[],
       sum(c.request_bytes)::bigint, sum(c.response_bytes)::bigint
FROM mcp_calls c
WHERE c.occurred_at >= $1::timestamptz AND c.occurred_at < $1::timestamptz + interval '1 hour'
GROUP BY c.gateway_id, c.gateway_team_id, c.server_id, c.server_team_id, c.capability_id, c.exposed_name, c.method,
         c.principal_kind, c.service_account_team_id, c.outcome;

-- name: StampAPIKeyPeppers :execrows
UPDATE api_keys SET pepper_id = @pepper_id WHERE pepper_id IS NULL;

-- name: StampServiceAccountKeyPeppers :execrows
UPDATE service_account_keys SET pepper_id = @pepper_id WHERE pepper_id IS NULL;

-- name: StampOAuthTokenPeppers :execrows
UPDATE oauth_tokens SET pepper_id = @pepper_id WHERE pepper_id IS NULL;

-- name: RehashAPIKey :execrows
-- Moves a key matched with the previous pepper to the current one (only if
-- its digest is still the old one).
UPDATE api_keys SET digest = @digest, pepper_id = @pepper_id WHERE id = @id AND digest = @old_digest;

-- name: RehashServiceAccountKey :execrows
UPDATE service_account_keys SET digest = @digest, pepper_id = @pepper_id WHERE id = @id AND digest = @old_digest;

-- name: KeysNotOnPepper :many
-- Usable keys (unrevoked, unexpired) whose digest is not on a pepper: personal
-- API keys, service account keys and automation tokens, with their owner or team.
SELECT 'api_key'::text AS kind, k.id, k.name, u.email::text AS owner, ''::text AS team_slug, k.pepper_id,
       k.last_used_at, k.created_at
FROM api_keys k JOIN users u ON u.id = k.user_id
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.pepper_id IS DISTINCT FROM @pepper_id::bytea
UNION ALL
SELECT 'service_account_key'::text, k.id, sa.name || ' · ' || k.name, ''::text, t.slug, k.pepper_id,
       k.last_used_at, k.created_at
FROM service_account_keys k JOIN service_accounts sa ON sa.id = k.service_account_id JOIN teams t ON t.id = sa.team_id
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.pepper_id IS DISTINCT FROM @pepper_id::bytea
UNION ALL
SELECT 'automation_token'::text, k.id, k.name, ''::text, COALESCE(t.slug, ''), k.pepper_id, k.last_used_at, k.created_at
FROM automation_tokens k LEFT JOIN teams t ON t.id = k.team_id
WHERE k.revoked_at IS NULL AND k.expires_at > now() AND k.pepper_id IS DISTINCT FROM @pepper_id::bytea
ORDER BY 1, 3;

-- name: CountOAuthTokensNotOnPepper :one
SELECT count(*) FROM oauth_tokens WHERE expires_at > now() AND pepper_id IS DISTINCT FROM @pepper_id::bytea;
