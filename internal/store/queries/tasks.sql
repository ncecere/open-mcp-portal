-- Task handles are private lookup keys, not authority. Callers must re-resolve
-- current principal/credential/offer/no-rule/deadlines before these operations.
-- Positional parameters avoid named-parameter rewrite ambiguity in this file;
-- integration tests exercise each CAS and its generated parameter ordering.

-- name: MCPTaskClock :one
SELECT clock_timestamp()::timestamptz AS at_time;

-- name: MCPTaskRootBelongsToPrincipal :one
-- Association only, NOT live authorization/scopes/status/expiry. OAuth binds
-- the stable grant and original gateway, never a short-lived token UUID.
SELECT EXISTS (
    SELECT 1 FROM api_keys WHERE $1::text = 'user' AND $3::text = 'api_key' AND user_id = $2::uuid AND id = $4::uuid
    UNION ALL
    SELECT 1 FROM oauth_grants WHERE $1::text = 'user' AND $3::text = 'oauth' AND user_id = $2::uuid AND id = $4::uuid AND gateway_id = $5::uuid
    UNION ALL
    SELECT 1 FROM service_account_keys WHERE $1::text = 'service_account' AND $3::text = 'service_account' AND service_account_id = $2::uuid AND id = $4::uuid
) AS belongs;

-- name: LockMCPTaskPrincipal :exec
-- Transaction-scoped capacity serialization only; release before any network.
SELECT pg_advisory_xact_lock($1::bigint);

-- name: CountUserOpenMCPTasks :one
SELECT count(*)::bigint FROM mcp_tasks
WHERE user_id = $1 AND expires_at > clock_timestamp()
  AND status IN ('reserved','working','input_required')
  AND (status <> 'reserved' OR reservation_deadline > clock_timestamp());

-- name: CountServiceAccountOpenMCPTasks :one
SELECT count(*)::bigint FROM mcp_tasks
WHERE service_account_id = $1 AND expires_at > clock_timestamp()
  AND status IN ('reserved','working','input_required')
  AND (status <> 'reserved' OR reservation_deadline > clock_timestamp());

-- name: InsertMCPTaskReservation :one
-- Unused principal/credential UUIDs are zero and explicitly stored as NULL.
-- TTL/reservation parameters are integer milliseconds, bounded before SQL and
-- independently ceiling-checked by the table. One statement timestamp is used.
INSERT INTO mcp_tasks(id,handle_digest,principal_kind,user_id,service_account_id,credential_kind,
    api_key_id,oauth_grant_id,service_account_key_id,gateway_id,server_id,capability_id,
    created_at,updated_at,ceiling_at,expires_at,reservation_deadline,next_poll_at)
VALUES ($1,$2,$3,NULLIF($4::uuid,'00000000-0000-0000-0000-000000000000'::uuid),
    NULLIF($5::uuid,'00000000-0000-0000-0000-000000000000'::uuid),$6,
    NULLIF($7::uuid,'00000000-0000-0000-0000-000000000000'::uuid),
    NULLIF($8::uuid,'00000000-0000-0000-0000-000000000000'::uuid),
    NULLIF($9::uuid,'00000000-0000-0000-0000-000000000000'::uuid),$10,$11,$12,
    statement_timestamp(),statement_timestamp(),statement_timestamp() + $13::bigint * interval '1 millisecond',
    statement_timestamp() + $13::bigint * interval '1 millisecond',
    statement_timestamp() + least($14::bigint,$13::bigint) * interval '1 millisecond',statement_timestamp())
RETURNING *;

-- name: GetMCPTaskByDigest :one
SELECT * FROM mcp_tasks WHERE handle_digest = $1 AND expires_at > clock_timestamp()
  AND status <> 'reserved';

-- name: GetMCPTaskForUpdate :one
SELECT * FROM mcp_tasks WHERE id = $1 AND expires_at > clock_timestamp() FOR UPDATE;

-- name: PrepareMCPTaskReservation :one
UPDATE mcp_tasks SET binding = $3, binding_digest = $4,
    state_cipher = $5, revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND status = 'reserved'
  AND reservation_deadline > clock_timestamp() AND expires_at > clock_timestamp()
RETURNING *;

-- name: ActivateMCPTaskReservation :one
UPDATE mcp_tasks SET status = $3, state_cipher = $4,
    upstream_created_at = $5, upstream_updated_at = $6,
    expires_at = least(expires_at,$7::timestamptz), poll_interval_ms = $8,
    reservation_deadline = NULL, revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND status = 'reserved'
  AND binding IS NOT NULL AND state_cipher IS NOT NULL
  AND reservation_deadline > clock_timestamp() AND expires_at > clock_timestamp()
  AND $7::timestamptz > clock_timestamp()
RETURNING *;

-- name: AcquireMCPTaskOperation :one
UPDATE mcp_tasks SET operation_id = $3,
    operation_deadline = least(expires_at,clock_timestamp() + $4::bigint * interval '1 millisecond'),
    next_poll_at = CASE WHEN $5::boolean THEN clock_timestamp() + poll_interval_ms * interval '1 millisecond' ELSE next_poll_at END,
    revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND status <> 'reserved'
  AND expires_at > clock_timestamp()
  AND (operation_id IS NULL OR operation_deadline <= clock_timestamp())
  -- Pacing bounds polling of unfinished work; a terminal result is still
  -- fetched (never stored) on each authorized get.
  AND (NOT $5::boolean OR next_poll_at <= clock_timestamp() OR status IN ('completed','failed','cancelled'))
RETURNING *;

-- name: CommitMCPTaskInputState :one
-- Commit attempted input before its one transport; failure never restores it.
UPDATE mcp_tasks SET state_cipher = $4, revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND operation_id = $3
  AND operation_deadline > clock_timestamp() AND expires_at > clock_timestamp()
RETURNING *;

-- name: FinishMCPTaskOperation :one
UPDATE mcp_tasks SET status = $4, state_cipher = $5,
    upstream_updated_at = $6,
    expires_at = least(expires_at,$7::timestamptz), poll_interval_ms = $8,
    -- Pace from the latest observation using its (bounded) interval.
    next_poll_at = clock_timestamp() + $8::int * interval '1 millisecond',
    operation_id = NULL, operation_deadline = NULL, revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND operation_id = $3
  AND operation_deadline > clock_timestamp() AND expires_at > clock_timestamp()
  AND $7::timestamptz > clock_timestamp()
RETURNING *;

-- name: ReleaseMCPTaskOperation :execrows
UPDATE mcp_tasks SET operation_id = NULL, operation_deadline = NULL,
    revision = revision+1, updated_at = clock_timestamp()
WHERE id = $1 AND revision = $2::bigint AND operation_id = $3;

-- name: DeleteMCPTaskReservation :execrows
DELETE FROM mcp_tasks WHERE id = $1 AND status = 'reserved' AND revision = $2::bigint;

-- name: PruneExpiredMCPTasks :execrows
DELETE FROM mcp_tasks WHERE id IN (
    SELECT id FROM mcp_tasks
    WHERE expires_at <= clock_timestamp() OR (status='reserved' AND reservation_deadline <= clock_timestamp())
    ORDER BY expires_at,id LIMIT $1::int FOR UPDATE SKIP LOCKED
);

-- name: SetMCPServerTaskSupport :exec
UPDATE mcp_servers SET supports_tasks = $2 WHERE id = $1;
