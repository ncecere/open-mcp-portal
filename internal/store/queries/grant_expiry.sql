-- Expiry is enforced by every effective-grant read, never by this cleanup.
-- name: GatewayGrantClock :one
SELECT clock_timestamp()::timestamptz AS at_time;

-- name: DeleteExpiredSubjectGrant :many
DELETE FROM gateway_grants WHERE gateway_id = @gateway_id AND subject_kind = @subject_kind
    AND team_id IS NOT DISTINCT FROM sqlc.narg(team_id)::uuid
    AND user_id IS NOT DISTINCT FROM sqlc.narg(user_id)::uuid
    AND group_name IS NOT DISTINCT FROM sqlc.narg(group_name)::text
    AND expires_at <= clock_timestamp()
RETURNING *;

-- name: DeleteExpiredGatewayGrants :many
DELETE FROM gateway_grants
WHERE id IN (SELECT id FROM gateway_grants
    WHERE expires_at <= clock_timestamp()
      AND (sqlc.narg(gateway_id)::uuid IS NULL OR gateway_id = sqlc.narg(gateway_id))
    ORDER BY expires_at, id LIMIT sqlc.arg(batch_size)::integer
    FOR UPDATE SKIP LOCKED)
RETURNING *;
