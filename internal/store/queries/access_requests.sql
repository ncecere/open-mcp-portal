-- Access requests are session-only. Reads resolve eligibility from live rows.
-- name: LockAccessRequestActors :many
SELECT * FROM users WHERE id = ANY(@ids::uuid[]) ORDER BY id FOR SHARE;

-- Serializes pending limits/cooldowns across all gateways for one requester.
-- name: LockAccessRequester :exec
SELECT pg_advisory_xact_lock(hashtextextended('omp.access-requester:' || sqlc.arg(user_id)::uuid::text, 0));

-- name: GetAccessRequest :one
SELECT * FROM access_requests WHERE id = $1;

-- name: LockAccessRequest :one
SELECT * FROM access_requests WHERE id = $1 FOR UPDATE;

-- name: AccessRequestReviewer :one
SELECT EXISTS (SELECT 1 FROM users u WHERE u.id = @user_id AND u.status = 'active'
    AND (u.platform_role = 'platform_admin' OR EXISTS (
        SELECT 1 FROM gateway_stewards gs WHERE gs.gateway_id = @gateway_id AND gs.user_id = u.id)))::bool;

-- name: ListRequestableGateways :many
SELECT g.id, g.name, g.description FROM gateways g
JOIN users actor ON actor.id = @actor_id AND actor.status = 'active'
WHERE g.owner_kind = 'platform' AND g.enabled AND g.access_requests_enabled
ORDER BY g.name, g.id LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer;

-- name: ListGatewayStewards :many
SELECT u.id, u.display_name, u.email::text AS email, u.status FROM gateway_stewards gs
JOIN users u ON u.id = gs.user_id WHERE gs.gateway_id = @gateway_id ORDER BY u.id;

-- name: DeleteGatewayStewards :exec
DELETE FROM gateway_stewards WHERE gateway_id = $1;

-- name: InsertGatewaySteward :exec
INSERT INTO gateway_stewards(gateway_id, user_id) VALUES ($1, $2);

-- name: SetGatewayAccessRequests :one
UPDATE gateways SET access_requests_enabled = @enabled, revision = revision + 1,
    updated_by = @actor_id, updated_at = clock_timestamp()
WHERE id = @gateway_id RETURNING *;

-- name: PendingAccessRequestsForUser :one
SELECT count(*)::bigint FROM access_requests WHERE requester_user_id = @user_id AND status = 'pending';

-- name: AccessRequestCooldown :one
SELECT EXISTS (SELECT 1 FROM access_requests WHERE gateway_id = @gateway_id AND requester_user_id = @requester_user_id
    AND subject_kind = @subject_kind AND team_id IS NOT DISTINCT FROM sqlc.narg(team_id)::uuid
    AND status = 'denied' AND decided_at > clock_timestamp() - interval '24 hours')::bool;

-- name: InsertAccessRequest :one
INSERT INTO access_requests(gateway_id, requester_user_id, subject_kind, team_id, reason)
VALUES (@gateway_id, @requester_user_id, @subject_kind, sqlc.narg(team_id), @reason) RETURNING *;

-- name: DecideAccessRequest :one
UPDATE access_requests SET status = @status, decided_by = sqlc.narg(decided_by), decided_at = clock_timestamp(),
    decision_note = @decision_note, grant_id = sqlc.narg(grant_id), grant_expires_at = sqlc.narg(grant_expires_at)
WHERE id = @id AND status = 'pending' RETURNING *;

-- name: ListAccessRequests :many
SELECT ar.* FROM access_requests ar JOIN users actor ON actor.id = @actor_id AND actor.status = 'active'
WHERE ((NOT @review::bool AND ar.requester_user_id = actor.id)
    OR (@review::bool AND ar.requester_user_id <> actor.id AND (actor.platform_role = 'platform_admin'
        OR EXISTS (SELECT 1 FROM gateway_stewards gs WHERE gs.gateway_id = ar.gateway_id AND gs.user_id = actor.id))))
    AND (NOT @pending_only::bool OR ar.status = 'pending')
ORDER BY ar.created_at DESC, ar.id DESC LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer;

-- name: CountActionableAccessRequests :one
SELECT count(*)::bigint FROM access_requests ar
JOIN gateways g ON g.id = ar.gateway_id AND g.enabled AND g.access_requests_enabled
JOIN users actor ON actor.id = @actor_id AND actor.status = 'active'
JOIN users requester ON requester.id = ar.requester_user_id AND requester.status = 'active'
WHERE ar.status = 'pending' AND ar.requester_user_id <> actor.id
    AND (actor.platform_role = 'platform_admin' OR EXISTS (
        SELECT 1 FROM gateway_stewards gs WHERE gs.gateway_id = ar.gateway_id AND gs.user_id = actor.id))
    AND (ar.subject_kind = 'user' OR EXISTS (SELECT 1 FROM teams t
        JOIN team_members m ON m.team_id = t.id AND m.user_id = ar.requester_user_id AND m.role IN ('owner','admin')
        WHERE t.id = ar.team_id AND t.status = 'active'));

-- name: AccessRequestRecipients :many
SELECT u.id FROM access_requests ar
JOIN gateways g ON g.id = ar.gateway_id
JOIN users u ON u.status = 'active'
WHERE ar.id = @request_id AND
    ((NOT @requested::bool AND ar.status IN ('approved','denied') AND u.id = ar.requester_user_id)
    OR (@requested::bool AND ar.status = 'pending' AND g.enabled AND g.access_requests_enabled
        AND u.id <> ar.requester_user_id AND (u.platform_role = 'platform_admin' OR EXISTS (
            SELECT 1 FROM gateway_stewards gs WHERE gs.gateway_id = ar.gateway_id AND gs.user_id = u.id))
        AND EXISTS (SELECT 1 FROM users requester WHERE requester.id = ar.requester_user_id AND requester.status = 'active')
        AND (ar.subject_kind = 'user' OR EXISTS (SELECT 1 FROM teams t JOIN team_members m ON m.team_id = t.id
            WHERE t.id = ar.team_id AND t.status = 'active' AND m.user_id = ar.requester_user_id AND m.role IN ('owner','admin')))))
ORDER BY u.id;
