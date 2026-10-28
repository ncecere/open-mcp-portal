-- Queues are metadata hints, never authority. All reads use one read-only
-- repeatable-read snapshot, WITHOUT the authority fence or actor row locks.
-- Filter requester/reviewer candidates in SQL BEFORE keyset pagination. The
-- service still applies exact live permissions, including reviewer fallback
-- and separation of duties, to at most 200 candidates per call.
-- name: ApprovalQueueCandidates :many
WITH requester_principals AS (
 SELECT 'user'::text AS kind, sqlc.arg(actor_id)::uuid AS id
 UNION ALL
 SELECT 'service_account'::text, sa.id
 FROM service_accounts sa
 JOIN teams t ON t.id = sa.team_id AND t.status = 'active'
 JOIN team_members m ON m.team_id = t.id
 WHERE m.user_id = sqlc.arg(actor_id) AND m.role IN ('owner','admin')
), candidate_ids AS (
 SELECT r.id FROM approval_requests r
 JOIN requester_principals p ON r.requester_kind = p.kind AND r.requester_id = p.id
 WHERE sqlc.arg(queue_view)::text = 'requested'
   AND (r.requester_kind = 'user' OR EXISTS (
     SELECT 1 FROM service_accounts sa WHERE sa.id = r.requester_id AND sa.team_id = r.requester_team_id))
 UNION ALL
 SELECT r.id FROM approval_requests r
 WHERE sqlc.arg(queue_view)::text = 'actionable'
   AND r.status = 'pending' AND r.expires_at > sqlc.arg(at_time)::timestamptz
   AND r.context_epoch = sqlc.arg(context_epoch)::bigint
   AND NOT (r.requester_kind = 'user' AND r.requester_id = sqlc.arg(actor_id))
   AND (
     sqlc.arg(platform_admin)::boolean
     OR EXISTS (SELECT 1 FROM approval_rule_approvers a JOIN users u ON u.id = sqlc.arg(actor_id)
                WHERE a.rule_id = r.rule_id AND (a.user_id = u.id OR a.group_name = ANY(u.groups)))
     OR EXISTS (SELECT 1 FROM mcp_servers s JOIN teams t ON t.id = s.team_id AND t.status = 'active'
                JOIN team_members m ON m.team_id = t.id
                WHERE s.id = r.server_id AND m.user_id = sqlc.arg(actor_id) AND m.role IN ('owner','admin'))
   )
)
SELECT r.id,r.rule_id,r.rule_revision,r.context_epoch,r.requester_kind,r.requester_id,r.requester_team_id,
 r.gateway_id,r.server_id,r.capability_id,r.exposed_name,r.tool_class,r.args_digest,r.binding_digest,
 r.capability_fingerprint,r.server_origin,r.preview_truncated,r.preview_redacted,
 r.status,r.review_revision,r.decided_by,r.created_at,r.expires_at,r.valid_until,r.decided_at,r.used_at,r.terminal_at,
 (r.preview_cipher IS NOT NULL)::boolean AS has_preview
FROM approval_requests r JOIN candidate_ids c ON c.id = r.id
WHERE (sqlc.narg(before_time)::timestamptz IS NULL OR (r.created_at,r.id) < (sqlc.narg(before_time)::timestamptz,sqlc.narg(before_id)::uuid))
ORDER BY r.created_at DESC,r.id DESC LIMIT sqlc.arg(candidate_limit)::integer;

-- Renewal hint lookup must not use the detail projection (which includes
-- preview_cipher). Lists only need the most recent ID for a binding.
-- name: ApprovalQueueLatestBindingID :one
SELECT id FROM approval_requests WHERE binding_digest = $1 ORDER BY created_at DESC,id DESC LIMIT 1;
