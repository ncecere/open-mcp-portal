-- Authority reads under the approval fence MUST NOT lock authority rows.
-- name: ApprovalEligibleReviewers :many
WITH eligible AS (
 SELECT u.id, u.platform_role,
   (CASE WHEN EXISTS (SELECT 1 FROM approval_rule_approvers a WHERE a.rule_id = @rule_id)
    THEN EXISTS (SELECT 1 FROM approval_rule_approvers a WHERE a.rule_id = @rule_id
                 AND (a.user_id = u.id OR a.group_name = ANY(u.groups)))
    ELSE EXISTS (SELECT 1 FROM mcp_servers s JOIN teams t ON t.id = s.team_id
                 JOIN team_members m ON m.team_id = t.id
                 WHERE s.id = @server_id AND t.status = 'active' AND m.user_id = u.id
                   AND m.role IN ('owner','admin')) END)::boolean AS primary_reviewer
 FROM users u
 WHERE u.status = 'active'
   AND NOT (@requester_kind::text = 'user' AND u.id = @requester_id)
   AND (@allow_service_account_admins::boolean OR @requester_kind::text <> 'service_account'
        OR NOT EXISTS (SELECT 1 FROM service_accounts sa JOIN team_members m ON m.team_id = sa.team_id
                       JOIN teams t ON t.id = sa.team_id
                       WHERE sa.id = @requester_id AND t.status = 'active'
                         AND m.user_id = u.id AND m.role IN ('owner','admin')))
)
SELECT id FROM eligible WHERE primary_reviewer
 OR (platform_role = 'platform_admin' AND NOT EXISTS (SELECT 1 FROM eligible WHERE primary_reviewer))
ORDER BY id;

-- name: ApprovalRequesterLive :one
SELECT (EXISTS (
 SELECT 1 FROM gateways g JOIN gateway_capabilities gc ON gc.gateway_id = g.id
 JOIN mcp_capabilities c ON c.id = gc.capability_id
 JOIN mcp_servers s ON s.id = c.server_id JOIN teams st ON st.id = s.team_id
 LEFT JOIN teams gt ON gt.id = g.team_id
 WHERE g.id = @gateway_id AND c.id = @capability_id AND s.id = @server_id
   AND g.enabled AND s.enabled AND st.status = 'active' AND COALESCE(gt.status,'active') = 'active'
   AND NOT (s.lifecycle = 'sunset' OR (s.sunset_at IS NOT NULL AND s.sunset_at <= clock_timestamp()))
   AND (CASE s.sensitivity WHEN 'public' THEN 0 WHEN 'internal' THEN 1 WHEN 'confidential' THEN 2 ELSE 3 END)
       <= (CASE g.max_sensitivity WHEN 'public' THEN 0 WHEN 'internal' THEN 1 WHEN 'confidential' THEN 2 ELSE 3 END)
   AND c.gone_at IS NULL AND c.kind = 'tool' AND c.fingerprint = @fingerprint
   AND ((g.owner_kind = 'team' AND g.team_id = s.team_id)
        OR (s.publish_state = 'published' AND c.approved_fingerprint = c.fingerprint))
) AND (
 (@requester_kind::text = 'user' AND EXISTS (SELECT 1 FROM users ru WHERE ru.id = @requester_id AND ru.status = 'active'))
 OR (@requester_kind::text = 'service_account' AND EXISTS (
   SELECT 1 FROM service_accounts sa JOIN teams t ON t.id = sa.team_id
   WHERE sa.id = @requester_id AND sa.enabled AND t.status = 'active' AND sa.team_id = sqlc.narg(requester_team_id)::uuid))
))::boolean AS live;

-- name: ApprovalSelectionRole :one
SELECT gc.min_team_role FROM gateway_capabilities gc
JOIN mcp_capabilities c ON c.id=gc.capability_id
JOIN mcp_servers s ON s.id=c.server_id
WHERE gc.gateway_id = sqlc.arg(gateway_id) AND gc.capability_id = sqlc.arg(capability_id)
 AND c.tool_class IS NOT DISTINCT FROM sqlc.narg(tool_class)::text
 AND COALESCE(CASE WHEN gc.base_fingerprint IS NOT NULL THEN gc.name_override END,s.slug||'__'||c.name) = sqlc.arg(exposed_name)
 AND (gc.base_fingerprint IS NULL OR gc.base_fingerprint=c.fingerprint);

-- name: ApprovalRequesterAgent :one
SELECT EXISTS (SELECT 1 FROM service_accounts sa JOIN teams t ON t.id = sa.team_id
 JOIN team_members m ON m.team_id = sa.team_id JOIN users u ON u.id = m.user_id
 WHERE sa.id = @service_account_id AND sa.team_id = @team_id AND t.status = 'active'
 AND u.id = @user_id AND u.status = 'active' AND m.role IN ('owner','admin'))::boolean AS allowed;

-- name: ApprovalTarget :one
SELECT s.id, s.team_id, 'server'::text AS target_kind FROM mcp_servers s WHERE s.id = @target_id AND @target_kind::text = 'server'
UNION ALL
SELECT g.id, COALESCE(g.team_id,'00000000-0000-0000-0000-000000000000'::uuid) AS team_id, 'gateway'::text AS target_kind FROM gateways g WHERE g.id = @target_id AND @target_kind::text = 'gateway';

-- name: ApprovalCapabilityBelongs :one
SELECT EXISTS (SELECT 1 FROM mcp_capabilities c WHERE c.id = @capability_id AND c.kind = 'tool' AND c.gone_at IS NULL
 AND ((@target_kind::text = 'server' AND c.server_id = @target_id)
 OR (@target_kind::text = 'gateway' AND EXISTS (SELECT 1 FROM gateway_capabilities gc WHERE gc.gateway_id = @target_id AND gc.capability_id = c.id))))::boolean AS allowed;

-- name: ApprovalRulesForTarget :many
SELECT * FROM approval_rules WHERE target_kind = @target_kind AND target_id = @target_id ORDER BY id;

-- name: ApprovalRulesForScope :many
SELECT * FROM approval_rules WHERE team_id IS NOT DISTINCT FROM sqlc.narg(team_id)::uuid
ORDER BY created_at DESC, id DESC LIMIT @page_limit::integer OFFSET @page_offset::integer;

-- Metadata-only bounded keyset scan. Services apply visibility BEFORE offset/limit.
-- name: ApprovalRequestMetadataBatch :many
SELECT id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
 gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,
 capability_fingerprint,server_origin,preview_truncated,preview_redacted,
 status,review_revision,decided_by,created_at,expires_at,valid_until,decided_at,used_at,terminal_at,
 (preview_cipher IS NOT NULL)::boolean AS has_preview
FROM approval_requests
WHERE (sqlc.narg(before_time)::timestamptz IS NULL OR (created_at,id) < (sqlc.narg(before_time)::timestamptz,sqlc.narg(before_id)::uuid))
ORDER BY created_at DESC,id DESC LIMIT @page_limit::integer;

-- The requester advisory lock is already held. Materialize stale/expired
-- requests before counting quota, including bindings from an OLD epoch.
-- name: ApprovalStaleRequesterRequests :many
SELECT * FROM approval_requests
WHERE requester_kind = sqlc.arg(requester_kind) AND requester_id = sqlc.arg(requester_id)
 AND status IN ('pending','approved')
 AND (context_epoch <> sqlc.arg(context_epoch)::bigint OR expires_at <= sqlc.arg(at_time)::timestamptz
      OR valid_until <= sqlc.arg(at_time)::timestamptz)
ORDER BY id LIMIT 200 FOR UPDATE;

-- name: ApprovalCleanupCandidates :many
SELECT id FROM approval_requests WHERE status IN ('pending','approved')
 AND (context_epoch <> omp_private.omp_current_approval_context()
      OR expires_at <= @at_time::timestamptz OR valid_until <= @at_time::timestamptz)
ORDER BY expires_at,id LIMIT @batch_size::integer FOR UPDATE SKIP LOCKED;
