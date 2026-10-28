-- Attention is a metadata-only hint, not decision authority. Run in the same
-- read-only repeatable-read snapshot as the fresh actor and context reads.
-- At the current epoch, Begin's structural authority and winning-rule checks
-- remain valid: all semantic authority changes invalidate the epoch. Absolute
-- request expiry is checked here; credential expiry belongs to dispatch.
-- name: ApprovalAttention :many
WITH pending AS MATERIALIZED (
 SELECT r.id,r.rule_id,r.requester_kind,r.requester_id,r.exposed_name,r.created_at,
        s.team_id,rule.allow_service_account_admins
 FROM approval_requests r
 JOIN approval_rules rule ON rule.id=r.rule_id AND rule.revision=r.rule_revision AND rule.enabled
 JOIN mcp_servers s ON s.id=r.server_id
 WHERE r.status='pending' AND r.expires_at > sqlc.arg(at_time)::timestamptz
   AND r.context_epoch=sqlc.arg(context_epoch)::bigint
   AND (sqlc.narg(team_id)::uuid IS NULL OR s.team_id=sqlc.narg(team_id)::uuid)
), primary_candidates AS (
 SELECT p.id,u.id AS user_id FROM pending p
 JOIN approval_rule_approvers a ON a.rule_id=p.rule_id
 JOIN users u ON (a.user_id=u.id OR a.group_name=ANY(u.groups)) AND u.status='active'
 UNION
 SELECT p.id,u.id AS user_id FROM pending p
 JOIN teams t ON t.id=p.team_id AND t.status='active'
 JOIN team_members m ON m.team_id=t.id AND m.role IN ('owner','admin')
 JOIN users u ON u.id=m.user_id AND u.status='active'
 WHERE NOT EXISTS (SELECT 1 FROM approval_rule_approvers a WHERE a.rule_id=p.rule_id)
), primary_reviewers AS MATERIALIZED (
 SELECT c.id,c.user_id FROM primary_candidates c JOIN pending p ON p.id=c.id
 WHERE NOT (p.requester_kind='user' AND c.user_id=p.requester_id)
   AND (p.allow_service_account_admins OR p.requester_kind<>'service_account'
     OR NOT EXISTS (SELECT 1 FROM service_accounts sa JOIN teams t ON t.id=sa.team_id
                    JOIN team_members m ON m.team_id=t.id
                    WHERE sa.id=p.requester_id AND t.status='active'
                      AND m.user_id=c.user_id AND m.role IN ('owner','admin')))
), eligible AS (
 SELECT p.id,p.exposed_name,p.created_at,p.team_id FROM pending p
 WHERE NOT (p.requester_kind='user' AND p.requester_id=sqlc.arg(actor_id)::uuid)
   AND (p.allow_service_account_admins OR p.requester_kind<>'service_account'
     OR NOT EXISTS (SELECT 1 FROM service_accounts sa JOIN teams t ON t.id=sa.team_id
                    JOIN team_members m ON m.team_id=t.id
                    WHERE sa.id=p.requester_id AND t.status='active'
                      AND m.user_id=sqlc.arg(actor_id) AND m.role IN ('owner','admin')))
   AND (EXISTS (SELECT 1 FROM primary_reviewers pr WHERE pr.id=p.id AND pr.user_id=sqlc.arg(actor_id))
     OR (sqlc.arg(platform_admin)::boolean AND NOT EXISTS (SELECT 1 FROM primary_reviewers pr WHERE pr.id=p.id)))
)
SELECT id,exposed_name,created_at,team_id,count(*) OVER () AS total
FROM eligible ORDER BY created_at,id LIMIT sqlc.arg(page_limit)::integer;
