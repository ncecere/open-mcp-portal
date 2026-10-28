-- Fan-out is a nonlocking committed-epoch read. Never fetch preview ciphertext,
-- argument/binding digests or user input to resolve a notification's audience.
-- name: GetApprovalNotificationRequest :one
SELECT id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
    gateway_id,server_id,capability_id,exposed_name,tool_class,capability_fingerprint,server_origin,
    status,expires_at,valid_until
FROM approval_requests WHERE id = $1;

-- Decision notices go only to the requester or CURRENT owning-team humans.
-- Platform observers and the service account's creator/operator are not agents.
-- name: ApprovalDecisionRecipients :many
SELECT u.id FROM users u
WHERE u.status = 'active' AND (
    (sqlc.arg(requester_kind)::text = 'user' AND u.id = sqlc.arg(requester_id)) OR
    (sqlc.arg(requester_kind)::text = 'service_account' AND EXISTS (
        SELECT 1 FROM service_accounts sa JOIN teams t ON t.id = sa.team_id
        JOIN team_members m ON m.team_id = sa.team_id
        WHERE sa.id = sqlc.arg(requester_id) AND sa.team_id = sqlc.narg(requester_team_id)::uuid
          AND sa.enabled AND t.status = 'active' AND m.user_id = u.id AND m.role IN ('owner','admin')
    ))
) ORDER BY u.id;
