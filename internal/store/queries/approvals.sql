-- Lock order: human actor KEY SHARE BEFORE epoch, then requester advisory /
-- request / rule locks. Under the epoch fence all authority reads are NONLOCKING.
-- No existing-table FKs on approval snapshots; system actor for consumption audit.
-- Never keep these locks through network I/O. Callers own transaction + audit.

-- name: GetApprovalContext :one
SELECT epoch FROM approval_context WHERE id = 1;

-- name: LockApprovalContext :one
SELECT public.omp_lock_approval_context(false)::bigint AS epoch;

-- name: LockApprovalContextExclusive :one
SELECT public.omp_lock_approval_context(true)::bigint AS epoch;

-- name: LockApprovalActor :one
SELECT id FROM users WHERE id = $1 FOR KEY SHARE;

-- name: LockApprovalRequester :exec
SELECT pg_advisory_xact_lock(hashtextextended('approval-requester:' || sqlc.arg(requester_kind)::text || ':' || sqlc.arg(requester_id)::uuid::text, 0));

-- name: ListApprovalRules :many
SELECT * FROM approval_rules
WHERE (sqlc.narg(team_id)::uuid IS NULL OR team_id = sqlc.narg(team_id))
ORDER BY created_at DESC, id DESC
LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer;

-- name: GetApprovalRule :one
SELECT * FROM approval_rules WHERE id = $1;

-- name: LockApprovalRule :one
SELECT * FROM approval_rules WHERE id = $1 FOR UPDATE;

-- name: ListMatchingApprovalRules :many
SELECT * FROM approval_rules WHERE enabled AND
    ((target_kind = 'server' AND target_id = sqlc.arg(server_id)) OR
     (target_kind = 'gateway' AND target_id = sqlc.arg(gateway_id)))
ORDER BY target_kind, id;

-- name: InsertApprovalRule :one
INSERT INTO approval_rules(id,name,team_id,target_kind,target_id,capability_id,classes,enabled,
    pending_minutes,valid_minutes,allow_service_account_admins,created_by)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *;

-- Rule services acquire the exclusive epoch fence before writes, validate
-- ownership/overlap live, then replace selectors in the same audited transaction.
-- name: UpdateApprovalRule :one
UPDATE approval_rules SET name = sqlc.arg(name), capability_id = sqlc.narg(capability_id),
    classes = sqlc.arg(classes), enabled = sqlc.arg(enabled), pending_minutes = sqlc.arg(pending_minutes),
    valid_minutes = sqlc.arg(valid_minutes), allow_service_account_admins = sqlc.arg(allow_service_account_admins),
    revision = revision + 1, updated_at = now()
WHERE id = sqlc.arg(id) AND revision = sqlc.arg(expected_revision) RETURNING *;

-- name: DeleteApprovalRule :execrows
DELETE FROM approval_rules WHERE id = $1 AND revision = $2;

-- name: ListApprovalRuleApprovers :many
SELECT * FROM approval_rule_approvers WHERE rule_id = $1 ORDER BY kind, user_id, group_name;

-- name: InsertApprovalRuleApprover :exec
INSERT INTO approval_rule_approvers(rule_id,kind,user_id,group_name) VALUES ($1,$2,$3,$4);

-- name: DeleteApprovalRuleApprovers :exec
DELETE FROM approval_rule_approvers WHERE rule_id = $1;

-- Detail queries return ciphertext for service-authorized decryption only.
-- Terminal previews are inaccessible even before physical cleanup.
-- name: GetApprovalRequest :one
SELECT id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
    gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,
    capability_fingerprint,server_origin,
    CASE WHEN status IN ('pending','approved') AND expires_at > now()
        AND (status = 'pending' OR valid_until > now())
        AND context_epoch = (SELECT epoch FROM approval_context WHERE approval_context.id = 1)
        THEN preview_cipher ELSE NULL::bytea END AS preview_cipher,
    preview_truncated,preview_redacted,status,review_revision,decided_by,created_at,expires_at,
    valid_until,decided_at,used_at,terminal_at
FROM approval_requests WHERE approval_requests.id = $1;

-- name: LockApprovalRequest :one
SELECT * FROM approval_requests WHERE id = $1 FOR UPDATE;

-- Metadata-only: never include ciphertext in queue/oversight lists.
-- Authorization/eligible reviewer filtering remains the service's responsibility.
-- name: ListApprovalRequests :many
SELECT id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
    gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,
    capability_fingerprint,server_origin,preview_truncated,preview_redacted,status,review_revision,
    decided_by,created_at,expires_at,valid_until,decided_at,used_at,terminal_at
FROM approval_requests
WHERE (sqlc.narg(requester_kind)::text IS NULL OR requester_kind = sqlc.narg(requester_kind))
  AND (sqlc.narg(requester_id)::uuid IS NULL OR requester_id = sqlc.narg(requester_id))
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status))
ORDER BY created_at DESC, id DESC LIMIT sqlc.arg(page_limit)::integer OFFSET sqlc.arg(page_offset)::integer;

-- Return latest denied too: ordinary retries must not implicitly renew it.
-- A used/expired/cancelled receipt is not reusable authority.
-- name: FindApprovalRequestBinding :one
SELECT * FROM approval_requests WHERE binding_digest = $1 ORDER BY created_at DESC, id DESC LIMIT 1;

-- name: InsertApprovalRequest :one
INSERT INTO approval_requests(id,rule_id,rule_revision,context_epoch,requester_kind,requester_id,requester_team_id,
    gateway_id,server_id,capability_id,exposed_name,tool_class,args_digest,binding_digest,
    capability_fingerprint,server_origin,preview_cipher,preview_truncated,preview_redacted,created_at,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21) RETURNING *;

-- Serialize quota and dedup with LockApprovalRequester in the same transaction.
-- name: CountPendingApprovalRequests :one
SELECT count(*) FROM approval_requests WHERE requester_kind = $1 AND requester_id = $2
    AND status = 'pending' AND expires_at > sqlc.arg(at_time)::timestamptz;

-- Displayed digest + review revision, current epoch, unexpired pending only.
-- Services re-evaluate rule revision, reviewer/requester eligibility under fence.
-- name: ApproveApprovalRequest :one
UPDATE approval_requests SET status = 'approved', review_revision = review_revision + 1,
    decided_by = sqlc.arg(decided_by), decided_at = sqlc.arg(at_time),
    valid_until = least(expires_at, sqlc.arg(valid_until)::timestamptz)
WHERE approval_requests.id = sqlc.arg(id) AND status = 'pending' AND binding_digest = sqlc.arg(binding_digest)
    AND review_revision = sqlc.arg(expected_review_revision) AND expires_at > sqlc.arg(at_time)::timestamptz
    AND context_epoch = (SELECT epoch FROM approval_context WHERE approval_context.id = 1)
    AND sqlc.arg(valid_until)::timestamptz > sqlc.arg(at_time)::timestamptz
    AND sqlc.arg(valid_until)::timestamptz <= sqlc.arg(at_time)::timestamptz + interval '60 minutes'
RETURNING *;

-- name: DenyApprovalRequest :one
UPDATE approval_requests SET status = 'denied', review_revision = review_revision + 1,
    decided_by = sqlc.arg(decided_by), decided_at = sqlc.arg(at_time), terminal_at = sqlc.arg(at_time)
WHERE approval_requests.id = sqlc.arg(id) AND status = 'pending' AND binding_digest = sqlc.arg(binding_digest)
    AND review_revision = sqlc.arg(expected_review_revision) AND expires_at > sqlc.arg(at_time)::timestamptz
    AND context_epoch = (SELECT epoch FROM approval_context WHERE approval_context.id = 1)
RETURNING *;

-- name: CancelApprovalRequest :one
UPDATE approval_requests SET status = 'cancelled', review_revision = review_revision + 1, terminal_at = sqlc.arg(at_time)
WHERE id = sqlc.arg(id) AND status IN ('pending','approved') AND review_revision = sqlc.arg(expected_review_revision)
RETURNING *;

-- Authorization spent, not execution confirmed. Atomic SYSTEM-actor audit and
-- confirmed commit are required before dispatch; ambiguous commit never sends.
-- The digest binds ALL immutable dispatch fields; validation must recompute it.
-- name: UseApprovalRequest :one
UPDATE approval_requests SET status = 'used', review_revision = review_revision + 1,
    used_at = sqlc.arg(at_time), terminal_at = sqlc.arg(at_time)
WHERE approval_requests.id = sqlc.arg(id) AND status = 'approved' AND binding_digest = sqlc.arg(binding_digest)
    AND args_digest = sqlc.arg(args_digest) AND rule_revision = sqlc.arg(rule_revision)
    AND review_revision = sqlc.arg(expected_review_revision) AND context_epoch = sqlc.arg(context_epoch)
    AND context_epoch = (SELECT epoch FROM approval_context WHERE approval_context.id = 1)
    AND expires_at > sqlc.arg(at_time)::timestamptz AND valid_until > sqlc.arg(at_time)::timestamptz
RETURNING *;

-- Cleanup transactions also follow epoch -> request ordering. Synchronous
-- transition/consumption queries enforce deadlines independently of this job.
-- name: ExpireApprovalRequests :execrows
WITH doomed AS (
    SELECT id FROM approval_requests WHERE status IN ('pending','approved')
      AND (expires_at <= sqlc.arg(at_time)::timestamptz OR valid_until <= sqlc.arg(at_time)::timestamptz)
    ORDER BY expires_at, id LIMIT sqlc.arg(batch_size)::integer FOR UPDATE SKIP LOCKED
)
UPDATE approval_requests SET status = 'expired', review_revision = review_revision + 1, terminal_at = sqlc.arg(at_time)
WHERE id IN (SELECT id FROM doomed);

-- name: ClearApprovalRequestPreviews :execrows
WITH doomed AS (
    SELECT id FROM approval_requests WHERE terminal_at IS NOT NULL AND terminal_at <= sqlc.arg(before_time)::timestamptz
      AND preview_cipher IS NOT NULL ORDER BY terminal_at, id LIMIT sqlc.arg(batch_size)::integer FOR UPDATE SKIP LOCKED
)
UPDATE approval_requests SET preview_cipher = NULL WHERE id IN (SELECT id FROM doomed);

-- Independent 90-day metadata retention, never audit's retention setting.
-- name: PurgeApprovalRequestMetadata :execrows
WITH doomed AS (
    SELECT id FROM approval_requests WHERE terminal_at < sqlc.arg(at_time)::timestamptz - interval '90 days'
    ORDER BY terminal_at, id LIMIT sqlc.arg(batch_size)::integer FOR UPDATE SKIP LOCKED
)
DELETE FROM approval_requests WHERE id IN (SELECT id FROM doomed);
