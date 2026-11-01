-- name: ListUsers :many
SELECT * FROM users
WHERE (sqlc.narg(search)::text IS NULL
       OR email::text ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR display_name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\')
  AND (sqlc.narg(platform_role)::text IS NULL OR platform_role = sqlc.narg(platform_role)::text)
  AND (sqlc.narg(status)::text IS NULL OR status = sqlc.narg(status)::text)
  AND (sqlc.narg(after_email)::text IS NULL
       OR (email::text, id) > (sqlc.narg(after_email)::text, sqlc.narg(after_id)::uuid))
ORDER BY email::text, id
LIMIT @page_size;

-- name: GetUserForUpdate :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: ListUsersByEmail :many
SELECT * FROM users WHERE email = @email ORDER BY created_at;

-- Locks every active platform admin so concurrent demotions serialise.
-- name: LockActivePlatformAdmins :many
SELECT id FROM users
WHERE platform_role = 'platform_admin' AND status = 'active'
ORDER BY id
FOR UPDATE;

-- name: UpdateUserAccess :one
-- @status is the manual standing; users.status (effective) is derived by
-- trigger with the directory standing (decision 92).
UPDATE users
SET platform_role = @platform_role,
    manual_status = @status,
    revision      = revision + 1,
    updated_at    = now()
WHERE id = @id
RETURNING *;

-- How many teams each user belongs to (the admin Users list).
-- name: UserTeamCounts :many
SELECT user_id, count(*)::bigint AS teams FROM team_members WHERE user_id = ANY(@ids::uuid[]) GROUP BY user_id;
