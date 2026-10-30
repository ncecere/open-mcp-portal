-- name: InsertTeam :one
INSERT INTO teams (slug, name, description, created_by)
VALUES (@slug, @name, @description, @created_by)
RETURNING *;

-- name: GetTeamByID :one
SELECT * FROM teams WHERE id = $1;

-- name: GetTeamBySlug :one
SELECT * FROM teams WHERE slug = $1;

-- Serialises membership changes for one team (owner counting, invites).
-- name: LockTeam :one
SELECT * FROM teams WHERE id = $1 FOR UPDATE;

-- name: ListTeamsAdmin :many
SELECT sqlc.embed(t),
       (SELECT count(*) FROM team_members m WHERE m.team_id = t.id)::bigint AS member_count,
       (SELECT count(*) FROM team_members m WHERE m.team_id = t.id AND m.role = 'owner')::bigint AS owner_count,
       (SELECT count(*) FROM team_invites i WHERE i.team_id = t.id AND i.role = 'owner' AND i.accepted_at IS NULL AND i.revoked_at IS NULL
          AND i.expires_at > now())::bigint AS owner_invites
FROM teams t
WHERE (sqlc.narg(search)::text IS NULL
       OR t.slug ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\'
       OR t.name ILIKE '%' || sqlc.narg(search)::text || '%' ESCAPE '\')
  AND (sqlc.narg(status)::text IS NULL OR t.status = sqlc.narg(status)::text)
  AND (sqlc.narg(after_slug)::text IS NULL OR t.slug > sqlc.narg(after_slug)::text)
ORDER BY t.slug
LIMIT @page_size;

-- name: TeamCounts :one
SELECT (SELECT count(*) FROM team_members m WHERE m.team_id = @team_id)::bigint AS member_count,
       (SELECT count(*) FROM team_members m WHERE m.team_id = @team_id AND m.role = 'owner')::bigint AS owner_count,
       (SELECT count(*) FROM team_invites i WHERE i.team_id = @team_id AND i.role = 'owner' AND i.accepted_at IS NULL AND i.revoked_at IS NULL
          AND i.expires_at > now())::bigint AS owner_invites;

-- name: UpdateTeam :one
UPDATE teams
SET name        = @name,
    description = @description,
    status      = @status,
    archived_at = CASE WHEN @status::text = 'archived' THEN coalesce(archived_at, now()) ELSE NULL END,
    revision    = revision + 1,
    updated_at  = now()
WHERE id = @id
RETURNING *;

-- name: ListTeamsForUser :many
SELECT t.*, m.role AS member_role
FROM team_members m
JOIN teams t ON t.id = m.team_id
WHERE m.user_id = @user_id
ORDER BY t.name, t.id;

-- name: GetMembership :one
SELECT * FROM team_members WHERE team_id = @team_id AND user_id = @user_id;

-- name: ListMembers :many
SELECT sqlc.embed(m), sqlc.embed(u)
FROM team_members m
JOIN users u ON u.id = m.user_id
WHERE m.team_id = @team_id
ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'editor' THEN 2 ELSE 3 END,
         u.email::text;

-- name: InsertMember :one
INSERT INTO team_members (team_id, user_id, role, added_by)
VALUES (@team_id, @user_id, @role, @added_by)
RETURNING *;

-- name: UpdateMemberRole :one
UPDATE team_members
SET role = @role, revision = revision + 1, updated_at = now()
WHERE team_id = @team_id AND user_id = @user_id
RETURNING *;

-- name: DeleteMember :exec
DELETE FROM team_members WHERE team_id = @team_id AND user_id = @user_id;

-- name: CountOwners :one
SELECT count(*) FROM team_members WHERE team_id = @team_id AND role = 'owner';

-- name: UpsertInvite :one
INSERT INTO team_invites (team_id, email, role, invited_by, expires_at)
VALUES (@team_id, @email, @role, @invited_by, @expires_at)
ON CONFLICT (team_id, email) WHERE accepted_at IS NULL AND revoked_at IS NULL
DO UPDATE SET role = EXCLUDED.role, invited_by = EXCLUDED.invited_by,
              expires_at = EXCLUDED.expires_at, created_at = now()
RETURNING *;

-- name: ListOpenInvites :many
SELECT * FROM team_invites
WHERE team_id = @team_id AND accepted_at IS NULL AND revoked_at IS NULL
ORDER BY created_at DESC;

-- name: GetOpenInvite :one
SELECT * FROM team_invites
WHERE id = @id AND team_id = @team_id AND accepted_at IS NULL AND revoked_at IS NULL
FOR UPDATE;

-- name: RevokeInvite :exec
UPDATE team_invites SET revoked_at = now() WHERE id = @id;

-- Discover candidates without holding invite rows. All membership/invite
-- mutations take the team first; multiple teams are locked in UUID order.
-- name: ListInviteTeamsForEmail :many
SELECT DISTINCT team_id FROM team_invites
WHERE email = @email AND accepted_at IS NULL AND revoked_at IS NULL
  AND expires_at > clock_timestamp()
ORDER BY team_id;

-- The team is already locked. Materialise locked, current rows before testing
-- expiry so time spent waiting on an invite lock cannot revive an old invite.
-- name: ClaimTeamInvitesForEmail :many
WITH locked AS MATERIALIZED (
    SELECT * FROM team_invites
    WHERE team_id = @team_id AND email = @email
      AND accepted_at IS NULL AND revoked_at IS NULL
    ORDER BY id
    FOR UPDATE
)
SELECT * FROM locked WHERE expires_at > clock_timestamp()
ORDER BY id;

-- name: AcceptInvite :exec
UPDATE team_invites SET accepted_at = now(), accepted_user_id = @user_id WHERE id = @id;

-- name: InsertMemberIfAbsent :execrows
INSERT INTO team_members (team_id, user_id, role, added_by)
VALUES (@team_id, @user_id, @role, @added_by)
ON CONFLICT (team_id, user_id) DO NOTHING;
